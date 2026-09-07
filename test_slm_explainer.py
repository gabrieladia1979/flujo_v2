"""Focused tests for the server-owned SLM explanation boundary.

Run with:
    python -m unittest -v test_slm_explainer.py

These tests intentionally avoid importing spaCy, XGBoost, SHAP, or the model pickle.
"""

import json
import unittest
from unittest.mock import patch

from services.slm_explanation import (
    LEGITIMATE_SUMMARY,
    MAX_RAW_PROVIDER_OUTPUT_BYTES,
    PHISHING_SUMMARY,
    SAFE_ACTION_TEXTS,
    SLM_PROMPT_VERSION,
    EvidenceSource,
    ExplanationEvidence,
    SafeActionCode,
    SLMExplanationValidationError,
    build_analyzer_evidence,
    build_explanation_context,
    build_slm_prompt_messages,
    render_server_fallback,
    validate_or_fallback_slm_output,
    validate_slm_output,
)


class Adjustment:
    def __init__(self, rule: str, delta: float, description: str):
        self.rule = rule
        self.delta = delta
        self.description = description


def action(code: SafeActionCode) -> dict[str, str]:
    return {"code": code.value, "text": SAFE_ACTION_TEXTS[code]}


def phishing_context():
    return build_explanation_context(
        is_phishing=True,
        risk_score=0.97,
        intent="solicitar_credenciales",
        evidence=[
            ExplanationEvidence(
                evidence_id="slot.urgencia",
                text="Se detectó presión temporal o urgencia en el mensaje.",
                source=EvidenceSource.OBSERVED_SIGNAL,
            ),
            ExplanationEvidence(
                evidence_id="security.dmarc_fail",
                text="La política de autenticación del dominio no se cumplió.",
                source=EvidenceSource.SECURITY_RULE,
            ),
        ],
    )


def legitimate_context():
    return build_explanation_context(
        is_phishing=False,
        risk_score=0.08,
        intent="comunicacion_operativa",
        evidence=[
            ExplanationEvidence(
                evidence_id="security.all_checks_pass",
                text="Las verificaciones de autenticación disponibles resultaron correctas.",
                source=EvidenceSource.SECURITY_RULE,
            )
        ],
    )


def valid_phishing_payload() -> dict:
    return {
        "summary": PHISHING_SUMMARY,
        "reasons": [
            {
                "evidence_id": "slot.urgencia",
                "text": "Se detectó presión temporal o urgencia en el mensaje.",
            }
        ],
        "recommended_actions": [action(SafeActionCode.DO_NOT_CLICK)],
    }


class SLMExplainerTests(unittest.TestCase):
    def assert_category(self, category: str, raw_output: str, context=None):
        with self.assertRaises(SLMExplanationValidationError) as raised:
            validate_slm_output(raw_output, context or phishing_context())
        self.assertEqual(category, raised.exception.category)

    def test_valid_contract_is_accepted(self):
        result = validate_slm_output(json.dumps(valid_phishing_payload()), phishing_context())
        self.assertEqual(PHISHING_SUMMARY, result.summary)
        self.assertEqual("slot.urgencia", result.reasons[0].evidence_id)

    def test_phishing_legitimate_and_insufficient_evidence_contracts(self):
        phishing = validate_slm_output(json.dumps(valid_phishing_payload()), phishing_context())
        self.assertEqual(PHISHING_SUMMARY, phishing.summary)

        legitimate_payload = {
            "summary": LEGITIMATE_SUMMARY,
            "reasons": [
                {
                    "evidence_id": "security.all_checks_pass",
                    "text": "Las verificaciones de autenticación disponibles resultaron correctas.",
                }
            ],
            "recommended_actions": [action(SafeActionCode.NO_ACTION_NEEDED)],
        }
        legitimate = validate_slm_output(json.dumps(legitimate_payload), legitimate_context())
        self.assertEqual(LEGITIMATE_SUMMARY, legitimate.summary)

        insufficient_context = build_explanation_context(
            is_phishing=False,
            risk_score=0.25,
            intent="comunicacion_operativa",
            evidence=[],
        )
        insufficient_payload = {
            "summary": LEGITIMATE_SUMMARY,
            "reasons": [
                {
                    "evidence_id": "evidence.insufficient",
                    "text": "No se recibieron señales verificadas suficientes para explicar el resultado con más detalle.",
                }
            ],
            "recommended_actions": [action(SafeActionCode.VERIFY_VIA_OFFICIAL_CHANNEL)],
        }
        insufficient = validate_slm_output(
            json.dumps(insufficient_payload), insufficient_context
        )
        self.assertEqual("evidence.insufficient", insufficient.reasons[0].evidence_id)

    def test_classifier_authority_fields_are_rejected(self):
        for field, value in (
            ("is_phishing", False),
            ("risk_score", 0.01),
            ("intent", "comunicacion_operativa"),
        ):
            with self.subTest(field=field):
                payload = valid_phishing_payload()
                payload[field] = value
                self.assert_category("schema_violation", json.dumps(payload))

    def test_extra_nested_fields_are_rejected(self):
        payload = valid_phishing_payload()
        payload["reasons"][0]["confidence"] = 1.0
        self.assert_category("schema_violation", json.dumps(payload))

    def test_unknown_and_ambiguous_actions_are_rejected(self):
        payload = valid_phishing_payload()
        payload["recommended_actions"] = [
            {"code": "reply_to_sender", "text": "Respondé al remitente."}
        ]
        self.assert_category("schema_violation", json.dumps(payload))

        payload = valid_phishing_payload()
        payload["recommended_actions"][0]["text"] = "Respondé para confirmar si es real."
        self.assert_category("action_value_mismatch", json.dumps(payload))

    def test_no_action_is_rejected_for_phishing(self):
        payload = valid_phishing_payload()
        payload["recommended_actions"] = [action(SafeActionCode.NO_ACTION_NEEDED)]
        self.assert_category("action_not_allowed_for_verdict", json.dumps(payload))

    def test_unknown_evidence_is_rejected(self):
        payload = valid_phishing_payload()
        payload["reasons"][0]["evidence_id"] = "invented.organization_failure"
        self.assert_category("unknown_evidence", json.dumps(payload))

    def test_reason_text_must_match_the_linked_server_evidence(self):
        payload = valid_phishing_payload()
        payload["reasons"][0]["text"] = "Una organización inventada confirmó un ataque."
        self.assert_category("reason_value_mismatch", json.dumps(payload))

    def test_duplicate_evidence_is_rejected(self):
        payload = valid_phishing_payload()
        payload["reasons"].append(dict(payload["reasons"][0]))
        self.assert_category("schema_violation", json.dumps(payload))

    def test_duplicate_json_keys_are_rejected(self):
        raw = (
            '{"summary":"' + PHISHING_SUMMARY + '",'
            '"summary":"' + PHISHING_SUMMARY + '",'
            '"reasons":[{"evidence_id":"slot.urgencia","text":"Motivo válido."}],'
            '"recommended_actions":[' + json.dumps(action(SafeActionCode.DO_NOT_CLICK)) + "]}"
        )
        self.assert_category("duplicate_json_key", raw)

    def test_invalid_json_fences_and_trailing_prose_are_rejected(self):
        valid = json.dumps(valid_phishing_payload())
        for raw in ("not-json", f"```json\n{valid}\n```", valid + " explicación"):
            with self.subTest(raw=raw[:20]):
                self.assert_category("invalid_json", raw)

    def test_oversized_output_falls_back_before_json_parsing(self):
        oversized = "x" * (MAX_RAW_PROVIDER_OUTPUT_BYTES + 1)
        with patch(
            "services.slm_explanation.json.loads",
            side_effect=AssertionError("json.loads must not be called"),
        ):
            result = validate_or_fallback_slm_output(oversized, phishing_context())
        self.assertTrue(result.used_fallback)
        self.assertEqual("output_too_large", result.error_category)

    def test_urls_and_control_characters_are_rejected(self):
        payload = valid_phishing_payload()
        payload["reasons"][0]["text"] = "Visitá https://example.com para verificar."
        self.assert_category("schema_violation", json.dumps(payload))

        payload = valid_phishing_payload()
        payload["reasons"][0]["text"] = "Texto con\u0007control."
        self.assert_category("schema_violation", json.dumps(payload))

    def test_item_and_text_bounds_are_enforced(self):
        payload = valid_phishing_payload()
        payload["reasons"] = []
        self.assert_category("schema_violation", json.dumps(payload))

        payload = valid_phishing_payload()
        payload["reasons"] = [
            {"evidence_id": "slot.urgencia", "text": "x" * 241}
        ]
        self.assert_category("schema_violation", json.dumps(payload))

        payload = valid_phishing_payload()
        payload["recommended_actions"] = [
            action(SafeActionCode.DO_NOT_CLICK),
            action(SafeActionCode.DO_NOT_REPLY),
            action(SafeActionCode.REPORT_MESSAGE),
            action(SafeActionCode.DO_NOT_SHARE_SENSITIVE_INFORMATION),
        ]
        self.assert_category("schema_violation", json.dumps(payload))

    def test_authoritative_summary_mismatch_is_rejected(self):
        payload = valid_phishing_payload()
        payload["summary"] = LEGITIMATE_SUMMARY
        self.assert_category("summary_mismatch", json.dumps(payload))

    def test_fallback_is_deterministic_and_safe(self):
        context = phishing_context()
        first = validate_or_fallback_slm_output("invalid", context)
        second = validate_or_fallback_slm_output("invalid", context)
        self.assertTrue(first.used_fallback)
        self.assertEqual("invalid_json", first.error_category)
        self.assertEqual(first.explanation, second.explanation)
        self.assertEqual(context.authoritative_summary, first.explanation.summary)
        self.assertNotIn(SafeActionCode.NO_ACTION_NEEDED, [a.code for a in first.explanation.recommended_actions])

    def test_fallback_for_missing_provider_output(self):
        result = validate_or_fallback_slm_output(None, legitimate_context())
        self.assertTrue(result.used_fallback)
        self.assertEqual("missing_output", result.error_category)
        self.assertEqual(LEGITIMATE_SUMMARY, result.explanation.summary)

    def test_validation_log_does_not_include_raw_model_output(self):
        raw_output = "sensitive-email-body-and-model-output"
        with self.assertLogs("services.slm_explanation", level="WARNING") as captured:
            validate_or_fallback_slm_output(raw_output, phishing_context())
        self.assertNotIn(raw_output, " ".join(captured.output))
        self.assertIn("SLM explanation fallback used", captured.output[0])

    def test_prompt_is_versioned_separated_and_authority_preserving(self):
        messages = build_slm_prompt_messages(phishing_context())
        self.assertEqual(["system", "user"], [message["role"] for message in messages])
        system = messages[0]["content"]
        user = messages[1]["content"]

        self.assertIn(SLM_PROMPT_VERSION, system)
        self.assertIn("is_phishing, risk_score e intent son inmutables", system)
        self.assertIn("datos no confiables", system)
        self.assertIn("No inventes señales, URLs, organizaciones, fallos técnicos ni intenciones", system)
        self.assertIn("solamente con un objeto JSON válido", system)
        self.assertIn(PHISHING_SUMMARY, system)
        self.assertIn(LEGITIMATE_SUMMARY, system)
        self.assertIn("evidence.insufficient", system)
        self.assertIn('"risk_score":0.97', user)

    def test_prompt_user_context_is_json_serialized(self):
        user = build_slm_prompt_messages(phishing_context())[1]["content"]
        prefix = "Contexto estructurado de solo lectura:\n"
        self.assertTrue(user.startswith(prefix))
        parsed = json.loads(user[len(prefix) :])
        self.assertTrue(parsed["is_phishing"])
        self.assertEqual(PHISHING_SUMMARY, parsed["authoritative_summary"])

    def test_analyzer_evidence_only_uses_signals_supporting_the_verdict(self):
        adjustments = [
            Adjustment("dmarc_fail", 0.15, "DMARC falló."),
            Adjustment("all_checks_pass", -0.05, "Las verificaciones resultaron correctas."),
        ]
        slots = {"URGENCIA": ["urgente"]}

        phishing = build_analyzer_evidence(
            slots, adjustments, is_phishing=True
        )
        self.assertEqual(
            ["slot.urgencia", "security.dmarc_fail"],
            [item.evidence_id for item in phishing],
        )

        legitimate = build_analyzer_evidence(
            slots, adjustments, is_phishing=False
        )
        self.assertEqual(
            ["security.all_checks_pass"],
            [item.evidence_id for item in legitimate],
        )

    def test_render_keeps_current_client_field_as_plain_string(self):
        rendered = render_server_fallback(phishing_context())
        self.assertIsInstance(rendered, str)
        self.assertIn(PHISHING_SUMMARY, rendered)
        self.assertIn("Motivos:", rendered)
        self.assertIn("Acciones recomendadas:", rendered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
