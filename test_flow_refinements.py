"""Contrasts for supplied document codes and authenticated bank sender parsing."""
import numpy as np
import pytest

from schemas import EmailPayloadSchema
from services.bank_identity import BANKS
from services.content_rules import detect_content_signals


@pytest.mark.parametrize("body", [
    'Para acceder a los documentos, ingrese el código de seguridad: ABCD1234EFGH5678.',
    'Visite el servicio de firma, haga clic en acceder a los documentos, e ingrese el código de seguridad: 8224B6E14BF49830E6DFAEIN400B41.',
    '<p>Para firmar el documento, ingrese el código de acceso: ABCD-1234-EFGH.</p>',
    'To view the document, enter the security code: ABCD1234EFGH5678.',
    'Nunca envíeme su contraseña ni códigos SMS.',
    'No me mande su contraseña ni códigos SMS.',
])
def test_literal_document_code_is_not_a_request_for_a_personal_secret(body):
    assert "credential_disclosure_request" not in {s.rule for s in detect_content_signals(body)}


@pytest.mark.parametrize("body", [
    'Para acceder al documento, ingrese su código de seguridad recibido por SMS.',
    'Para firmar el documento, envíe el código de seguridad: ABCD1234EFGH5678.',
    'Para acceder al documento, ingrese su contraseña y código SMS.',
    'Para acceder al documento, ingrese el código de seguridad: ABCD1234EFGH5678 y su contraseña.',
    'Para acceder al documento, ingrese el código de seguridad: ABCD1234EFGH5678. Responda con su contraseña y código SMS.',
    'To view the document, enter your authentication code received by SMS.',
    'To view the document, enter the security code: ABCD1234EFGH5678 and your password.',
    'Envíeme su contraseña y código SMS.',
    'Mándeme su contraseña y código SMS.',
])
def test_document_context_does_not_allowlist_personal_secret_requests(body):
    assert "credential_disclosure_request" in {s.rule for s in detect_content_signals(body)}


def test_document_code_does_not_allowlist_deceptive_link():
    body = ('Para firmar el documento, ingrese el código de seguridad: ABCD1234EFGH5678. '
            '<a href="https://signature.evil.invalid">https://www.docusign.com</a>')
    assert "displayed_url_destination_mismatch" in {s.rule for s in detect_content_signals(body)}


@pytest.mark.parametrize("bank", BANKS, ids=lambda bank: bank["id"])
def test_authenticated_bank_domains_and_rfc_sender_names_use_same_evidence(bank, monkeypatch):
    from services import analyzer
    monkeypatch.setattr(analyzer.calibrated_model, "predict_proba", lambda x: np.array([[0.99, 0.01]]))
    for root in bank["domains"]:
        payload = EmailPayloadSchema(metadata={"asunto": "Resumen disponible", "remitente_email": f"{bank['name']} <avisos@{root}>"},
            contenido="Su resumen está disponible en la aplicación habitual.",
            security_features={"has_headers": True, "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass"})
        result = analyzer._classify_payload(payload)
        assert result["bank_context"].sender_bank == bank["name"]
        assert result["is_phishing"] is False
        assert any(a.rule == "trusted_official_domain" for a in result["security_adjustments"])


@pytest.mark.parametrize("security", [
    {"has_headers": False, "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass"},
    {"has_headers": True, "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "fail"},
    {"has_headers": True, "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass", "from_reply_to_match": False},
])
def test_bank_domain_without_sufficient_identity_evidence_does_not_get_official_discount(security, monkeypatch):
    from services import analyzer
    monkeypatch.setattr(analyzer.calibrated_model, "predict_proba", lambda x: np.array([[0.99, 0.01]]))
    payload = EmailPayloadSchema(metadata={"asunto": "Resumen disponible", "remitente_email": "BBVA <avisos@bbva.com>"},
        contenido="Su resumen está disponible en la aplicación habitual.", security_features=security)
    result = analyzer._classify_payload(payload)
    assert not any(a.rule == "trusted_official_domain" for a in result["security_adjustments"])
    assert result["is_phishing"] is True


def test_authenticated_display_sender_still_cannot_request_password(monkeypatch):
    from services import analyzer
    monkeypatch.setattr(analyzer.calibrated_model, "predict_proba", lambda x: np.array([[0.01, 0.99]]))
    payload = EmailPayloadSchema(metadata={"asunto": "BBVA - Firma de documento", "remitente_email": "BBVA <avisos@bbva.com>"},
        contenido='Para firmar el documento, ingrese el código de seguridad: ABCD1234EFGH5678. Envíeme su contraseña y código SMS.',
        security_features={"has_headers": True, "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass"})
    result = analyzer._classify_payload(payload)
    assert result["is_phishing"] is True
    assert result["risk_score"] >= 0.95
