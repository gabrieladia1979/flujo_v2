import numpy as np
import pytest
from fastapi.testclient import TestClient

from schemas import EmailPayloadSchema
from services.bank_identity import BANKS, analyze_bank_identity, bank_for_domain


def payload(sender="avisos@bbva.com.ar", subject="BBVA - Aviso", body="Su resumen está disponible.", **security):
    return EmailPayloadSchema(metadata={"asunto": subject, "remitente_email": sender}, contenido=body,
                              security_features=security or None)


@pytest.mark.parametrize("bank", BANKS, ids=lambda bank: bank["id"])
def test_bank_roots_and_subdomains_have_explicit_identity(bank):
    for root in bank["domains"]:
        assert bank_for_domain(root)["id"] == bank["id"]
        assert bank_for_domain("avisos." + root)["id"] == bank["id"]
        assert bank_for_domain(root + ".evil.invalid") is None
        assert bank_for_domain("fake" + root) is None


@pytest.mark.parametrize("sender", ["avisos@bbva.com", "BBVA <avisos@bbva.com.ar>", "avisos@info.bbva.com.ar"])
def test_bbva_sender_requires_authentication_evidence(sender):
    context, signals = analyze_bank_identity(payload(sender), [])
    assert context.sender_bank == "BBVA"
    assert context.sender_status == "known_domain_unverified"
    assert not signals
    context, signals = analyze_bank_identity(payload(sender, has_headers=True, spf_result="pass", dmarc_result="pass"), [])
    assert context.sender_status == "known_domain_authenticated"
    assert not signals


def test_authentication_without_headers_is_not_enough():
    context, _ = analyze_bank_identity(payload(spf_result="pass", dmarc_result="pass"), [])
    assert context.sender_status == "known_domain_unverified"


def test_bank_domain_with_failed_dmarc_is_not_verified():
    context, _ = analyze_bank_identity(payload(has_headers=True, dmarc_result="fail"), [])
    assert context.sender_status == "known_domain_auth_failed"


@pytest.mark.parametrize("sender,body,url", [
    ("BBVA <avisos@bbva-validacion.invalid>", "Valide su cuenta para mantener el acceso.", None),
    ("avisos@bbva-validacion.invalid", "Valide su cuenta para mantener el acceso.", None),
    ("BBVA <avisos@other.invalid>", 'Verificá tu cuenta en <a href="https://bbva.com.ar.evil.invalid">este enlace</a>.', "https://bbva.com.ar.evil.invalid"),
    ("Santander <avisos@other.invalid>", "Confirme su cuenta en https://santander-validacion.invalid", "https://santander-validacion.invalid"),
])
def test_bank_claim_plus_lookalike_and_account_request_is_exposed(sender, body, url):
    context, signals = analyze_bank_identity(payload(sender, subject="Aviso", body=body), [url] if url else [])
    assert context.sender_bank is None
    assert context.lookalike_domains
    assert [signal.rule for signal in signals] == ["bank_brand_impersonation"]


@pytest.mark.parametrize("body,urls", [
    ("Ingresá a tu cuenta desde la aplicación habitual de BBVA.", []),
    ("No ingrese a su cuenta en https://bbva-validacion.invalid", ["https://bbva-validacion.invalid"]),
    ("Esta nota explica una estafa: https://bbva-validacion.invalid", ["https://bbva-validacion.invalid"]),
    ("Promo de BBVA: descuentos en restaurantes.", []),
    ('<blockquote>Verificá tu cuenta en https://bbva-validacion.invalid</blockquote><p>Reportá este mensaje.</p>', ["https://bbva-validacion.invalid"]),
    ('<blockquote>https://bbva-validacion.invalid</blockquote><p>Ingresá a tu cuenta desde la aplicación habitual.</p>', ["https://bbva-validacion.invalid"]),
    ('Verificá tu cuenta en <a href="https://bbva.com.ar">BBVA</a>', ["https://bbva.com.ar"]),
    ('Verificá tu cuenta en <a href="https://marketing-provider.invalid">el sitio</a>', ["https://marketing-provider.invalid"]),
])
def test_bank_mentions_unknown_providers_and_defensive_advice_do_not_force_phishing(body, urls):
    _, signals = analyze_bank_identity(payload(body=body), urls)
    assert signals == []


def test_bbva_does_not_turn_someone_elses_email_into_a_bank_sender():
    context, signals = analyze_bank_identity(payload("cliente@example.invalid", body="Te transfiero a tu cuenta BBVA mañana."), [])
    assert context.mentioned_banks == ["BBVA"]
    assert context.sender_bank is None
    assert not signals


def test_bbva_identity_reaches_http_and_fallback(monkeypatch):
    import main
    from services import analyzer
    monkeypatch.setattr(analyzer, "_ANALYSIS_CACHE", {})
    response = TestClient(main.app).post("/api/v1/analyze", headers={main.API_KEY_NAME: main.API_KEY},
        json=payload(has_headers=True, spf_result="pass", dkim_result="pass", dmarc_result="pass").model_dump())
    assert response.status_code == 200
    result = response.json()
    assert result["bank_context"]["sender_bank"] == "BBVA"
    assert result["bank_context"]["sender_status"] == "known_domain_authenticated"
    assert "BBVA" in result["slm_explanation"]


def test_bank_spoofing_rule_survives_low_model_score_and_passing_auth(monkeypatch):
    from services import analyzer
    monkeypatch.setattr(analyzer.calibrated_model, "predict_proba", lambda x: np.array([[0.01, 0.99]]))
    result = analyzer._classify_payload(payload("BBVA <avisos@bbva-verificacion.invalid>",
        body="Verificá tu cuenta para mantener el acceso.",
        has_headers=True, spf_result="pass", dkim_result="pass", dmarc_result="pass"))
    assert result["is_phishing"] is True
    assert result["risk_score"] >= 0.95
    assert result["intent"] == "suplantacion_bancaria"
    assert result["decision_source"] == "content_security_rule"


def test_authenticated_bank_can_still_request_secrets(monkeypatch):
    from services import analyzer
    monkeypatch.setattr(analyzer.calibrated_model, "predict_proba", lambda x: np.array([[0.01, 0.99]]))
    result = analyzer._classify_payload(payload(body="Responda con su contraseña y código SMS.",
        has_headers=True, spf_result="pass", dkim_result="pass", dmarc_result="pass"))
    assert result["bank_context"].sender_status == "known_domain_authenticated"
    assert result["is_phishing"] is True
    assert result["intent"] == "solicitar_credenciales"
