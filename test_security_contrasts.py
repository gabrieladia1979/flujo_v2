"""Contrastive regressions for shared rules; this is development data, not a holdout."""
import json
from pathlib import Path

import pytest
from services.content_rules import detect_content_signals

CASES = [json.loads(line) for line in (Path(__file__).parent / 'data/security_contrastive_development.jsonl').read_text(encoding='utf-8').splitlines()]

@pytest.mark.parametrize('case', CASES, ids=lambda c: c['id'])
def test_security_contrast(case):
    signals = {s.rule for s in detect_content_signals(case['body'])}
    if case['expected_rule']:
        assert case['expected_rule'] in signals
    else:
        assert not signals

@pytest.mark.parametrize('body', [
    'Envíe el código de pedido para consultar el envío.',
    'Send the order code to track your parcel.',
    'We will buy gift cards through procurement. No employee needs to send codes.',
    'Comprá tarjetas de regalo para el evento aprobado por Compras.',
    'El proveedor cambió su cuenta. No transfieras hasta verificar con el contacto habitual.',
    '<blockquote>Send your password.</blockquote><p>Report this message.</p>',
    '<script>Send your password.</script><p>Meeting at noon.</p>',
    '<a href="https://tracking.example">Ver novedades</a>',
    '<a href="https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fbank.example%2Fhelp">https://bank.example</a>',
    '<a href="https://bank.example/">www.bank.example</a>',
])
def test_additional_benign_contrasts(body):
    assert not detect_content_signals(body)

@pytest.mark.parametrize('body', [
    'Security training. Never share your password. Reply with your password to complete this registration.',
    '> No compartas tu contraseña.\nEnvianos tu clave de acceso.',
    '<blockquote>No compartas tu contraseña.</blockquote><p>Envianos tu clave de acceso.</p>',
])
def test_warning_or_quote_does_not_allowlist_later_attack(body):
    assert 'credential_disclosure_request' in {s.rule for s in detect_content_signals(body)}

def test_safe_links_host_suffix_is_not_trusted_when_embedded_in_an_attacker_domain():
    body = '<a href="https://nam01.safelinks.protection.outlook.com.evil.example/?url=https%3A%2F%2Fbank.example">https://bank.example</a>'
    assert 'displayed_url_destination_mismatch' in {s.rule for s in detect_content_signals(body)}

@pytest.mark.parametrize('body', [
    "Don't send your password or verification code.",
    "Don't buy gift cards and email me the codes. Keep this warning available.",
    'Buy gift cards through procurement. Never send redemption codes; the event budget is confidential.',
    '<a href>https://bank.example</a>',
])
def test_negated_disclosure_and_empty_href_are_safe(body):
    assert not detect_content_signals(body)

def test_quoted_secret_is_still_a_direct_request():
    assert 'credential_disclosure_request' in {s.rule for s in detect_content_signals('Enviame "tu contraseña".')}


@pytest.mark.parametrize('case_id', ['gift_es-phishing', 'html_url-phishing', 'credential_mixed-phishing'])
def test_new_signals_reach_http_with_evidence(case_id, monkeypatch):
    import main
    from fastapi.testclient import TestClient
    from services.slm_explanation import render_server_fallback
    monkeypatch.setattr('services.slm_client.generate_slm_explanation', render_server_fallback)
    case = next(c for c in CASES if c['id'] == case_id)
    from services import analyzer
    monkeypatch.setattr(analyzer, '_ANALYSIS_CACHE', {})
    endpoint = '/api/v1/analyze'
    response = TestClient(main.app).post(endpoint,
        headers={main.API_KEY_NAME: main.API_KEY},
        json={'metadata': {'asunto': case['subject']}, 'contenido': case['body'],
              'security_features': {'spf_result': 'pass', 'dkim_result': 'pass', 'dmarc_result': 'pass'}})
    assert response.status_code == 200
    result = response.json()
    assert result['is_phishing'] is True
    assert result['risk_score'] >= 0.95
    assert case['expected_rule'] in {s['rule'] for s in result['content_signals']}
    assert 'content.' + case['expected_rule'] in result['slm_explanation']
    if case_id.startswith('gift_'):
        assert result['intent'] == 'desviar_pago'

@pytest.mark.parametrize('body', [
    'Grant the application permissions only after checking the publisher. Never ignore the unverified publisher warning.',
    'Comprá tarjetas de regalo. Mandame fotos del envoltorio para el evento confidencial.',
])
def test_verification_advice_and_packaging_photos_are_not_fraud_rules(body):
    assert not detect_content_signals(body)
