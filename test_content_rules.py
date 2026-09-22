"""Contrastive content-rule tests plus the real authenticated HTTP pipeline."""

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from services.content_rules import detect_content_signals


CREDENTIAL_REQUESTS = [
    'Responda este correo con su contraseña y el código SMS para evitar la suspensión de su cuenta.',
    'Envíame tu contraseña por correo para validar el acceso.',
    'Por favor, envíe su clave fiscal para desbloquear su usuario.',
    'Compartí tu código de verificación por este medio.',
    'Facilite su token de autenticación respondiendo este mensaje.',
    'Respondé con tu PIN de acceso.',
    '<p>Env&iacute;e su <strong>contrase&ntilde;a</strong> por correo.</p>',
    'Nunca compartas tus claves. Para este trámite, enviame tu contraseña.',
    'Capacitación de seguridad. Respondé este correo con tu contraseña.',
]
PAYMENT_REQUESTS = [
    'No llame al proveedor. Transfiera hoy el saldo pendiente a la nueva cuenta indicada y envíe el comprobante respondiendo este mensaje.',
    'Pagá al nuevo CBU sin consultar al proveedor.',
    'Deposite el saldo en la cuenta actualizada. No contacte al titular.',
    '<p>No verifique con el banco.</p><p>Realice la transferencia a otra cuenta.</p>',
]
SAFE_REQUESTS = [
    'Nunca compartas tu contraseña ni tu código SMS.',
    'No responda con su contraseña.',
    'Jamás envíe su clave fiscal por correo.',
    'No le envíe su token a nadie.',
    'Responde si olvidaste tu contraseña para recibir ayuda.',
    'Envíe instrucciones para restablecer su contraseña.',
    'Enviame información sobre el token de acceso.',
    'Respondé con el código de pedido para consultar el envío.',
    'Compartí el enlace para recuperar tu contraseña.',
    'Envíe el comprobante de transferencia al proveedor.',
    'Pague la factura en la cuenta habitual.',
    'Transferí a la nueva cuenta después de verificar con el proveedor.',
    'No transfiera a la nueva cuenta. Llame al proveedor para verificarla.',
    'Pagá a la nueva cuenta después de verificar con el proveedor. No contacte al banco por la factura.',
    'Ejemplo: responda con su contraseña.',
    'El correo decía: “Envíe su clave fiscal”. No lo responda.',
    'Ejemplo: "<blockquote>Envíe su contraseña por correo.</blockquote>" Este es el ejemplo que debemos reportar.',
    '> Responda con su contraseña\nEste es el intento de estafa recibido ayer.',
    'Analizaremos la frase "No llame al proveedor. Transfiera a la nueva cuenta" en la capacitación.',
]


@pytest.mark.parametrize('body', CREDENTIAL_REQUESTS)
def test_credential_requests(body):
    assert 'credential_disclosure_request' in {s.rule for s in detect_content_signals(body)}


@pytest.mark.parametrize('body', PAYMENT_REQUESTS)
def test_payment_requests(body):
    assert 'payment_redirection_no_verification' in {s.rule for s in detect_content_signals(body)}


@pytest.mark.parametrize('body', SAFE_REQUESTS)
def test_safe_contrasts(body):
    assert detect_content_signals(body) == []


@pytest.mark.parametrize('body,rule,intent', [
    (CREDENTIAL_REQUESTS[0], 'credential_disclosure_request', 'solicitar_credenciales'),
    (PAYMENT_REQUESTS[0], 'payment_redirection_no_verification', 'desviar_pago'),
])
def test_http_response_exposes_rule_and_evidence_even_with_authenticated_headers(body, rule, intent):
    import main
    from services import analyzer
    from services.slm_explanation import render_server_fallback
    contexts = []

    def fallback(context):
        contexts.append(context)
        return render_server_fallback(context)

    with patch.object(analyzer, '_ANALYSIS_CACHE', {}), \
         patch('services.slm_client.generate_slm_explanation', side_effect=fallback):
        response = TestClient(main.app).post('/api/v1/analyze',
            headers={main.API_KEY_NAME: main.API_KEY}, json={
                'metadata': {'asunto': 'Solicitud', 'remitente_email': 'sender@example.invalid'},
                'contenido': body,
                'security_features': {'spf_result': 'pass', 'dkim_result': 'pass',
                                      'dmarc_result': 'pass', 'auth_as': 'Internal'},
            })
    assert response.status_code == 200
    data = response.json()
    assert data['is_phishing'] is True
    assert data['risk_score'] >= 0.95
    assert data['raw_model_score'] < analyzer.UMBRAL_CRITICO
    assert data['decision_source'] == 'content_security_rule'
    assert data['intent'] == intent
    assert data['content_signals'][0]['rule'] == rule
    assert data['content_signals'][0]['description'] in data['reason']
    assert contexts[0].evidence[0].evidence_id == 'content.' + rule
    assert data['content_signals'][0]['description'] in data['slm_explanation']
