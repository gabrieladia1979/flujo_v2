"""Regression coverage for email representation, cache and bulk-mail decisions."""

import json
from unittest.mock import patch

import pytest
import numpy as np

from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema
from services import analyzer
from services.security_rules import check_critical_threats, apply_security_rules


@pytest.mark.parametrize('url,expected', [
    ('https://www.example.test/x', 'example.test'),
    ('HTTPS://WWW.Example.test/x', 'example.test'),
    ('https://wexample.test', 'wexample.test'),
    ('https://microsoft.test', 'microsoft.test'),
    ('//example.test/x', 'example.test'),
    ('https://example.test.evil.invalid', 'example.test.evil.invalid'),
])
def test_domain_extraction(url, expected):
    assert analyzer.extraer_dominio(url) == expected


def test_hidden_links_entities_and_tracking_pixels():
    raw = '<a HREF="//arca-login.invalid/?a=1&amp;b=2">Verificar</a><img src="https://pixel.invalid">'
    assert analyzer.extraer_urls_correo(raw, 'Verificar') == ['https://arca-login.invalid/?a=1&b=2']


def test_visible_anchor_not_counted_twice():
    raw = '<a href="https://example.invalid">https://example.invalid</a>'
    assert analyzer.extraer_urls_correo(raw, 'https://example.invalid') == ['https://example.invalid']


def test_html_link_reaches_model_features():
    payload = EmailPayloadSchema(metadata=MetadataSchema(asunto='Verificación'),
        contenido='<a href="http://arca-login.invalid">Ingrese su clave fiscal</a>')
    result = analyzer._classify_payload(payload)
    assert result['urls_detectadas'] == ['http://arca-login.invalid']
    assert result['feature_count'] == analyzer.calibrated_model.n_features_in_


def test_bulk_mail_is_not_critical_but_retains_adjustment():
    features = SecurityFeaturesSchema(bcl=9)
    assert not check_critical_threats(features)[0]
    assert any(a.rule == 'bcl_high' and a.delta > 0 for a in apply_security_rules(features))
    assert check_critical_threats(features.model_copy(update={'has_executable_attachment': True}))[0]


def test_classification_does_not_mutate_input():
    payload = EmailPayloadSchema(metadata=MetadataSchema(remitente_email='sender@example.invalid'),
        contenido='Reunión mañana.', security_features=SecurityFeaturesSchema(is_trusted_domain=True))
    before = payload.model_dump()
    analyzer._classify_payload(payload)
    assert payload.model_dump() == before


def test_unexplained_model_alert_does_not_claim_credential_theft():
    payload = EmailPayloadSchema(metadata=MetadataSchema(asunto='Resumen de reunión'),
        contenido='Hola equipo. Compartimos el resumen semanal. No hace falta responder.')
    with patch.object(analyzer.calibrated_model, 'predict_proba',
                      return_value=np.array([[0.94, 0.06]])):
        diagnostics = analyzer._classify_payload(payload)
    assert diagnostics['is_phishing'] is True
    assert diagnostics['content_signals'] == []
    assert diagnostics['intent'] == 'intencion_no_determinada'


def test_informational_meeting_email_is_legitimate():
    payload = EmailPayloadSchema(metadata=MetadataSchema(
        asunto='[PFI-DEMO-03] Resumen de la reunión semanal',
        remitente_email='tomas.basualdo44@gmail.com'),
        contenido=('Hola, equipo: Comparto el resumen de la reunión semanal. '
                   'La entrega de la primera etapa continúa según lo planificado. '
                   'La próxima revisión será el viernes a las 10:00. '
                   'Cada integrante actualizará el estado de sus tareas antes de la reunión. '
                   'Este correo es únicamente informativo. No es necesario responder '
                   'ni realizar ninguna acción adicional. Saludos, Equipo de Proyecto'))
    diagnostics = analyzer._classify_payload(payload)
    assert diagnostics['is_phishing'] is False
    assert diagnostics['risk_score'] < 0.5


def test_authenticated_terms_update_is_not_credential_theft():
    payload = EmailPayloadSchema(metadata=MetadataSchema(
        asunto='Actualizaciones de nuestros términos de uso',
        remitente_email='msa@communication.microsoft.com'),
        contenido=('Hola: Ha recibido este correo electrónico porque vamos a actualizar '
                   'el Contrato de servicios de Microsoft. Puede leer el contrato completo aquí. '
                   'Las actualizaciones entrarán en vigor el 30 de septiembre de 2026. '
                   'Si continúa usando nuestros productos y servicios, estará aceptando las actualizaciones.'),
        security_features=SecurityFeaturesSchema(
            spf_result='pass', dkim_result='pass', dmarc_result='pass',
            auth_as='Anonymous', received_hop_count=5, has_headers=True))
    diagnostics = analyzer._classify_payload(payload)
    assert diagnostics['is_phishing'] is False
    assert diagnostics['intent'] == 'comunicacion_operativa'


def test_cache_distinguishes_senders_and_reuses_same_request():
    payload = EmailPayloadSchema(metadata=MetadataSchema(asunto='Mismo asunto', remitente_email='a@example.invalid'),
        contenido='Mismo mensaje')
    other = payload.model_copy(update={'metadata': MetadataSchema(asunto='Mismo asunto', remitente_email='b@example.invalid')})
    diagnostics = dict(raw_score=0.1, risk_score=0.1, is_phishing=False,
                       intent='comunicacion_operativa', slots_detectados={},
                       security_adjustments=None, decision_source='model_only', critical_reason=None)
    with patch.object(analyzer, '_ANALYSIS_CACHE', {}), \
         patch.object(analyzer, '_classify_payload', return_value=diagnostics) as classify, \
         patch('services.slm_client.generate_slm_explanation', side_effect=RuntimeError('offline')):
        analyzer.analyze_email(payload)
        analyzer.analyze_email(payload)
        analyzer.analyze_email(other)
    assert classify.call_count == 2


def test_fallback_explanation_is_structured_and_identified():
    payload = EmailPayloadSchema(metadata=MetadataSchema(
        asunto='Resumen de reunión', remitente_email='equipo@example.invalid'),
        contenido='La reunión será mañana a las 10:00. No se requiere ninguna acción.')
    diagnostics = dict(raw_score=0.01, risk_score=0.01, is_phishing=False,
                       intent='comunicacion_operativa', slots_detectados={},
                       security_adjustments=None, decision_source='model_only', critical_reason=None)
    with patch.object(analyzer, '_ANALYSIS_CACHE', {}), \
         patch.object(analyzer, '_classify_payload', return_value=diagnostics):
        result = analyzer.analyze_email(payload)
    explanation = json.loads(result.slm_explanation)
    assert result.explanation_source == 'fallback'
    assert explanation['summary']
    assert explanation['reasons']
    assert explanation['recommended_actions']


def test_valid_slm_explanation_is_identified_and_invalid_output_falls_back():
    from services.slm_explanation import build_explanation_context, build_safe_fallback

    context = build_explanation_context(is_phishing=True, risk_score=0.95,
        intent='desviar_pago', evidence=[dict(evidence_id='content.payment',
        text='El mensaje pide pagar a una cuenta nueva.', source='observed_signal')])
    valid_json = build_safe_fallback(context).model_dump_json()
    with patch('services.slm_client.generate_slm_explanation', return_value=valid_json):
        explanation, source = analyzer._structured_explanation(context, use_slm=True)
    assert source == 'slm'
    assert json.loads(explanation)['summary'] == context.authoritative_summary

    with patch('services.slm_client.generate_slm_explanation', return_value='texto plano'):
        explanation, source = analyzer._structured_explanation(context, use_slm=True)
    assert source == 'fallback'
    assert json.loads(explanation)['summary'] == context.authoritative_summary


def test_comparison_restores_production_index():
    from scripts.compare_classifier import compare
    from scripts.classifier_corpus import load_jsonl
    original = analyzer.PRODUCTION_PHISHING_PROBABILITY_INDEX
    records = load_jsonl(analyzer.DEFAULT_MODEL_PATH.parents[1] / 'data/classifier_eval_v1.jsonl')
    result = compare(records, analyzer)
    assert analyzer.PRODUCTION_PHISHING_PROBABILITY_INDEX == original == 0
    assert result['0']['metrics']['final']['confusion_matrix']['false_negative'] == 0
    assert result['1']['metrics']['final']['confusion_matrix']['false_negative'] == 2
