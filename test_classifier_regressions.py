"""Regression coverage for email representation, cache and bulk-mail decisions."""

from unittest.mock import patch

import pytest

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


def test_comparison_restores_production_index():
    from scripts.compare_classifier import compare
    from scripts.classifier_corpus import load_jsonl
    original = analyzer.PRODUCTION_PHISHING_PROBABILITY_INDEX
    records = load_jsonl(analyzer.DEFAULT_MODEL_PATH.parents[1] / 'data/classifier_eval_v1.jsonl')
    result = compare(records, analyzer)
    assert analyzer.PRODUCTION_PHISHING_PROBABILITY_INDEX == original == 0
    assert result['0']['metrics']['final']['confusion_matrix']['false_negative'] == 0
    assert result['1']['metrics']['final']['confusion_matrix']['false_negative'] == 2
