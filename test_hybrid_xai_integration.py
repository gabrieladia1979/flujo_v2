"""The Hybrid response must distinguish model attribution from rule evidence."""

import json
from unittest.mock import patch

from fastapi.testclient import TestClient

from schemas import EmailPayloadSchema
from services.hybrid_classifier import HybridClassifier


PAYLOAD = EmailPayloadSchema.model_validate({
    'metadata': {'asunto': 'Aviso de prueba'},
    'contenido': 'Mensaje de prueba sobre cuenta y acceso.',
})


def classifier():
    instance = object.__new__(HybridClassifier)
    instance.manifest = {'threshold': 0.8}
    return instance


def test_reliable_lime_and_technical_shap_reach_main_hybrid_response(monkeypatch):
    instance = classifier()
    monkeypatch.setattr(instance, 'raw_score', lambda payload: 0.95)
    monkeypatch.setattr(instance, 'technical_attributions', lambda payload, raw: (
        [{'feature': 'http_count', 'value': 1, 'contribution_log_odds': 0.7}], 0.4, -0.2))
    monkeypatch.setattr('services.hybrid_lime.explain_hybrid_text', lambda *args, **kwargs: {
        'phishing_probability': 0.95, 'reliable_local_fit': True,
        'word_weights': [{'word': 'cuenta', 'weight': 0.2}],
        'local_fidelity_r2': 0.9, 'heldout_fidelity_r2': 0.8,
        'original_prediction_error': 0.001,
    })

    result = instance.analyze(PAYLOAD)
    explanation = json.loads(result.slm_explanation)
    reasons = [item['text'] for item in explanation['reasons']]
    assert result.hybrid_xai.technical_status == 'available'
    assert result.hybrid_xai.lime_status == 'reliable'
    assert result.hybrid_xai.lime_word_attributions[0].word == 'cuenta'
    assert any('HTTP sin cifrar' in text for text in reasons)
    assert any('LIME' in text and 'cuenta' in text for text in reasons)
    assert result.raw_model_score == 0.95


def test_unreliable_lime_never_leaks_diagnostic_weights(monkeypatch):
    instance = classifier()
    monkeypatch.setattr(instance, 'raw_score', lambda payload: 0.95)
    monkeypatch.setattr(instance, 'technical_attributions', lambda payload, raw: ([], 1.0, 0.0))
    monkeypatch.setattr('services.hybrid_lime.explain_hybrid_text', lambda *args, **kwargs: {
        'phishing_probability': 0.95, 'reliable_local_fit': False,
        'word_weights': [], 'diagnostic_word_weights': [{'word': 'clave', 'weight': 0.5}],
        'local_fidelity_r2': 0.5, 'heldout_fidelity_r2': 0.3,
        'original_prediction_error': 0.02,
    })

    result = instance.analyze(PAYLOAD)
    assert result.hybrid_xai.lime_status == 'unreliable'
    assert result.hybrid_xai.lime_word_attributions == []
    assert 'clave' not in result.model_dump_json()


def test_critical_rule_does_not_claim_model_attribution(monkeypatch):
    instance = classifier()
    monkeypatch.setattr(instance, 'raw_score', lambda payload: (_ for _ in ()).throw(AssertionError('model bypassed')))
    payload = EmailPayloadSchema.model_validate({
        'metadata': {'asunto': 'Aviso'}, 'contenido': 'Mensaje de prueba.',
        'security_features': {'has_executable_attachment': True},
    })
    result = instance.analyze(payload)
    assert result.decision_source == 'hybrid_critical_security_rule'
    assert result.hybrid_xai.technical_status == 'skipped'
    assert result.hybrid_xai.lime_status == 'skipped'
    assert result.raw_model_score is None


def test_rule_override_does_not_present_raw_model_words_as_verdict_reason(monkeypatch):
    instance = classifier()
    monkeypatch.setattr(instance, 'raw_score', lambda payload: 0.75)
    monkeypatch.setattr(instance, 'technical_attributions', lambda payload, raw: (
        [{'feature': 'http_count', 'value': 1, 'contribution_log_odds': 0.7}], 0.4, -0.2))
    monkeypatch.setattr('services.hybrid_lime.explain_hybrid_text', lambda *args, **kwargs: {
        'phishing_probability': 0.75, 'reliable_local_fit': True,
        'word_weights': [{'word': 'cuenta', 'weight': 0.2}],
        'local_fidelity_r2': 0.9, 'heldout_fidelity_r2': 0.8,
        'original_prediction_error': 0.001,
    })
    payload = PAYLOAD.model_copy(update={
        'security_features': EmailPayloadSchema.model_validate({
            'metadata': {}, 'security_features': {'spf_result': 'fail'},
        }).security_features,
    })
    result = instance.analyze(payload)
    assert result.is_phishing and result.raw_model_score < instance.manifest['threshold']
    assert result.hybrid_xai.lime_status == 'reliable'
    assert result.hybrid_xai.supports_final_verdict is False
    assert 'LIME' not in result.slm_explanation
    assert 'HTTP sin cifrar' not in result.slm_explanation


def test_hybrid_route_can_skip_slow_lime(monkeypatch):
    import main
    instance = classifier()
    monkeypatch.setattr(instance, 'raw_score', lambda payload: 0.95)
    monkeypatch.setattr(instance, 'technical_attributions', lambda payload, raw: ([], 1.0, 0.0))
    monkeypatch.setenv('PHISHARG_HYBRID_MODEL_DIR', 'fake-artifact')
    with patch('services.hybrid_classifier._load', return_value=instance), \
         patch('services.hybrid_lime.explain_hybrid_text', side_effect=AssertionError('LIME disabled')):
        response = TestClient(main.app).post(
            '/api/v1/analyze/hybrid?include_lime=false',
            json=PAYLOAD.model_dump(), headers={main.API_KEY_NAME: main.API_KEY},
        )
    assert response.status_code == 200
    assert response.json()['hybrid_xai']['lime_status'] == 'disabled'


def test_legitimate_result_skips_lime_but_keeps_technical_attribution(monkeypatch):
    instance = classifier()
    monkeypatch.setattr(instance, 'raw_score', lambda payload: 0.05)
    monkeypatch.setattr(instance, 'technical_attributions', lambda payload, raw: ([], -1.0, 0.0))
    with patch('services.hybrid_lime.explain_hybrid_text', side_effect=AssertionError('not needed')):
        result = instance.analyze(PAYLOAD)
    assert result.is_phishing is False
    assert result.hybrid_xai.technical_status == 'available'
    assert result.hybrid_xai.lime_status == 'skipped'
