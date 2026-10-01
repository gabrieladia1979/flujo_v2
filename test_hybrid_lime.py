"""Experimental LIME route boundaries and real artifact score parity."""

import os

import pytest
from fastapi.testclient import TestClient


PAYLOAD = {
    "metadata": {"asunto": "Acceso"},
    "contenido": "Responda este correo con su contraseña y código SMS para evitar la suspensión de su cuenta.",
}


def test_lime_requires_authentication_and_opt_in(monkeypatch):
    import main

    monkeypatch.delenv("ENABLE_HYBRID_LIME", raising=False)
    client = TestClient(main.app)
    assert client.post("/api/v1/analyze/hybrid/lime", json=PAYLOAD).status_code == 401
    assert client.post(
        "/api/v1/analyze/hybrid/lime", json=PAYLOAD,
        headers={main.API_KEY_NAME: main.API_KEY},
    ).status_code == 404


def test_lime_rejects_unbounded_work(monkeypatch):
    import main

    monkeypatch.setenv("ENABLE_HYBRID_LIME", "true")
    client = TestClient(main.app)
    headers = {main.API_KEY_NAME: main.API_KEY}
    assert client.post("/api/v1/analyze/hybrid/lime?num_samples=5000", json=PAYLOAD, headers=headers).status_code == 422


def test_lime_rejects_text_without_enough_words():
    from schemas import EmailPayloadSchema
    from services.hybrid_lime import explain_hybrid_text

    with pytest.raises(ValueError, match="at least two words"):
        explain_hybrid_text(object(), EmailPayloadSchema.model_validate({
            "metadata": {"asunto": "Aviso"}, "contenido": "hola",
        }))


@pytest.mark.skipif(not os.getenv("HYBRID_TEST_ARTIFACT"), reason="Requires explicit local trained artifact")
def test_lime_real_artifact_explains_raw_score(monkeypatch):
    import main
    from schemas import EmailPayloadSchema
    from services.hybrid_classifier import _load

    directory = os.environ["HYBRID_TEST_ARTIFACT"]
    monkeypatch.setenv("ENABLE_HYBRID_LIME", "true")
    monkeypatch.setenv("PHISHARG_HYBRID_MODEL_DIR", directory)
    response = TestClient(main.app).post(
        "/api/v1/analyze/hybrid/lime?num_samples=128",
        json=PAYLOAD, headers={main.API_KEY_NAME: main.API_KEY},
    )
    assert response.status_code == 200
    result = response.json()
    raw = _load(directory).raw_score(EmailPayloadSchema.model_validate(PAYLOAD))
    assert result["phishing_probability"] == pytest.approx(raw, abs=1e-6)
    assert result["scope"].startswith("raw_hybrid_model_score")
    assert result["diagnostic_word_weights"]
    assert result["word_weights"] == (result["diagnostic_word_weights"] if result["reliable_local_fit"] else [])
    assert result["num_samples"] == 128
    assert result["heldout_fidelity_r2"] is None or isinstance(result["heldout_fidelity_r2"], float)
    assert result["heldout_mae"] >= 0
    assert result["reliable_local_fit"] is (
        result["local_fidelity_r2"] >= 0.7
        and result["heldout_fidelity_r2"] is not None
        and result["heldout_fidelity_r2"] >= 0.7
        and result["original_prediction_error"] <= result["max_original_prediction_error"]
    )


def test_high_fidelity_does_not_hide_original_score_mismatch(monkeypatch):
    import threading
    from types import SimpleNamespace
    import numpy as np
    from lime.lime_text import IndexedString, LimeTextExplainer
    from schemas import EmailPayloadSchema
    from services.hybrid_lime import explain_hybrid_text

    def explanation(_self, body, callback, **kwargs):
        return SimpleNamespace(predict_proba=callback([body])[0], score=0.99,
            domain_mapper=SimpleNamespace(indexed_string=IndexedString(body)),
            local_exp={1: [(0, 0.1), (1, 0.1)]}, intercept={1: 0.52},
            as_list=lambda **kwargs: [('alpha', 0.1), ('beta', 0.1)])

    monkeypatch.setattr(LimeTextExplainer, 'explain_instance', explanation)
    monkeypatch.setattr('services.hybrid_encoder.embed',
                        lambda encoder, texts: np.array([[len(t.split())] for t in texts], dtype=np.float32))
    monkeypatch.setattr('services.hybrid_features.encoder_text', lambda subject, body: body)
    monkeypatch.setattr('services.hybrid_features.technical_features', lambda *args: [0.0])

    def predict(matrix):
        counts = matrix.get_data().toarray()[:, 0]
        return np.where(counts == 2, 0.7, 0.52 + 0.1 * counts)

    classifier = SimpleNamespace(lock=threading.Lock(), encoder=object(), head=SimpleNamespace(predict=predict))
    result = explain_hybrid_text(classifier, EmailPayloadSchema.model_validate({
        'metadata': {'asunto': ''}, 'contenido': 'alpha beta'}))
    assert result['local_fidelity_r2'] == 0.99
    assert result['heldout_fidelity_r2'] == pytest.approx(1.0)
    assert result['original_prediction_error'] == pytest.approx(0.02, abs=1e-6)
    assert result['reliable_local_fit'] is False
    assert result['word_weights'] == []
    assert result['diagnostic_word_weights']
