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
    assert result["word_weights"]
    assert result["num_samples"] == 128
