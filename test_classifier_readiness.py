"""Unavailable and oversized analyses must never be rendered as legitimate mail."""
import pytest
from fastapi.testclient import TestClient

import main
from services import analyzer


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(analyzer, "_ANALYSIS_CACHE", {})
    return TestClient(main.app)


@pytest.mark.parametrize("component", ["calibrated_model", "tfidf", "nlp", "matcher_global"])
def test_missing_component_returns_503_without_verdict(client, monkeypatch, component):
    monkeypatch.setattr(analyzer, component, None)
    response = client.post("/api/v1/analyze", headers={main.API_KEY_NAME: main.API_KEY},
                           json={"metadata": {"asunto": "Aviso"}, "contenido": "Reunión mañana."})
    assert response.status_code == 503
    assert "is_phishing" not in response.json()
    health = client.get("/api/v1/health").json()
    assert health["status"] == "degraded"
    assert health["classifier"]["loaded"] is False


def test_long_mail_returns_413_instead_of_truncating(client, monkeypatch):
    monkeypatch.setattr(analyzer.nlp, "max_length", 100)
    response = client.post("/api/v1/analyze", headers={main.API_KEY_NAME: main.API_KEY},
                           json={"metadata": {"asunto": "Aviso"}, "contenido": "texto " * 100})
    assert response.status_code == 413
    assert "is_phishing" not in response.json()


def test_critical_attachment_can_be_detected_without_model(client, monkeypatch):
    monkeypatch.setattr(analyzer, "calibrated_model", None)
    monkeypatch.setattr("services.slm_client.generate_slm_explanation", lambda context: None)
    response = client.post("/api/v1/analyze", headers={main.API_KEY_NAME: main.API_KEY},
                           json={"metadata": {}, "contenido": "Documento adjunto.",
                                 "security_features": {"has_executable_attachment": True}})
    assert response.status_code == 200
    assert response.json()["is_phishing"] is True
    assert response.json()["decision_source"] == "critical_security_rule"


def test_loader_rejects_unverified_xgboost_runtime_before_unpickling(monkeypatch):
    from unittest.mock import Mock
    for name in ("modelo_exportado", "tfidf", "scaler_meta", "scaler_slots",
                 "scaler_legibilidad", "calibrated_model", "LOADED_MODEL_PATH"):
        monkeypatch.setattr(analyzer, name, getattr(analyzer, name))
    monkeypatch.setattr("xgboost.__version__", "3.2.0")
    unpickle = Mock(side_effect=AssertionError("must not unpickle"))
    monkeypatch.setattr(analyzer.pickle, "load", unpickle)
    analyzer._load_model()
    assert analyzer.calibrated_model is None
    assert analyzer.tfidf is None
    unpickle.assert_not_called()
