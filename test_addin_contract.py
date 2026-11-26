"""Audit route, fast phase and the real Add-in token protocol."""
import base64
import hashlib
import hmac
import json
import secrets
import time
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import main
from services import analyzer, browser_auth

KEY = "addin-contract-key-" + "x" * 32


def signed(body, **changes):
    now = int(time.time())
    claims = {"aud": "phisharg-hybrid", "iat": now, "exp": now + 90, "nonce": secrets.token_hex(16)}
    claims.update(changes)
    claims.setdefault("digest", hashlib.sha256(claims["nonce"].encode() + b"." + body).hexdigest())
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(hmac.new(KEY.encode(), encoded.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{encoded}.{signature}"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(browser_auth, "TOKEN_KEY", KEY)
    monkeypatch.setattr(browser_auth, "REPLAY_TABLE", "")
    monkeypatch.setattr(browser_auth, "_used_nonces", {})
    monkeypatch.setattr(analyzer, "_ANALYSIS_CACHE", {})
    return TestClient(main.app)


def post(client, body, token=None, route="/api/v1/analyze?quick=true"):
    return client.post(route, content=body,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + (token or signed(body))})


def test_signed_addin_request_runs_real_classifier_and_rejects_replay(client):
    body = json.dumps({"metadata": {"asunto": "BBVA - Aviso", "remitente_nombre": "BBVA", "remitente_email": "avisos@bbva-validacion.invalid"},
                       "contenido": "Verificá tu cuenta para mantener el acceso."}).encode()
    token = signed(body)
    result = post(client, body, token)
    assert result.status_code == 200
    assert result.json()["is_phishing"] is True
    assert result.json()["bank_context"]["mentioned_banks"] == ["BBVA"]
    assert post(client, body, token).status_code == 401


@pytest.mark.parametrize("changes", [
    {"exp": 1}, {"aud": "other"}, {"iat": True}, {"digest": "0" * 64},
    {"iat": int(time.time()) + 100, "exp": int(time.time()) + 150},
    {"exp": int(time.time()) + 1000},
])
def test_invalid_signed_claims_are_rejected(client, changes):
    body = b'{"metadata":{},"contenido":"Aviso"}'
    assert post(client, body, signed(body, **changes)).status_code == 401


def test_changed_body_and_signature_are_rejected(client):
    body = b'{"metadata":{},"contenido":"Aviso"}'
    token = signed(body)
    assert post(client, body + b" ", token).status_code == 401
    assert post(client, body, token[:-1] + ("a" if token[-1] != "a" else "b")).status_code == 401


def test_quick_phase_skips_slm_and_shap_and_does_not_poison_full_cache(client, monkeypatch):
    from services.slm_explanation import render_server_fallback
    provider = Mock(side_effect=render_server_fallback)
    shap = Mock(return_value=[])
    monkeypatch.setattr("services.slm_client.generate_slm_explanation", provider)
    monkeypatch.setattr("services.explainer.extract_shap_insights", shap)
    body = json.dumps({"metadata": {"asunto": "Solicitud"}, "contenido": "Envíeme su contraseña y código SMS."}).encode()
    first = post(client, body).json()
    provider.assert_not_called()
    shap.assert_not_called()
    assert first["is_phishing"] is True
    assert first["explanation_source"] == "fallback"
    full = post(client, body, route="/api/v1/analyze").json()
    assert provider.call_count == 1
    assert shap.call_count == 1
    for key in ("is_phishing", "risk_score", "decision_source", "intent", "content_signals"):
        assert first[key] == full[key]
    assert post(client, body).json()["explanation_source"] == "fallback"
    assert provider.call_count == 1


def test_large_request_is_rejected_before_authentication_or_inference(client):
    response = client.post("/api/v1/analyze", content=b"x" * (main.MAX_ANALYSIS_REQUEST_BYTES + 1),
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_configured_addin_origin_can_send_bearer_requests(client):
    response = client.options("/api/v1/analyze", headers={"Origin": "https://add-in-pfi-hybrid.vercel.app",
        "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://add-in-pfi-hybrid.vercel.app"
    response = client.options("/api/v1/analyze", headers={"Origin": "https://other.invalid",
        "Access-Control-Request-Method": "POST"})
    assert response.status_code == 400


def test_shared_replay_store_is_atomic_and_unavailable_store_fails_closed(monkeypatch):
    class ConditionalFailure(Exception):
        response = {"Error": {"Code": "ConditionalCheckFailedException"}}
    class Table:
        seen = set()
        unavailable = False
        def put_item(self, *, Item, ConditionExpression):
            assert ConditionExpression == "attribute_not_exists(nonce)"
            if self.unavailable:
                raise RuntimeError("Unavailable")
            if Item["nonce"] in self.seen:
                raise ConditionalFailure()
            self.seen.add(Item["nonce"])
    table = Table()
    monkeypatch.setattr(browser_auth, "REPLAY_TABLE", "test-replay")
    monkeypatch.setattr(browser_auth, "_get_replay_table", lambda: table)
    now = int(time.time())
    browser_auth._claim_nonce("a" * 32, now + 90, now)
    with pytest.raises(ValueError):
        browser_auth._claim_nonce("a" * 32, now + 90, now)
    table.unavailable = True
    with pytest.raises(HTTPException) as error:
        browser_auth._claim_nonce("b" * 32, now + 90, now)
    assert error.value.status_code == 503


def test_internal_errors_are_not_exposed(client, monkeypatch):
    def fail(payload):
        raise RuntimeError("internal-secret-path")
    monkeypatch.setattr(main, "analyze_email", fail)
    response = post(client, b'{"metadata":{},"contenido":"Aviso"}', route="/api/v1/analyze")
    assert response.status_code == 500
    assert "internal-secret-path" not in response.text
