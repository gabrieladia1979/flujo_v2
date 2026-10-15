import os
import base64
import hashlib
import hmac
import json
import subprocess
import sys
import time
import threading
import pytest
from fastapi import HTTPException

from fastapi.testclient import TestClient


def test_production_rejects_development_key():
    env = os.environ.copy()
    env["PHISHARG_ENV"] = "production"
    env["API_KEY"] = "PHISHARG_DEV_KEY_123"
    result = subprocess.run(
        [sys.executable, "-c", "import main"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "API_KEY debe ser una clave" in result.stderr


def test_production_requires_a_token_signing_key():
    env = os.environ.copy()
    env["PHISHARG_ENV"] = "production"
    env["API_KEY"] = "a" * 32
    env.pop("PHISHARG_TOKEN_KEY", None)
    result = subprocess.run(
        [sys.executable, "-c", "import main"], env=env,
        capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert "PHISHARG_TOKEN_KEY debe tener" in result.stderr


def test_default_cors_rejects_foreign_web_origins():
    import main

    response = TestClient(main.app).options(
        "/api/v1/analyze/hybrid",
        headers={
            "Origin": "https://sitio-ajeno.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_hybrid_token_is_signed_short_lived_and_bound_to_exact_body(monkeypatch):
    import main

    key = "a" * 32
    monkeypatch.setattr(main, "TOKEN_KEY", key)
    body = b'{"metadata":{"asunto":"X"},"contenido":"mensaje"}'
    nonce = "b" * 32

    def token(payload=body, expires_in=90, token_nonce=nonce):
        now = int(time.time())
        claims = {
            "aud": "phisharg-hybrid", "iat": now, "exp": now + expires_in,
            "nonce": token_nonce,
            "digest": hashlib.sha256(token_nonce.encode() + b"." + payload).hexdigest(),
        }
        encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        signature = base64.urlsafe_b64encode(
            hmac.new(key.encode(), encoded.encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        return f"{encoded}.{signature}"

    client = TestClient(main.app)
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token()}"}
    accepted = client.post("/api/v1/analyze/hybrid", content=body, headers=headers)
    assert accepted.status_code != 401
    assert client.post("/api/v1/analyze/hybrid", content=body, headers=headers).status_code == 401
    altered_headers = {**headers, "Authorization": f"Bearer {token(token_nonce='c' * 32)}"}
    assert client.post("/api/v1/analyze/hybrid", content=body + b" ", headers=altered_headers).status_code == 401
    expired_headers = {**headers, "Authorization": f"Bearer {token(expires_in=-1, token_nonce='d' * 32)}"}
    assert client.post("/api/v1/analyze/hybrid", content=body, headers=expired_headers).status_code == 401


def test_oversized_analysis_request_is_rejected_before_inference():
    import main

    response = TestClient(main.app).post(
        "/api/v1/analyze/hybrid",
        content=b"x" * (main.MAX_ANALYSIS_REQUEST_BYTES + 1),
        headers={"Content-Type": "application/json", "X-API-Key": main.API_KEY},
    )
    assert response.status_code == 413


def test_hybrid_capacity_limit_rejects_extra_inference(monkeypatch):
    import main

    slot = threading.BoundedSemaphore(1)
    slot.acquire()
    monkeypatch.setattr(main, "_hybrid_slots", slot)
    try:
        response = TestClient(main.app).post(
            "/api/v1/analyze/hybrid",
            json={"metadata": {"asunto": "prueba"}, "contenido": "mensaje"},
            headers={"X-API-Key": main.API_KEY},
        )
        assert response.status_code == 429
        assert response.headers["Retry-After"] == "5"
    finally:
        slot.release()


def test_shared_replay_store_claims_nonce_atomically_and_fails_closed(monkeypatch):
    import main

    class ConditionalFailure(Exception):
        response = {"Error": {"Code": "ConditionalCheckFailedException"}}

    class FakeTable:
        def __init__(self):
            self.claimed = set()
            self.unavailable = False

        def put_item(self, *, Item, ConditionExpression):
            assert ConditionExpression == "attribute_not_exists(nonce)"
            assert Item["expires_at"] > int(time.time())
            if self.unavailable:
                raise RuntimeError("DynamoDB unavailable")
            if Item["nonce"] in self.claimed:
                raise ConditionalFailure()
            self.claimed.add(Item["nonce"])

    table = FakeTable()
    monkeypatch.setattr(main, "REPLAY_TABLE", "phisharg-token-replay")
    monkeypatch.setattr(main, "_get_replay_table", lambda: table)
    now = int(time.time())
    main._claim_token_nonce("a" * 32, now + 90, now)
    with pytest.raises(ValueError):
        main._claim_token_nonce("a" * 32, now + 90, now)
    table.unavailable = True
    with pytest.raises(HTTPException) as failure:
        main._claim_token_nonce("b" * 32, now + 90, now)
    assert failure.value.status_code == 503


def test_diagnostic_lime_shares_hybrid_capacity_limit(monkeypatch):
    import main

    slot = threading.BoundedSemaphore(1)
    slot.acquire()
    monkeypatch.setattr(main, "_hybrid_slots", slot)
    monkeypatch.setenv("ENABLE_HYBRID_LIME", "true")
    monkeypatch.setenv("PHISHARG_HYBRID_MODEL_DIR", "fake-model")
    try:
        response = TestClient(main.app).post(
            "/api/v1/analyze/hybrid/lime",
            json={"metadata": {"asunto": "prueba"}, "contenido": "mensaje"},
            headers={"X-API-Key": main.API_KEY},
        )
        assert response.status_code == 429
    finally:
        slot.release()


def test_legacy_route_does_not_expose_internal_exception(monkeypatch):
    import main

    def fail(_payload):
        raise RuntimeError("ruta interna y secreto de diagnóstico")

    monkeypatch.setattr(main, "analyze_email", fail)
    response = TestClient(main.app).post(
        "/api/v1/analyze",
        json={"metadata": {"asunto": "prueba"}, "contenido": "mensaje"},
        headers={"X-API-Key": main.API_KEY},
    )
    assert response.status_code == 500
    assert "ruta interna" not in response.text
    assert "secreto" not in response.text
