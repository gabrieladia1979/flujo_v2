"""Consume the existing Add-in/Vercel body-bound HMAC protocol.

Adapted from entrega's verifier (9dce97e). The audience retains its protocol name
phisharg-hybrid for compatibility; the XGBoost URL stays /api/v1/analyze.
"""
import base64
import binascii
from functools import lru_cache
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

TOKEN_KEY = os.getenv("PHISHARG_TOKEN_KEY", "")
REPLAY_TABLE = os.getenv("PHISHARG_REPLAY_TABLE", "").strip()
_used_nonces = {}
_nonce_lock = threading.Lock()


@lru_cache(maxsize=1)
def _get_replay_table():
    import boto3
    from botocore.config import Config
    return boto3.resource("dynamodb", config=Config(connect_timeout=2, read_timeout=2,
        retries={"max_attempts": 1})).Table(REPLAY_TABLE)


def _claim_nonce(nonce, expires, now):
    if REPLAY_TABLE:
        try:
            _get_replay_table().put_item(Item={"nonce": nonce, "expires_at": expires + 120},
                ConditionExpression="attribute_not_exists(nonce)")
        except Exception as exc:
            if getattr(exc, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise ValueError("Permiso ya utilizado") from exc
            raise HTTPException(status_code=503, detail="Control de reutilización no disponible") from exc
        return
    with _nonce_lock:
        for saved, expiry in list(_used_nonces.items()):
            if expiry < now:
                del _used_nonces[saved]
        if nonce in _used_nonces or len(_used_nonces) >= 10000:
            raise ValueError("Permiso ya utilizado o servidor ocupado")
        _used_nonces[nonce] = expires


async def verify_browser_auth(request: Request, authorization: str):
    if not authorization.startswith("Bearer ") or len(TOKEN_KEY) < 32:
        raise HTTPException(status_code=401, detail="Autorización inválida")
    token = authorization.removeprefix("Bearer ")
    try:
        encoded, signature = token.split(".")
        if (len(token) > 1024 or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", signature)):
            raise ValueError("Formato inválido")
        expected = base64.urlsafe_b64encode(hmac.new(TOKEN_KEY.encode(), encoded.encode("ascii"), hashlib.sha256).digest()).rstrip(b"=").decode()
        if not secrets.compare_digest(signature, expected):
            raise ValueError("Firma inválida")
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        now = int(time.time())
        if (claims.get("aud") != "phisharg-hybrid" or type(claims.get("iat")) is not int
                or type(claims.get("exp")) is not int or claims["iat"] > now + 10
                or claims["exp"] <= now or not 0 < claims["exp"] - claims["iat"] <= 90
                or not re.fullmatch(r"[a-f0-9]{32}", claims.get("nonce", ""))
                or not re.fullmatch(r"[a-f0-9]{64}", claims.get("digest", ""))):
            raise ValueError("Claims inválidas")
        digest = hashlib.sha256(claims["nonce"].encode("ascii") + b"." + await request.body()).hexdigest()
        if not secrets.compare_digest(claims["digest"], digest):
            raise ValueError("La huella no corresponde al cuerpo")
        await run_in_threadpool(_claim_nonce, claims["nonce"], claims["exp"], now)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, binascii.Error):
        raise HTTPException(status_code=401, detail="Autorización inválida") from None
    return claims
