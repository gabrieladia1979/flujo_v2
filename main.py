import os
import secrets
import base64
import binascii
import hashlib
import hmac
import json
import re
import time
import threading
from functools import lru_cache
from fastapi import FastAPI, Depends, Header, HTTPException, Query, Request, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from dotenv import load_dotenv

# Cargar variables de entorno desde .env ANTES de importar módulos internos
load_dotenv()

from schemas import EmailPayloadSchema, AnalysisResultSchema
from services.analyzer import analyze_email

# ============================================================
# Configuración de Seguridad
# ============================================================
# La clave de desarrollo solo se admite fuera de AWS y de PHISHARG_ENV=production.
PRODUCTION = (os.getenv("PHISHARG_ENV", "").lower() == "production"
              or bool(os.getenv("AWS_EXECUTION_ENV"))
              or bool(os.getenv("ECS_CONTAINER_METADATA_URI_V4")))
API_KEY = os.getenv("API_KEY") or "PHISHARG_DEV_KEY_123"
if PRODUCTION and (API_KEY == "PHISHARG_DEV_KEY_123" or len(API_KEY) < 32):
    raise RuntimeError("API_KEY debe ser una clave de al menos 32 caracteres en producción")
TOKEN_KEY = os.getenv("PHISHARG_TOKEN_KEY", "")
if PRODUCTION and len(TOKEN_KEY) < 32:
    raise RuntimeError("PHISHARG_TOKEN_KEY debe tener al menos 32 caracteres en producción")
REPLAY_TABLE = os.getenv("PHISHARG_REPLAY_TABLE", "").strip()
_used_token_nonces: dict[str, int] = {}
_used_token_lock = threading.Lock()
MAX_ANALYSIS_REQUEST_BYTES = 1_100_000
MAX_HYBRID_CONCURRENCY = int(os.getenv("PHISHARG_MAX_HYBRID_CONCURRENCY", "2"))
if MAX_HYBRID_CONCURRENCY < 1:
    raise RuntimeError("PHISHARG_MAX_HYBRID_CONCURRENCY debe ser positivo")
_hybrid_slots = threading.BoundedSemaphore(MAX_HYBRID_CONCURRENCY)
API_KEY_NAME = "X-API-Key"

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


@lru_cache(maxsize=1)
def _get_replay_table():
    import boto3
    from botocore.config import Config

    return boto3.resource(
        "dynamodb",
        config=Config(connect_timeout=2, read_timeout=2, retries={"max_attempts": 1}),
    ).Table(REPLAY_TABLE)


def _claim_token_nonce(nonce: str, expires: int, now: int) -> None:
    if REPLAY_TABLE:
        try:
            _get_replay_table().put_item(
                Item={"nonce": nonce, "expires_at": expires + 120},
                ConditionExpression="attribute_not_exists(nonce)",
            )
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ConditionalCheckFailedException":
                raise ValueError("Permiso ya utilizado") from exc
            raise HTTPException(status_code=503, detail="Control de reutilización no disponible") from exc
        return

    with _used_token_lock:
        for used_nonce, saved_expiry in list(_used_token_nonces.items()):
            if saved_expiry < now:
                del _used_token_nonces[used_nonce]
        if nonce in _used_token_nonces or len(_used_token_nonces) >= 10_000:
            raise ValueError("Permiso ya utilizado o servidor ocupado")
        _used_token_nonces[nonce] = expires

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if not api_key_header:
        raise HTTPException(
            status_code=401, 
            detail="Se requiere API Key en el header X-API-Key"
        )
    if not secrets.compare_digest(api_key_header, API_KEY):
        raise HTTPException(
            status_code=401, 
            detail="API Key inválida"
        )
    return api_key_header


async def get_hybrid_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    api_key: str | None = Security(api_key_header),
):
    """Accept a short-lived, body-bound browser token or a server-side API key."""
    if not authorization:
        return await get_api_key(api_key)
    if not authorization.startswith("Bearer ") or not TOKEN_KEY:
        raise HTTPException(status_code=401, detail="Autorización inválida")
    token = authorization.removeprefix("Bearer ")
    try:
        encoded, signature = token.split(".")
        if (len(token) > 1024 or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", signature)):
            raise ValueError("Formato inválido")
        expected = base64.urlsafe_b64encode(
            hmac.new(TOKEN_KEY.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
        ).rstrip(b"=").decode("ascii")
        if not secrets.compare_digest(signature, expected):
            raise ValueError("Firma inválida")
        padded = encoded + "=" * (-len(encoded) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        now = int(time.time())
        if (claims.get("aud") != "phisharg-hybrid"
                or type(claims.get("iat")) is not int
                or type(claims.get("exp")) is not int
                or claims["iat"] > now + 10
                or claims["exp"] < now
                or claims["exp"] - claims["iat"] > 90
                or not re.fullmatch(r"[a-f0-9]{32}", claims.get("nonce", ""))
                or not re.fullmatch(r"[a-f0-9]{64}", claims.get("digest", ""))):
            raise ValueError("Claims inválidas")
        body_digest = hashlib.sha256(
            claims["nonce"].encode("ascii") + b"." + await request.body()
        ).hexdigest()
        if not secrets.compare_digest(claims["digest"], body_digest):
            raise ValueError("La huella no corresponde al cuerpo")
        await run_in_threadpool(_claim_token_nonce, claims["nonce"], claims["exp"], now)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, binascii.Error):
        raise HTTPException(status_code=401, detail="Autorización inválida") from None
    return claims

# ============================================================
# Configuración de la Aplicación FastAPI
# ============================================================
app = FastAPI(
    title="PhishARG API",
    description="Backend de análisis de correos para detectar Phishing con XGBoost y reglas heurísticas.",
    version="2.0.0"
)

# El Add-in publicado obtiene un permiso breve y envía el correo directamente.
# CORS admite solo el origen del complemento o los indicados explícitamente.
cors_origins = [origin.strip().rstrip("/") for origin in
                os.getenv("PHISHARG_CORS_ORIGINS", "https://add-in-pfi.vercel.app").split(",") if origin.strip()]
if "*" in cors_origins:
    raise RuntimeError("PHISHARG_CORS_ORIGINS no admite el origen comodín")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["POST"],
    allow_headers=["Content-Type", API_KEY_NAME, "Authorization"],
)


@app.middleware("http")
async def limit_analysis_request_size(request: Request, call_next):
    """Reject oversized analysis input before JSON parsing or model execution."""
    if request.method == "POST" and request.url.path.startswith("/api/v1/analyze"):
        length = request.headers.get("content-length")
        if length is not None:
            try:
                if int(length) > MAX_ANALYSIS_REQUEST_BYTES:
                    return JSONResponse({"detail": "Correo demasiado grande"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "Content-Length inválido"}, status_code=400)
        chunks = bytearray()
        async for chunk in request.stream():
            if len(chunks) + len(chunk) > MAX_ANALYSIS_REQUEST_BYTES:
                return JSONResponse({"detail": "Correo demasiado grande"}, status_code=413)
            chunks.extend(chunk)
        request._body = bytes(chunks)
    return await call_next(request)

# ============================================================
# Endpoints
# ============================================================
@app.get("/")
def read_root():
    return {"message": "PhishARG API está funcionando. Motor: FastAPI + XGBoost + NLP."}


@app.post("/api/v1/analyze", response_model=AnalysisResultSchema)
def analyze_email_endpoint(
    payload: EmailPayloadSchema, 
    api_key: str = Depends(get_api_key)
):
    """
    Analiza un correo electrónico y devuelve la probabilidad de que sea phishing.
    Requiere autenticación mediante el header X-API-Key.
    """
    try:
        # Pydantic ya validó todo el payload y sus tipos de datos.
        # Solo necesitamos pasarlo a nuestra función de negocio.
        resultado = analyze_email(payload)
        return resultado
    except Exception:
        raise HTTPException(status_code=500, detail="No se pudo completar el análisis") from None

# (Opcional) Bloque para correr localmente sin uvicorn CLI
@app.post("/api/v1/analyze/hybrid", response_model=AnalysisResultSchema)
def analyze_hybrid_endpoint(
    payload: EmailPayloadSchema,
    quick: bool = Query(default=False),
    include_lime: bool = Query(default=True),
    lime_samples: int = Query(default=128, ge=64, le=256),
    api_key: str = Depends(get_hybrid_auth),
):
    """Return a quick verdict on request, or the full Hybrid explanation."""
    from services.hybrid_classifier import analyze_hybrid_email, HybridUnavailableError
    if not _hybrid_slots.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Análisis en curso; intente más tarde",
                            headers={"Retry-After": "5"})
    try:
        return analyze_hybrid_email(payload, include_lime=include_lime,
                                    lime_samples=lime_samples, quick=quick)
    except HybridUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        _hybrid_slots.release()


@app.post("/api/v1/analyze/hybrid/lime")
def explain_hybrid_lime_endpoint(
    payload: EmailPayloadSchema,
    num_samples: int = Query(default=128, ge=64, le=256),
    api_key: str = Depends(get_api_key),
):
    """Optional, costly local explanation of the raw hybrid model score."""
    if os.getenv("ENABLE_HYBRID_LIME", "").strip().lower() not in {"1", "true", "yes"}:
        raise HTTPException(status_code=404, detail="LIME experimental no está habilitado")
    directory = os.getenv("PHISHARG_HYBRID_MODEL_DIR")
    if not directory:
        raise HTTPException(status_code=503, detail="El modelo híbrido no está configurado")
    from pathlib import Path
    from services.hybrid_classifier import _load
    from services.hybrid_lime import explain_hybrid_text

    if not _hybrid_slots.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Análisis en curso; intente más tarde",
                            headers={"Retry-After": "5"})
    try:
        return explain_hybrid_text(_load(str(Path(directory).resolve())), payload, num_samples=num_samples)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (ImportError, OSError, RuntimeError, KeyError) as exc:
        raise HTTPException(status_code=503, detail="No se pudo generar la explicación LIME") from exc
    finally:
        _hybrid_slots.release()


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8001"))
    uvicorn.run("main:app", host=host, port=port, reload=True)
