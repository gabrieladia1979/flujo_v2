import os
import secrets
from fastapi import FastAPI, Depends, Header, HTTPException, Query, Request, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

# Cargar variables de entorno desde .env ANTES de importar módulos internos
load_dotenv()

PRODUCTION = (os.getenv("PHISHARG_ENV", "").lower() == "production"
              or bool(os.getenv("AWS_EXECUTION_ENV")) or bool(os.getenv("ECS_CONTAINER_METADATA_URI_V4")))
if PRODUCTION:
    if len(os.getenv("API_KEY", "")) < 32 or os.getenv("API_KEY") == "PHISHARG_DEV_KEY_123":
        raise RuntimeError("API_KEY debe ser una clave de al menos 32 caracteres en producción")
    if len(os.getenv("PHISHARG_TOKEN_KEY", "")) < 32:
        raise RuntimeError("PHISHARG_TOKEN_KEY debe tener al menos 32 caracteres en producción")
    if not os.getenv("PHISHARG_REPLAY_TABLE", "").strip():
        raise RuntimeError("PHISHARG_REPLAY_TABLE es obligatoria en producción")

from schemas import EmailPayloadSchema, AnalysisResultSchema
from services.analyzer import analyze_email, ClassifierUnavailableError, ClassifierInputTooLongError
from services.browser_auth import verify_browser_auth

# ============================================================
# Configuración de Seguridad
# ============================================================
# En producción, esto debe venir de las variables de entorno.
# Si no está definida, usamos una por defecto para desarrollo.
API_KEY = os.getenv("API_KEY", "PHISHARG_DEV_KEY_123")
API_KEY_NAME = "X-API-Key"

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

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


async def get_analysis_auth(request: Request, authorization: str | None = Header(default=None),
                            api_key: str | None = Security(api_key_header)):
    if authorization:
        return await verify_browser_auth(request, authorization)
    return await get_api_key(api_key)

# ============================================================
# Configuración de la Aplicación FastAPI
# ============================================================
app = FastAPI(
    title="PhishARG API",
    description="Backend de análisis de correos para detectar Phishing con XGBoost y reglas heurísticas.",
    version="2.0.0"
)

# Configurar CORS
cors_origins = [value.strip().rstrip("/") for value in os.getenv("PHISHARG_CORS_ORIGINS",
    "https://add-in-pfi-hybrid.vercel.app,https://add-in-pfi.vercel.app,https://localhost:3000").split(",") if value.strip()]
if PRODUCTION and "*" in cors_origins:
    raise RuntimeError("PHISHARG_CORS_ORIGINS no admite comodines en producción")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)

MAX_ANALYSIS_REQUEST_BYTES = 1_100_000


@app.middleware("http")
async def limit_analysis_size(request: Request, call_next):
    if request.method == "POST" and request.url.path == "/api/v1/analyze":
        try:
            if int(request.headers.get("content-length", "0")) > MAX_ANALYSIS_REQUEST_BYTES:
                return JSONResponse({"detail": "Correo demasiado grande"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "Content-Length inválido"}, status_code=400)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_ANALYSIS_REQUEST_BYTES:
                return JSONResponse({"detail": "Correo demasiado grande"}, status_code=413)
            body.extend(chunk)
        request._body = bytes(body)
    return await call_next(request)

# ============================================================
# Endpoints
# ============================================================
@app.get("/")
def read_root():
    return {"message": "PhishARG API está funcionando. Motor: FastAPI + XGBoost + NLP."}


@app.get("/api/v1/health")
def health_check():
    """
    Endpoint de salud público para monitoreo y despliegue cloud (Render, Railway, Kubernetes).
    No requiere autenticación.
    """
    from services.analyzer import calibrated_model, tfidf, nlp, matcher_global, LOADED_MODEL_PATH
    from services.slm_client import slm_runtime_status

    loaded = all(component is not None for component in (calibrated_model, tfidf, nlp, matcher_global))
    return {
        "status": "ok" if loaded else "degraded",
        "service": "PhishARG Backend Light",
        "version": "2.0.0",
        "classifier": {
            "loaded": loaded,
            "model_type": "phisharg_xgboost",
            "features_expected": int(getattr(calibrated_model, "n_features_in_", 6022)),
            "artifact_group": LOADED_MODEL_PATH.parent.name if LOADED_MODEL_PATH else None,
        },
        "slm_service": slm_runtime_status(),
    }


@app.post("/api/v1/analyze", response_model=AnalysisResultSchema)
def analyze_email_endpoint(
    payload: EmailPayloadSchema,
    quick: bool = Query(default=False),
    api_key = Depends(get_analysis_auth)
):
    """
    Analiza un correo electrónico y devuelve la probabilidad de que sea phishing.
    Requiere autenticación mediante el header X-API-Key.
    """
    try:
        # Pydantic ya validó todo el payload y sus tipos de datos.
        # Solo necesitamos pasarlo a nuestra función de negocio.
        resultado = analyze_email(payload, quick=True) if quick else analyze_email(payload)
        return resultado
    except ClassifierUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except ClassifierInputTooLongError as e:
        raise HTTPException(status_code=413, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail="No se pudo completar el análisis.") from e


def slm_required():
    return os.getenv("PRELOAD_SLM", "").lower() in {"1", "true", "yes", "on"}


@app.on_event("startup")
def preload_slm_when_configured():
    if slm_required():
        from scripts.bootstrap_models import ensure_slm_model_available
        from services.slm_client import get_slm_instance
        ensure_slm_model_available()
        get_slm_instance()


@app.get("/api/v1/health/ready")
def readiness_check():
    health = health_check()
    ready = health["classifier"]["loaded"] and (not slm_required() or health["slm_service"]["loaded"])
    if not ready:
        raise HTTPException(status_code=503, detail="Los componentes requeridos no están listos")
    return {"status": "ready", "classifier_loaded": True, "slm_service": health["slm_service"]}


@app.post("/api/v1/internal/warmup")
def warmup_slm(api_key=Depends(get_api_key)):
    from scripts.bootstrap_models import ensure_slm_model_available
    from services.slm_client import get_slm_instance, slm_runtime_status
    try:
        ensure_slm_model_available()
        get_slm_instance()
    except Exception as error:
        raise HTTPException(status_code=503, detail="No se pudo inicializar el explicador") from error
    return {"status": "ready", "component": "slm", "slm_service": slm_runtime_status()}


# (Opcional) Bloque para correr localmente sin uvicorn CLI
if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8001"))
    uvicorn.run("main:app", host=host, port=port, reload=True)
