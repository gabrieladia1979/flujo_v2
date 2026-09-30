import os
import secrets

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from dotenv import load_dotenv

load_dotenv()

from schemas import EmailPayloadSchema, AnalysisResultSchema
from services.analyzer import analyze_email

API_KEY = os.getenv("API_KEY", "PHISHARG_DEV_KEY_123")
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


def is_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


async def get_api_key(api_key_header: str = Security(api_key_header)):
    if not api_key_header:
        raise HTTPException(status_code=401, detail="Se requiere API Key en el header X-API-Key")
    if not secrets.compare_digest(api_key_header, API_KEY):
        raise HTTPException(status_code=401, detail="API Key inválida")
    return api_key_header


app = FastAPI(
    title="PhishARG API",
    description="Backend de análisis de correos para detectar Phishing con XGBoost y reglas heurísticas.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def preload_models_when_configured() -> None:
    """Load only the model components selected for this task."""
    if is_truthy(os.getenv("PRELOAD_SLM")):
        from scripts.bootstrap_models import ensure_slm_model_available
        from services.slm_client import get_slm_instance

        ensure_slm_model_available()
        get_slm_instance()
    if is_truthy(os.getenv("PRELOAD_HYBRID")):
        from scripts.bootstrap_hybrid import ensure_hybrid_model_available
        from services.hybrid_classifier import _load

        _load(str(ensure_hybrid_model_available()))


def _hybrid_ready() -> bool:
    if not os.getenv("PHISHARG_HYBRID_MODEL_DIR"):
        return False
    from services.hybrid_classifier import _load

    return _load.cache_info().currsize > 0


@app.get("/")
def read_root():
    return {"message": "PhishARG API está funcionando. Motor: FastAPI + XGBoost + NLP."}


@app.get("/api/v1/health")
def health_check():
    """Liveness and component state. This endpoint never downloads or loads the SLM."""
    from services.analyzer import calibrated_model, tfidf
    from services.slm_client import slm_runtime_status

    return {
        "status": "ok",
        "service": "PhishARG Backend Light",
        "version": "2.0.0",
        "classifier": {
            "loaded": calibrated_model is not None and tfidf is not None,
            "model_type": "phisharg_xgboost",
            "features_expected": 6022,
        },
        "slm_service": slm_runtime_status(),
        "hybrid_loaded": _hybrid_ready(),
    }


@app.get("/api/v1/health/ready")
def readiness_check():
    """Return 503 until all components selected for this task are ready."""
    from services.analyzer import calibrated_model, tfidf
    from services.slm_client import slm_runtime_status

    slm_status = slm_runtime_status()
    classifier_loaded = calibrated_model is not None and tfidf is not None
    hybrid_loaded = _hybrid_ready()
    ready = classifier_loaded
    ready = ready and (not is_truthy(os.getenv("PRELOAD_SLM")) or slm_status["loaded"])
    ready = ready and (not is_truthy(os.getenv("PRELOAD_HYBRID")) or hybrid_loaded)
    if not ready:
        raise HTTPException(
            status_code=503,
            detail={
                "message": "A required model is not ready",
                "classifier_loaded": classifier_loaded,
                "slm_service": slm_status,
                "hybrid_loaded": hybrid_loaded,
            },
        )
    return {"status": "ready", "classifier_loaded": True, "slm_service": slm_status,
            "hybrid_loaded": hybrid_loaded}


@app.post("/api/v1/internal/warmup")
def warmup_slm(api_key: str = Depends(get_api_key)):
    """Protected deployment hook: provision and initialize the GGUF on this task."""
    from scripts.bootstrap_models import ModelBootstrapError, ensure_slm_model_available
    from services.slm_client import get_slm_instance, slm_runtime_status

    try:
        ensure_slm_model_available()
        get_slm_instance()
    except (ModelBootstrapError, OSError, ImportError) as error:
        raise HTTPException(status_code=503, detail=f"SLM warm-up failed: {error}") from error
    return {"status": "ready", "component": "slm", "slm_service": slm_runtime_status()}


@app.post("/api/v1/analyze", response_model=AnalysisResultSchema)
def analyze_email_endpoint(
    payload: EmailPayloadSchema,
    api_key: str = Depends(get_api_key),
):
    try:
        return analyze_email(payload)
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Error en el análisis: {str(error)}") from error


@app.post("/api/v1/analyze/hybrid", response_model=AnalysisResultSchema)
def analyze_hybrid_endpoint(payload: EmailPayloadSchema, api_key: str = Depends(get_api_key)):
    """Experimental route that uses the separately provisioned hybrid artifact."""
    from services.hybrid_classifier import HybridUnavailableError, analyze_hybrid_email

    try:
        return analyze_hybrid_email(payload)
    except HybridUnavailableError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8001"))
    uvicorn.run("main:app", host=host, port=port, reload=True)
