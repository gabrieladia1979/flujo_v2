import os
import secrets
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Cargar variables de entorno desde .env ANTES de importar módulos internos
load_dotenv()

from schemas import EmailPayloadSchema, AnalysisResultSchema
from services.analyzer import analyze_email

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

# ============================================================
# Configuración de la Aplicación FastAPI
# ============================================================
app = FastAPI(
    title="PhishARG API",
    description="Backend de análisis de correos para detectar Phishing con XGBoost y reglas heurísticas.",
    version="2.0.0"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def is_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


@app.on_event("startup")
def preload_models_when_configured() -> None:
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
    directory = os.getenv("PHISHARG_HYBRID_MODEL_DIR")
    if not directory:
        return False
    from services.hybrid_classifier import _load
    return _load.cache_info().currsize > 0


@app.get("/api/v1/health")
def health_check():
    from services.analyzer import calibrated_model, tfidf
    from services.slm_client import slm_runtime_status

    return {
        "status": "ok",
        "classifier_loaded": calibrated_model is not None and tfidf is not None,
        "slm_service": slm_runtime_status(),
        "hybrid_loaded": _hybrid_ready(),
    }


@app.get("/api/v1/health/ready")
def readiness_check():
    from services.analyzer import calibrated_model, tfidf
    from services.slm_client import slm_runtime_status

    classifier_loaded = calibrated_model is not None and tfidf is not None
    hybrid_loaded = _hybrid_ready()
    slm_loaded = slm_runtime_status()["loaded"]
    ready = classifier_loaded and (not is_truthy(os.getenv("PRELOAD_HYBRID")) or hybrid_loaded)
    ready = ready and (not is_truthy(os.getenv("PRELOAD_SLM")) or slm_loaded)
    if not ready:
        raise HTTPException(status_code=503, detail={
            "classifier_loaded": classifier_loaded,
            "hybrid_loaded": hybrid_loaded,
            "slm_loaded": slm_loaded,
        })
    return {"status": "ready", "classifier_loaded": True, "hybrid_loaded": hybrid_loaded, "slm_loaded": slm_loaded}


@app.post("/api/v1/internal/warmup")
def warmup_slm(api_key: str = Depends(get_api_key)):
    from scripts.bootstrap_models import ensure_slm_model_available
    from services.slm_client import get_slm_instance, slm_runtime_status

    ensure_slm_model_available()
    get_slm_instance()
    return {"status": "ready", "component": "slm", "slm_service": slm_runtime_status()}

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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en el análisis: {str(e)}")

# (Opcional) Bloque para correr localmente sin uvicorn CLI
@app.post("/api/v1/analyze/hybrid", response_model=AnalysisResultSchema)
def analyze_hybrid_endpoint(payload: EmailPayloadSchema, api_key: str = Depends(get_api_key)):
    """Experimental route. Requires a separately trained local artifact directory."""
    from services.hybrid_classifier import analyze_hybrid_email, HybridUnavailableError
    try:
        return analyze_hybrid_email(payload)
    except HybridUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8001"))
    uvicorn.run("main:app", host=host, port=port, reload=True)
