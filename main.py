import os
import os
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
    if api_key_header != API_KEY:
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
    from services.analyzer import calibrated_model, tfidf
    from services.slm_client import MODEL_PATH

    return {
        "status": "ok",
        "service": "PhishARG Backend Light",
        "version": "2.0.0",
        "classifier": {
            "loaded": calibrated_model is not None and tfidf is not None,
            "model_type": "phisharg_xgboost",
            "features_expected": 6022,
        },
        "slm_service": {
            "model_path": MODEL_PATH,
            "model_file_exists": os.path.exists(MODEL_PATH),
        },
    }


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
if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8001"))
    uvicorn.run("main:app", host=host, port=port, reload=True)
