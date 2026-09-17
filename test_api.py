import os
from fastapi.testclient import TestClient

# Forzar el modo desarrollo para los tests y configurar una key fija
os.environ["API_KEY"] = "TEST_KEY_123"

from main import app, API_KEY, API_KEY_NAME
from main import API_KEY, API_KEY_NAME

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "FastAPI" in response.json()["message"]

def test_analyze_no_api_key():
    # Enviar un request sin el header de seguridad
    payload = {
        "metadata": {"asunto": "Test", "remitente_email": "test@test.com"},
        "contenido": "Hola mundo"
    }
    response = client.post("/api/v1/analyze", json=payload)
    
    # Debe ser bloqueado por la seguridad de FastAPI
    assert response.status_code == 401
    assert response.json()["detail"] == "Se requiere API Key en el header X-API-Key"

def test_analyze_wrong_api_key():
    headers = {API_KEY_NAME: "LLAVE_INVENTADA"}
    payload = {
        "metadata": {"asunto": "Test", "remitente_email": "test@test.com"},
        "contenido": "Hola mundo"
    }
    response = client.post("/api/v1/analyze", headers=headers, json=payload)
    
    assert response.status_code == 401
    assert response.json()["detail"] == "API Key inválida"

def test_analyze_invalid_payload():
    # Payload sin el campo requerido 'metadata'
    headers = {API_KEY_NAME: API_KEY}
    payload = {
        "contenido": "Hola mundo sin metadata"
    }
    response = client.post("/api/v1/analyze", headers=headers, json=payload)
    
    # Pydantic debe rechazarlo automáticamente (422 Unprocessable Entity)
    assert response.status_code == 422
    assert "metadata" in response.text

def test_analyze_valid_request():
    headers = {API_KEY_NAME: API_KEY}
    payload = {
        "metadata": {"asunto": "Test Seguro", "remitente_email": "ceo@empresa.com"},
        "contenido": "Reunion hoy a las 10.",
        "security_features": {
            "spf_result": "pass",
            "attachment_count": 0
        }
    }
    response = client.post("/api/v1/analyze", headers=headers, json=payload)
    
    # El mock model debería responder
    assert response.status_code == 200
    data = response.json()
    assert "is_phishing" in data
    assert "risk_score" in data

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "classifier" in data
    assert data["classifier"]["model_type"] == "phisharg_xgboost"
    assert "loaded" in data["classifier"]

def test_analyze_with_aliases():
    headers = {API_KEY_NAME: API_KEY}
    payload = {
        "metadata": {"subject": "Alerta de Factura", "from": "facturas@proveedor.com"},
        "body": "Por favor revise la factura adjunta.",
    }
    response = client.post("/api/v1/analyze", headers=headers, json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "is_phishing" in data
    assert "risk_score" in data

if __name__ == "__main__":
    print("Ejecutando tests de API de FastAPI...")
    test_root()
    test_health_endpoint()
    test_analyze_no_api_key()
    test_analyze_wrong_api_key()
    test_analyze_invalid_payload()
    test_analyze_valid_request()
    test_analyze_with_aliases()
    print("✅ Todos los tests de la API (Seguridad, Health y Aliases) pasaron correctamente.")
