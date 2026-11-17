# PhishARG — Backend de Inferencia Híbrida y Explicabilidad (XAI)

**Proyecto Final de Integración (PFI) — Ingeniería en Informática — UADE**  
**Servicio Central de Ciberdefensa (FastAPI / XGBoost / TreeSHAP / LIME / Qwen 2.5 3B SLM)**

---

## 1. Descripción General

Este repositorio contiene la arquitectura central del backend de **PhishARG**, responsable de la ingestión, análisis predictivo y generación de explicaciones didácticas en tiempo real ante amenazas de phishing y ataques de ingeniería social por correo electrónico.

El servicio está implementado sobre **FastAPI** y combina un clasificador híbrido de aprendizaje automático (embeddings multilingües MiniLM + 16 variables técnicas de cabeceras estructuradas) con explicabilidad matemática dual (TreeSHAP y LIME) y un modelo de lenguaje acotado (*Small Language Model* — Qwen 2.5 3B) ejecutado localmente sin dependencia de servicios de inferencia externos.

---

## 2. Arquitectura del Pipeline de Ciberdefensa

El endpoint productivo `POST /api/v1/analyze/hybrid` articula una arquitectura de inspección multicapa:

```
[ Solicitud HTTP: /api/v1/analyze/hybrid ]
                    │
                    ▼
 ┌─────────────────────────────────────────────────────────┐
 │ 1. Reglas Críticas & Heurísticas de Seguridad           │
 │    - Autenticación: SPF, DKIM, DMARC, CompAuth, SCL, BCL│
 │    - Contenido: Robo de credenciales, coerción MFA, QR  │
 └─────────────────────────┬───────────────────────────────┘
                           │
                           ▼
 ┌─────────────────────────────────────────────────────────┐
 │ 2. Clasificador Predictivo Híbrido                      │
 │    - Embeddings contextuales multilingües (MiniLM)      │
 │    - 16 variables técnicas estructuradas de cabeceras   │
 │    - Modelo XGBoost V4 calibrado con piso heurístico    │
 └─────────────────────────┬───────────────────────────────┘
                           │
                           ▼
 ┌─────────────────────────────────────────────────────────┐
 │ 3. Explicabilidad Dual (XAI)                            │
 │    - TreeSHAP: Atribuciones exactas por variable técnica│
 │    - LIME: Perturbaciones locales en cuerpo del correo  │
 └─────────────────────────┬───────────────────────────────┘
                           │
                           ▼
 ┌─────────────────────────────────────────────────────────┐
 │ 4. Generación Narrativa Segura (SLM Qwen 2.5 3B)        │
 │    - Contrato Pydantic estricto (ExplanationResponse)   │
 │    - Validación de no-alucinación contra evidencias     │
 │    - Fallback determinista seguro (build_safe_fallback) │
 └─────────────────────────────────────────────────────────┘
```

---

## 3. Requisitos del Sistema

* **Python:** 3.10 o superior (recomendado 3.11).
* **Gestor de entorno:** `venv` o `conda`.
* **Hardware para inferencia SLM:** CPU multinúcleo con soporte AVX2 (o GPU CUDA / Apple Metal para aceleración por hardware).

### Instalación de dependencias:
```powershell
pip install -r requirements.txt
pip install -r requirements-hybrid.txt
```

---

## 4. Configuración y Puesta en Marcha Local

Los pesos binarios pesados (`.pkl` y `.gguf`) no se almacenan en el repositorio de Git; se descargan de forma segura desde buckets privados de Amazon S3 con validación de hash SHA-256.

Para ejecutar el servicio localmente:
```powershell
$env:PHISHARG_HYBRID_MODEL_DIR = "C:\ruta\al\artefacto\multilingual-candidate-v3-curated"
$env:PHISHARG_SLM_MODEL_PATH = "C:\ruta\al\qwen2.5-3b-instruct-q4_k_m.gguf"
python -m uvicorn main:app --host 127.0.0.1 --port 8001
```

---

## 5. Infraestructura en la Nube (AWS)

* **Contenedores en Amazon ECS (Fargate):** Imagen Docker productiva compilada y publicada en Amazon ECR (`sha256:6552a0725e83d17c204db6d1fc5c2173f8cd930b1274b00fff5b7a2df4fba5db`).
* **Transporte Seguro:** Certificado ACM activo sobre Application Load Balancer (`https://api.phisharg.com`) con política exclusiva TLS 1.2 y TLS 1.3.

---

## 6. Protocolo de Pruebas y Validación

La estabilidad funcional, los contratos de seguridad y la fidelidad de las explicaciones se validan mediante la suite de pruebas automatizadas:

```powershell
# Pruebas del pipeline híbrido de inferencia
pytest test_hybrid_pipeline.py -q

# Pruebas de seguridad de API, tokens y control de orígenes cruzados
pytest test_api_security.py -q

# Pruebas de reglas de contenido y patrones de ingeniería social
pytest test_content_rules.py -q
```

---

## 7. Ramas Oficiales del Repositorio

| Rama | Propósito | Estado |
| :--- | :--- | :---: |
| **`entrega`** | Rama oficial de entrega académica, testing y auditoría de código | ✅ Sincronizada |
| **`hybrid-xai-aws`** | Rama de despliegue en la nube orientada a AWS ECS Fargate | ✅ Sincronizada |
| **`enable-hybrid-dispatch`** | Rama técnica para pruebas de despacho manual en AWS | ✅ Sincronizada |

---

## 8. Documentación Técnica de Referencia

* [**Guía de Organización y Estructura**](docs/GUIA_ORGANIZACION.md): Mapa completo del repositorio y políticas de aislamiento de artefactos.
* [**Memoria de Saneamiento y Entrega**](docs/RESUMEN_SANEAMIENTO_Y_ENTREGA.md): Registro integral de depuración de ramas de asistentes, saneamiento de notebooks y auditoría de idioma.
* [**Entrenamiento y Evaluación Hybrid**](docs/HYBRID_NLP.md): Métricas experimentales, calibración y evaluación comparativa.
* [**Registro del Adaptador Qwen**](model/entrega/README.md): Procedencia y auditoría del adaptador LoRA de evaluación.
