# Proyecto Flujo

En `codex/hybrid-xai`, `POST /api/v1/analyze/hybrid` está implementado, conectado y operando con el modelo definitivo Hybrid XAI: ejecuta la clasificación (MiniLM + XGBoost), reglas heurísticas, SHAP, LIME (para perturbaciones locales de texto) y Qwen 2.5 3B Instruct para generar explicaciones didácticas de alertas en español en tiempo real. La respuesta de Qwen se valida frente a evidencias y acciones autorizadas mediante contrato Pydantic, y ante cualquier contingencia activa un respaldo determinista seguro. El Add-in de Outlook en `codex/hybrid-xai-addin` consume directamente esta ruta. Ver [entrenamiento, evaluación y configuración](docs/HYBRID_NLP.md).

Este repositorio contiene el código fuente del proyecto Flujo.

## Clasificador y respuesta del backend

Se conserva la columna `0` del modelo. El endpoint `POST /api/v1/analyze` aplica también reglas de contenido para solicitudes de secretos y desvío de pagos acompañado de instrucciones de no verificar. Las señales se reflejan en `is_phishing`, `risk_score`, `reason` e `intent` y se entregan al explicador.

La respuesta incorpora tres campos: `raw_model_score` (score previo a reglas; nulo si el modelo no intervino), `decision_source` y `content_signals` (regla y descripción). El score final puede incluir un piso heurístico de 0.95; no debe interpretarse como probabilidad calibrada del modelo.

Ver [resultados, pruebas y límites](reports/classifier_content_improvements.md). Los cambios se ejecutan al iniciar o recargar este backend. El servicio remoto necesita actualizarse con este código para reflejarlos.

## Requisitos Previos

Asegurate de tener Python instalado y luego instala las dependencias:

```bash
pip install -r requirements.txt
pip install -r requirements-hybrid.txt
```

## Configuración local de Hybrid y Qwen

Los pesos de Hybrid y el GGUF de Qwen no se guardan en Git. Antes de iniciar el backend, ubicá el artefacto Hybrid V3 entrenado y el archivo `qwen2.5-3b-instruct-q4_k_m.gguf` en rutas accesibles al proceso. Se configuran por separado:

```powershell
$env:PHISHARG_HYBRID_MODEL_DIR = 'C:\ruta\al\artefacto\multilingual-candidate-v3-curated'
$env:PHISHARG_SLM_MODEL_PATH = 'C:\ruta\al\qwen2.5-3b-instruct-q4_k_m.gguf'
python -m uvicorn main:app --host 127.0.0.1 --port 8001
```

La API ejecuta el modelo Hybrid y el modelo Qwen 2.5 3B cuantizado en GGUF en `/api/v1/analyze/hybrid`. Cuenta además con un generador de respaldo determinista seguro (`build_safe_fallback`) que garantiza respuesta continua estructurada ante cualquier eventualidad o contingencia.
