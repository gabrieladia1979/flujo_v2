# Guía de Organización y Estructura — PhishARG Backend & Pipeline XAI

Este documento detalla la estructura del repositorio del backend de **PhishARG**, la distribución de sus componentes, la política de aislamiento de artefactos y las pautas para ejecución y prueba del sistema.

---

## 1. Arquitectura del Servicio

El servicio está implementado sobre **FastAPI** y articula una arquitectura de ciberdefensa en múltiples capas:

1. **Capa Heurística y Reglas de Seguridad (`services/security_rules.py`, `services/content_rules.py`):**
   * Inspección de cabeceras de autenticación (SPF, DKIM, DMARC, SCL, CompAuth).
   * Detección de patrones de ingeniería social (solicitudes de claves fiscales, códigos MFA, desvío de transferencias).
   * Reglas críticas con bypass inmediato para mitigar amenazas evidentes sin sobrecargar los modelos.

2. **Capa Predictiva Híbrida (`services/analyzer.py`, `services/hybrid_classifier.py`):**
   * Extracción de 16 variables técnicas de seguridad combinadas con embeddings multilingües (MiniLM).
   * Clasificador XGBoost calibrado para inferencia rápida y umbral de decisión controlado.

3. **Capa de Explicabilidad Dual (XAI - `services/`):**
   * **TreeSHAP:** Desglose matemático exacto de atribuciones en escala log-odds.
   * **LIME acotado:** Análisis local de términos sospechosos en el cuerpo del correo con validación de estabilidad.

4. **Capa Generativa de Narrativa Segura (SLM - `services/slm_*.py`):**
   * Modelo Qwen 2.5 3B cuantizado en GGUF operando localmente en CPU/GPU sin conexión a servicios externos.
   * Contrato estricto Pydantic (`ExplanationResponse`) que valida que las razones y acciones recomendadas provengan únicamente de evidencias observadas.
   * Mecanismo de respaldo determinista seguro (`build_safe_fallback`) que garantiza respuesta continua ante cualquier contingencia.

---

## 2. Mapa del Repositorio

* **Raíz (`/`):**
  * `main.py`: Entrada principal de la API FastAPI y definición de endpoints (`/api/v1/analyze`, `/api/v1/analyze/hybrid`).
  * `schemas.py`: Contratos de datos (Pydantic) de entrada y salida del sistema.
  * `database.py`: Conectores y esquemas de persistencia.
  * `Dockerfile`, `docker-compose.yml`, `render.yaml`: Configuraciones de contenedor y despliegue.
* **`services/`:** Lógica de clasificación, extracción de señales, cliente de inferencia local y validación de explicaciones.
* **`scripts/`:** Herramientas operativas del pipeline híbrido:
  * `scripts/slm/`: Preparación de datasets (ChatML), curaduría de candidatos y generador de notebooks Colab.
  * `scripts/legacy_patches/`: Utilidades históricas de parcheo y verificación manual aisladas para mantener la raíz limpia y evitar interferencias en la suite de pruebas.
* **`notebooks/`:** Notebooks interactivos de investigación y entrenamiento en Colab.
* **`data/`:** Conjuntos de datos y particiones versionadas de prueba.
* **`reports/`:** Auditorías reproducibles, matrices de confusión y métricas experimentales.
* **`docs/`:** Documentación técnica de arquitectura, seguridad y despliegue en AWS.
* **`deploy/`:** Políticas IAM, definiciones de tareas ECS y automatizaciones de despliegue.

---

## 3. Política de Artefactos y Modelos Pesados

Siguiendo las mejores prácticas de ingeniería de software:
* **Exclusión de Git:** Los archivos de pesos (`.pkl`), modelos cuantizados (`.gguf`) y artefactos de inferencia están estrictamente excluidos mediante `.gitignore`.
* **Almacenamiento de modelos:** Los pesos de producción se versionan de forma independiente y segura en buckets privados de **Amazon S3** con validación estricta de hash SHA-256 previa a la inicialización del contenedor.

---

## 4. Protocolo de Pruebas

El repositorio cuenta con una suite integral de pruebas que cubren reglas, contratos de API, aislamiento de dependencias y fidelidad de explicaciones:

```powershell
# Ejecución de pruebas unitarias y de integración
pytest test_hybrid_pipeline.py -q
pytest test_api_security.py -q
pytest test_content_rules.py -q
```

---

## 5. Ramas del Repositorio

* **`entrega`:** Rama limpia principal de entrega para evaluación académica, con estructura saneada y documentación actualizada.
* **`hybrid-xai-aws`:** Rama de despliegue orientada a la infraestructura en la nube (AWS ECS / Fargate).
* **`master`:** Rama base histórica del prototipo.
