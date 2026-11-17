# Resumen de Saneamiento, Arquitectura y Entrega — PhishARG Backend & Pipeline XAI

**Proyecto Final de Integración (PFI) — Ingeniería en Informática — UADE**  
**Fecha de consolidación:** 17 de noviembre de 2026  
**Ramas oficiales:** `entrega` (Evaluación académica y testing) / `hybrid-xai-aws` (Despliegue productivo en la nube)

---

## 1. Alcance y Objetivos de la Intervención

El presente documento resume las tareas de saneamiento, depuración de metadatos, estructuración y verificación de calidad llevadas a cabo sobre el backend de **PhishARG** (API FastAPI, clasificador híbrido, pipeline XAI y módulo generativo SLM) de cara a la entrega formal del Proyecto Final de Integración en UADE.

La intervención garantizó la eliminación exhaustiva de ramas y artefactos temporales de asistentes automáticos, la sincronización de ramas de producción y entrega, y la homologación de contratos de explicabilidad e idioma técnico en español.

---

## 2. Depuración de Ramas y Saneamiento de Control de Versiones

1. **Eliminación de Ramas Remotas de Asistentes:**
   * Se identificó y migró la rama remota `origin/codex/enable-hybrid-dispatch` hacia la rama canónica limpia `enable-hybrid-dispatch`.
   * Se eliminó de forma permanente la rama `codex/` de GitHub, dejando el repositorio remoto con cero ramas con prefijos de asistentes o herramientas no institucionales.
2. **Sincronización Total de Ramas y Worktrees:**
   * Se sincronizaron y unificaron mediante avance rápido (*fast-forward*) las ramas principales `entrega` y `hybrid-xai-aws` en el commit `481663f`.
   * Se configuraron los worktrees independientes:
     * `flujo_v2`: Rama `hybrid-xai-aws` (orientada a contenedor Docker y AWS ECS).
     * `flujo_v2_hybrid_cleanup`: Rama `entrega` (orientada a auditoría de código, documentación y suites de prueba).
     * `flujo_v2_aws_dispatch`: Rama `enable-hybrid-dispatch` (orientada al disparador manual del backend).
3. **Depuración de Cuadernos Interactivos (Notebooks):**
   * Se revisaron y actualizaron los notebooks de Google Colab (`PhishARG_Train_Curated_Colab.ipynb`, `PhishARG_Train_Hybrid_Colab.ipynb`) para clonar la rama oficial limpia `hybrid-nlp` en lugar de ramas experimentales.

---

## 3. Arquitectura del Servicio y Pipeline de Ciberdefensa

El backend articula un flujo de inferencia multicapa diseñado para mitigar ataques de phishing y evasión sofisticada:

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

## 4. Estado de la Infraestructura en la Nube (AWS)

* **Registro de Contenedores (ECR):** Imagen Docker compilada de manera reproducible y publicada en Amazon ECR bajo el commit `bf7b279` con digest inmutable verificado:
  ```
  sha256:6552a0725e83d17c204db6d1fc5c2173f8cd930b1274b00fff5b7a2df4fba5db
  ```
* **Balanceador y TLS:** Application Load Balancer productivo en AWS (`api.phisharg.com`) configurado con certificado ACM y restricción estricta a protocolos seguros TLS 1.2 y TLS 1.3.
* **Aislamiento de Pesos de Modelos:** Los artefactos `.pkl` (XGBoost) y `.gguf` (Qwen 2.5 3B) no se versionan en Git; residen en un bucket privado de Amazon S3 y se verifican mediante hash SHA-256 en tiempo de arranque del contenedor.

---

## 5. Auditoría de Idioma y Localización

* **Descripciones Heurísticas (`services/security_rules.py`, `services/content_rules.py`, `services/link_rules.py`):**
  * Todas las señales de seguridad y contenido emiten descripciones claras, concisas y en español formal:
    * *"SPF fail: el remitente no está autorizado por el dominio"*.
    * *"El mensaje pide enviar o compartir contraseñas, claves o códigos de autenticación"*.
    * *"Un enlace muestra una dirección web pero apunta a un dominio diferente"*.
* **Directivas del Módulo Generativo (`services/slm_explanation.py`):**
  * El system prompt del SLM instruye expresamente en español la estructuración estricta de razones y acciones recomendadas.
  * Se preserva el respaldo determinista seguro ante cualquier falla de validación o indisponibilidad del modelo.
* **Preservación Terminológica:** Se respetaron las nomenclaturas estándar de la industria (SPF, DKIM, DMARC, Return-Path, TLS 1.3, TreeSHAP, LIME).

---

## 6. Verificación y Protocolo de Pruebas

La estabilidad de la API y de las capas predictivas se valida mediante las pruebas unitarias y de integración:

```powershell
pytest test_hybrid_pipeline.py -q
pytest test_api_security.py -q
pytest test_content_rules.py -q
```

* **Pipeline Híbrido:** Validación del flujo en dos fases (`quick_verdict` + enriquecimiento XAI).
* **Seguridad de API:** Validación de autenticación por cabecera `X-API-Key`, limitación de tasa y aislamiento de excepciones internas.
* **Reglas de Contenido:** Validación de patrones de ingeniería social en lenguaje natural.

---

## 7. Tabla de Sincronización de Ramas

| Rama | Commit | Repositorio Remoto | Propósito |
| :--- | :---: | :--- | :--- |
| `entrega` | `481663f` | `origin/entrega` | Versión formal de entrega académica y auditoría |
| `hybrid-xai-aws` | `481663f` | `origin/hybrid-xai-aws` | Versión de despliegue en contenedor para AWS ECS |
| `enable-hybrid-dispatch` | `c9c535c` | `origin/enable-hybrid-dispatch` | Disparador manual para pruebas de despacho en AWS |
