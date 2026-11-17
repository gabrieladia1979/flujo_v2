# Bitácora Integral de la Jornada — 17 de noviembre de 2026

**Proyecto Final de Integración (PFI) — Ingeniería en Informática — UADE**  
**Proyecto:** PhishARG — Plataforma de Ciberdefensa contra Phishing Asistida por IA y Explicabilidad (XAI)  
**Alcance:** Ecosistema completo (Frontend Outlook, Backend FastAPI, Infraestructura AWS, Memoria Académica y Datasets NLP)

---

## 1. Resumen Ejecutivo de la Jornada

Durante la jornada del 17 de noviembre de 2026 se llevó a cabo una intervención técnica integral sobre los 8 repositorios y árboles de trabajo (*worktrees*) que conforman el proyecto **PhishARG**.

Los objetivos primordiales alcanzados fueron:
1. **Saneamiento y descarte de rastros:** Eliminación exhaustiva de ramas remotas y locales, archivos de configuración, metadatos y prompts residuales de asistentes de codificación o herramientas automáticas (`codex/*`, `.claude/`, `openspec/`, `AGENTS.md`).
2. **Integración definitiva del cliente Hybrid:** Homologación de la rama `entrega` del complemento de Outlook con el servidor Hybrid del backend (`flujo_v2/entrega`), adoptando el flujo de inferencia en dos fases con explicabilidad TreeSHAP/LIME y autorización criptográfica HMAC.
3. **Localización al español formal:** Auditoría y traducción exhaustiva de interfaces de usuario, estados de cabeceras, botones, alertas y directivas de explicabilidad al español argentino, respetando estándares y siglas internacionales de ciberseguridad.
4. **Verificación de infraestructura y pruebas:** Validación empírica del despliegue en AWS ECS Fargate, pruebas de carga de modelos (XGBoost V4 y Qwen 2.5 3B GGUF) y verificación exitosa de suites de pruebas automatizadas en cliente y servidor.
5. **Estética y presentación profesional:** Reestructuración ejecutiva de los archivos `README.md` de todos los repositorios y unificación de la identidad de marca institucional.

---

## 2. Acciones de Saneamiento Técnico de Repositorios

### A. Eliminación de Ramas de Asistentes en GitHub
* Se detectó la rama remota `origin/codex/enable-hybrid-dispatch` en el repositorio `flujo_v2`.
* Se migró su contenido a la rama canónica limpia `enable-hybrid-dispatch`, se configuró el worktree local correspondiente y se eliminó de forma permanente la rama `codex/` de GitHub.
* **Resultado:** Cero ramas con prefijos de asistentes o herramientas no institucionales en todo el ecosistema remoto de GitHub.

### B. Depuración de Referencias Colgantes en Git
* Se detectó y eliminó una referencia dangling de backup histórico (`refs/original/refs/heads/test-history`) en `Add_in_PFI` derivada de reescrituras previas con `git-filter-branch`.

### C. Eliminación Física de Archivos Huérfanos
* Se detectaron carpetas y archivos huérfanos que aún residían físicamente en disco aunque estuvieran en `.gitignore`:
  * `Add_in_PFI_hybrid_pilot`: Directorios `.claude/` y `openspec/`, y archivo `AGENTS.md`.
  * `UADE_PFI_Template`: Archivo `AGENTS.md`.
* Se eliminaron físicamente del disco mediante scripts seguros y se normalizaron los archivos `.gitignore` para conservar únicamente directivas estándar de la industria (Node/React, LaTeX y Python).

---

## 3. Integración Arquitectónica del Cliente Hybrid en `Add_in_PFI/entrega`

### Diagnóstico Inicial:
* El servidor en `flujo_v2/entrega` ya contaba con el pipeline definitivo Hybrid XAI (`/api/v1/analyze/hybrid`).
* Sin embargo, la rama `Add_in_PFI/entrega` conservaba el código del prototipo v1 intermediado por proxy clásico (`/api/v1/analyze`), mientras que el cliente correspondiente a la tesis se encontraba en la rama paralela `hybrid-aws-pilot`.

### Resolución Técnica Aplicada:
* Se unificó el cliente Hybrid en `Add_in_PFI/entrega` (commit `56ae9fb` / `b7c9475`), consolidando:
  1. **Análisis en dos fases (*Two-Phase Analysis*):**
     * **Fase 1 (`quick=true`):** Solicitud rápida instantánea que computa el veredicto predictivo y la heurística de seguridad.
     * **Fase 2:** Enriquecimiento progresivo en segundo plano con explicabilidad TreeSHAP (escala log-odds) y LIME acotado en el texto del mensaje.
  2. **Privacidad de Extremo a Extremo con Tokens HMAC:**
     * El correo corporativo **nunca pasa por Vercel**; viaja directamente desde Outlook hacia AWS por **TLS 1.3**.
     * Vercel actúa exclusivamente como autoridad de autenticación (`api/v1/analyze/token.mjs`), recibiendo únicamente el digest salado `SHA-256(nonce + correo)` para emitir un token firmado por HMAC SHA-256 con vigencia de 90 segundos.
  3. **Identidad Independiente en Manifiestos:**
     * `Id` GUID `f0355dbe-00bc-47de-8626-f157b7c59135` registrado como **PhishARG Hybrid Piloto**, permitiendo su coexistencia con cualquier versión previa sin colisión en el cliente de correo.
  4. **Endpoint Productivo en AWS:**
     * Configuración del Application Load Balancer `https://api.phisharg.com` en `.env.example`.

---

## 4. Localización Integral al Español Argentino

Se realizó una revisión integral de terminología e idioma en todos los niveles del sistema:

* **Complemento de Outlook (`taskpane.tsx`, componentes y manifiestos):**
  * Estados de autenticación: `pass` ➔ **Aprobado**, `fail` ➔ **Falló**, `softfail` ➔ **Sospechoso**, `none`/`unknown` ➔ **Sin registro**.
  * Botones y acciones: *"Analizar correo"*, *"Analizar Amenaza"*, *"Reportar correo sospechoso"*.
  * Mensajes de contexto: *"Analizando el correo. Esperá un momento."*, *"Variables técnicas influyentes"*, *"Palabras asociadas por LIME con mayor riesgo"*.
  * Título del panel en `taskpane.html`: Actualizado de `Phish-Score Lab` a `PhishARG Hybrid`.
* **Backend (`services/`):**
  * Descripciones heurísticas en `security_rules.py` (*"SPF fail: el remitente no está autorizado..."*), `content_rules.py` (*"El mensaje pide enviar o compartir contraseñas..."*) y `link_rules.py` (*"Un enlace muestra una dirección web pero apunta a un dominio diferente..."*).
  * Directivas del SLM Qwen en `slm_explanation.py` en español riguroso con respaldo determinista seguro (`build_safe_fallback`).
* **Preservación Técnica:** Se respetaron los acrónimos y estándares de la industria (SPF, DKIM, DMARC, TLS 1.3, Return-Path, SCL, CompAuth, TreeSHAP, LIME).

---

## 5. Infraestructura en la Nube (AWS) y Modelos

* **Imagen en Amazon ECR:**
  * Compilada de forma reproducible desde el commit `bf7b279` y publicada con digest inmutable verificado:
    `sha256:6552a0725e83d17c204db6d1fc5c2173f8cd930b1274b00fff5b7a2df4fba5db`.
* **Ensayo Empírico en Fargate (`us-east-1`):**
  * Tarea privada `862052350c754032940a338e73811d3a` ejecutada con éxito; precargó los objetos versionados de S3 (XGBoost V4 y Qwen 2.5 3B Instruct GGUF).
  * Respuesta HTTP 200 de disponibilidad y análisis sintético con `is_phishing=true` y `explanation_source=qwen` validada contra contrato Pydantic. Finalización limpia con código de salida 0. El índice de evidencia en `progress/README.md` identifica el ensayo.
* **Seguridad de Transporte:**
  * Certificado ACM activo en ALB (`api.phisharg.com`) con cifrado estricto TLS 1.2 y TLS 1.3.

---

## 6. Saneamiento de Cuadernos y Datasets

* **Notebooks Colab (`flujo_v2/notebooks/`):**
  * `PhishARG_Train_Curated_Colab.ipynb` y `PhishARG_Train_Hybrid_Colab.ipynb` actualizados para clonar la rama oficial limpia `hybrid-nlp`.
* **Scripts de Aumentación (`Clasificador_PFI`):**
  * Saneamiento de `argentinizar_dataset.py`, `argentinizar_colab.py` y `argentinizar_masivo.py`, eliminando nombres comerciales de asistentes, prompts con personas artificiales y unificando variables a `DATA_AUGMENTATION_API_KEY`.

---

## 7. Batería de Pruebas y Calidad de Código

| Entorno | Suite de Pruebas | Resultado | Detalle |
| :--- | :--- | :---: | :--- |
| **Add-in de Outlook** | `test-analysis.cjs` + `test-api-token.cjs` | **15 / 15 ✅** | Contratos de veredicto, HMAC, privacidad y límites de carga útil |
| **Add-in de Outlook** | `tsc --noEmit` (TypeScript Check) | **0 Errores ✅** | Tipado estricto verificado en toda la UI y servicios |
| **Add-in de Outlook** | `webpack --mode production` | **Éxito (5.1s) ✅** | Bundle de producción minificado (192 KiB) |
| **Backend FastAPI** | `test_hybrid_pipeline.py` | **16 / 16 ✅** | Flujo híbrido en dos fases, extracción de 16 variables y XAI |
| **Backend FastAPI** | `test_api_security.py` | **9 / 9 ✅** | Validación de claves, firma de tokens HMAC y rechazo de CORS ajenos |

---

## 8. Matriz Consolidada de Repositorios (Estado Final)

Todos los árboles de trabajo se encuentran limpios, sin stashes y sincronizados con sus ramas remotas en GitHub:

| Repositorio / Worktree | Rama Oficial | Commit | Estado en GitHub | Rol en el Sistema |
| :--- | :--- | :---: | :---: | :--- |
| [**Add_in_PFI**](file:///C:/Users/Usuario/Documents/GitHub/Add_in_PFI) | `entrega` | `b7c9475` | ✅ Al día | Complemento Outlook oficial con cliente Hybrid en dos fases |
| [**Add_in_PFI_clean**](file:///C:/Users/Usuario/Documents/GitHub/Add_in_PFI_clean) | `entrega` | `b7c9475` | ✅ Al día | Clon de respaldo idéntico |
| [**Add_in_PFI_hybrid_pilot**](file:///C:/Users/Usuario/Documents/GitHub/Add_in_PFI_hybrid_pilot) | `hybrid-aws-pilot` | `092c990` | ✅ Al día | Worktree paralelo de desarrollo del piloto |
| [**flujo_v2**](file:///C:/Users/Usuario/Documents/GitHub/flujo_v2) | `hybrid-xai-aws` | `f0a3165` | ✅ Al día | Servidor FastAPI Hybrid, XGBoost, TreeSHAP/LIME y Qwen SLM |
| [**flujo_v2_hybrid_cleanup**](file:///C:/Users/Usuario/Documents/GitHub/flujo_v2_hybrid_cleanup) | `entrega` | `f0a3165` | ✅ Al día | Worktree saneado con documentación de entrega |
| [**flujo_v2_aws_dispatch**](file:///C:/Users/Usuario/Documents/GitHub/flujo_v2_aws_dispatch) | `enable-hybrid-dispatch` | `c9c535c` | ✅ Al día | Disparador manual para pruebas en AWS |
| [**UADE_PFI_Template**](file:///C:/Users/Usuario/Documents/GitHub/UADE_PFI_Template) | `migracion-template-2026` | `cc5ee46` | ✅ Al día | Memoria LaTeX con bitácora `CONTEXTO_2026-11-17.md` |
| [**Clasificador_PFI**](file:///C:/Users/Usuario/Documents/GitHub/Clasificador_PFI) | `main` | `c339a03` | ✅ Al día | Datasets y scripts NLP sin metadatos de asistentes |
