# Pruebas Funcionales — PhishARG

## 1. Estrategia de Testing

PhishARG emplea una estrategia de pruebas en capas que combina **testing automatizado** con **evaluaciones empíricas sobre datasets** para validar cada componente del pipeline de detección de phishing. La estrategia sigue el principio de la pirámide de testing: una base amplia de tests unitarios, una capa intermedia de tests de integración y una capa superior de tests end-to-end y evaluaciones de rendimiento.

### Herramientas y frameworks utilizados

| Herramienta | Propósito |
|---|---|
| **pytest** (v9.1.1) | Framework principal de testing automatizado |
| **FastAPI TestClient** | Pruebas funcionales de endpoints HTTP |
| **unittest.mock** | Aislamiento de componentes mediante mocks y stubs |
| **scikit-learn metrics** | Cálculo de precisión, recall, F1 y matriz de confusión |
| **SHAP** | Explicabilidad del modelo XGBoost |
| **spaCy** (`es_core_news_sm`) | Procesamiento de lenguaje natural y validación de matcher |

### Entorno de ejecución

- **Python**: 3.14
- **XGBoost**: 2.0.3 (inferencia) / 3.4.1 (entrenamiento)
- **spaCy**: 3.8.16 con modelo `es_core_news_sm` 3.8.0
- **SO**: Windows 11 (desarrollo y testing local)

---

## 2. Técnicas de Testing Aplicadas

### 2.1 Testing Unitario

**Objetivo**: Validar el comportamiento individual de cada componente aislado.

**Cobertura**: 38 tests unitarios en 3 archivos.

- **Reglas de seguridad** (`test_security_rules.py`, 19 tests): Verifica cada ajuste heurístico individual (SPF fail → +0.15, DKIM fail → +0.10, DMARC fail → +0.15, etc.), los límites matemáticos del score (clamping a [0.0, 1.0]), y los escenarios extremos (peor caso acumulado, mejor caso con autenticación interna).
- **Reglas de contenido** (`test_content_rules.py`, 4 tests parametrizados sobre 34 variantes): Evalúa la activación correcta de reglas `credential_disclosure_request` y `payment_redirection_no_verification` con 13 casos positivos y 19 contrastes benignos (negaciones, citas, consejos de seguridad).
- **Herramientas de evaluación** (`test_classifier_evaluation_tools.py`, 15 tests): Valida la auditoría del modelo, validación de corpus JSONL, cálculo de métricas estadísticas, determinismo de reportes y aislamiento de reglas críticas en métricas.

### 2.2 Testing Funcional / API

**Objetivo**: Verificar que los endpoints HTTP respondan correctamente a solicitudes válidas e inválidas.

**Cobertura**: 11 tests funcionales.

- **Endpoint de análisis** (`POST /api/v1/analyze`): Autenticación con `X-API-Key` (401 sin clave, 401 con clave incorrecta), validación de payloads Pydantic (422 sin metadatos), respuesta completa con `is_phishing` y `risk_score`.
- **Endpoint de salud** (`GET /api/v1/health`): Retorna estado del clasificador, tipo de modelo y existencia del SLM.
- **Compatibilidad de aliases**: Acepta nombres alternativos de campos (`subject` → `asunto`, `from` → `remitente_email`, `body` → `contenido`).
- **Integración reglas + cabeceras**: Las reglas de contenido prevalecen sobre cabeceras SPF/DKIM/DMARC válidas cuando se detecta phishing textual.

### 2.3 Testing de Regresión

**Objetivo**: Prevenir degradaciones inadvertidas en funcionalidad existente.

**Cobertura**: 8 tests de regresión.

- **Extracción de dominios**: Normalización ante esquemas HTTP/HTTPS, mayúsculas, prefijos `www`.
- **Parseo de HTML**: Manejo de URLs relativas, entidades HTML (`&amp;`), exclusión de píxeles de seguimiento.
- **Deduplicación de enlaces**: Cuando el texto visible coincide con el hipervínculo.
- **Inmutabilidad de entrada**: Los payloads Pydantic no se mutan durante la inferencia.
- **Caché del analizador**: Reutilización para solicitudes idénticas, separación por remitente.
- **Índice de producción**: Los scripts de auditoría restauran `PRODUCTION_PHISHING_PROBABILITY_INDEX = 0`.

### 2.4 Testing de Integración

**Objetivo**: Verificar el pipeline completo de NLP + ML + heurísticas + SLM.

**Cobertura**: 14 tests de integración.

- **Pipeline XGBoost** (`test_xgboost_analyzer.py`, 8 tests): Carga de modelo, inferencia sobre correo legítimo vs. phishing, extracción de slots psicológicos (`URGENCIA`, `AUTORIDAD`, `FINANCIERO`), ajustes por cabeceras de seguridad, validación del contrato de respuesta.
- **Integración SLM** (`test_analyzer_slm_integration.py`, 6 tests): Autoridad final del servidor, separación de scores brutos vs. ajustados, camino crítico sin score del clasificador, preservación de campos públicos, fallback determinista y seguro.

### 2.5 Testing End-to-End (Smoke Tests)

**Objetivo**: Ejecutar el flujo completo desde payload de entrada hasta explicación estructurada.

**Cobertura**: 2 escenarios E2E.

- **Correo legítimo de oficina**: Dispara el fast-path con respuesta casi instantánea.
- **Phishing de robo de credenciales**: Dispara el flujo profundo de detección, generación de explicación SLM y validación de estructura.

### 2.6 Testing de Seguridad y Anti-Alucinación

**Objetivo**: Garantizar que el SLM no pueda alterar veredictos, inyectar URLs maliciosas ni alucinar evidencia.

**Cobertura**: 22 tests de seguridad en `test_slm_explainer.py`.

- **Barrera de autoridad**: Rechaza cualquier intento del SLM de modificar `is_phishing`, `risk_score` o `intent`.
- **Validación de esquema**: Rechaza campos anidados no autorizados, acciones desconocidas, evidencia duplicada, claves JSON duplicadas.
- **Anti-inyección**: Rechaza respuestas con URLs, caracteres de control ASCII o markdown fences.
- **Límites de tamaño**: Fallback inmediato ante respuestas que superen 16.384 bytes.
- **Coherencia**: Rechaza resúmenes que contradigan el veredicto del servidor.
- **Determinismo del fallback**: El fallback es seguro, determinista y consistente.

### 2.7 Testing de Falsos Positivos

**Objetivo**: Validar que correos legítimos con señales ambiguas no sean clasificados erróneamente.

**Cobertura**: 14 tests en 8 clases temáticas.

| Escenario | Validación |
|---|---|
| Newsletter con Reply-To diferente | No es amenaza crítica, penalización marginal |
| Email reenviado con DMARC fail | DKIM intacto compensa, no supera umbral |
| Envío via SaaS (SendGrid, SES) | Return-Path de rebote no es amenaza |
| Factura urgente legítima con auth perfecta | Autenticación neutraliza vocabulario de urgencia |
| Acumulación de penalizaciones | Tope máximo de +0.35 para delta positivo |
| Phishing real (SPF fail + sender mismatch) | Sigue detectándose como crítico |
| Adjunto ejecutable | Siempre clasificado como amenaza crítica |
| Dominio oficial con auth perfecta | Bonificación masiva (≤ -0.50) |

### 2.8 Testing Contrastivo Bilingüe

**Objetivo**: Evaluar la detección de amenazas modernas (MFA push, device code, payment redirection) en español e inglés.

**Cobertura**: 12 casos de challenge + 16 pares contrastivos (defensivo vs. ofensivo).

- **Challenge bilingüe**: 12 casos de amenazas reales 2026 en español e inglés → 12/12 correctos.
- **Pares contrastivos**: 8 pares donde un texto es defensivo/educativo (debe ser legítimo) y su contraparte es un ataque real (debe ser phishing). Verifica que las reglas distingan correctamente ambos casos.

---

## 3. Inventario de Tests Automatizados

| Archivo | Líneas | Tests | Técnica Principal |
|---|:---:|:---:|---|
| `test_security_rules.py` | 296 | 19 | Unitario — Reglas heurísticas |
| `test_slm_explainer.py` | 326 | 22 | Seguridad — Anti-alucinación SLM |
| `test_classifier_evaluation_tools.py` | 234 | 15 | Unitario — Herramientas de auditoría |
| `test_false_positives.py` | 262 | 14 | Funcional — Mitigación de FP |
| `test_classifier_regressions.py` | 82 | 8 | Regresión — Pipeline ML |
| `test_xgboost_analyzer.py` | 271 | 8 | Integración — NLP + ML + heurísticas |
| `test_api.py` | 101 | 7 | Funcional — Endpoints HTTP |
| `test_analyzer_slm_integration.py` | 362 | 6 | Integración — SLM con mocks |
| `test_content_rules.py` | 101 | 4 | Unitario contrastivo |
| `test_end_to_end.py` | 63 | 2 | End-to-End / Smoke |
| `test_slm_transparente.py` | 154 | 1 | Observabilidad interactiva |
| `test_slm_vivo.py` | 55 | 1 | Integración en vivo (CPU) |
| **Total** | **2.307** | **107** | |

---

## 4. Cobertura por Componente del Sistema

```
┌────────────────────────────────────────────────────────┐
│                    FastAPI (main.py)                     │
│  test_api.py: 7 tests HTTP (auth, payloads, health)     │
├────────────────────────────────────────────────────────┤
│              Analizador (services/analyzer.py)           │
│  test_xgboost_analyzer.py: 8 tests pipeline completo   │
│  test_classifier_regressions.py: 8 tests regresión     │
│  test_analyzer_slm_integration.py: 6 tests integración │
│  test_end_to_end.py: 2 escenarios E2E                  │
├───────────────┬───────────────┬────────────────────────┤
│ Reglas de     │ Reglas de     │ SLM Explainer          │
│ Contenido     │ Seguridad     │ (services/slm_client)  │
│ 4 tests       │ 19 tests      │ 22+2 tests             │
├───────────────┴───────────────┴────────────────────────┤
│            Modelo XGBoost + spaCy + TF-IDF              │
│  test_classifier_evaluation_tools.py: 15 tests          │
│  test_false_positives.py: 14 tests                      │
└────────────────────────────────────────────────────────┘
```

---

## 5. Datasets de Evaluación

### 5.1 Corpus Diagnóstico v3

- **Archivo**: `data/classifier_diagnostic_v3.jsonl`
- **Tamaño**: 56 casos (24 base + 32 variantes de contraste)
- **Categorías**: 10 (comunicación interna, suplantación tributaria, suplantación bancaria, email técnico, newsletter, factura legítima, notificación bancaria, recuperación de contraseña, notificación marketplace, robo de credenciales, premio falso, entrega falsa, factura falsa, malware, otros legítimos, otro phishing)
- **Naturaleza**: Corpus de desarrollo diagnóstico, no un holdout independiente
- **Reproducción**: `python scripts/compare_classifier.py --dataset data/classifier_diagnostic_v3.jsonl --output reports/classifier_content_v3`

### 5.2 Challenge Bilingüe (Amenazas 2026)

- **Tamaño**: 12 casos
- **Cobertura**: MFA push fatigue (EN/ES), device code phishing (EN/ES), payment redirection (EN/ES), credential theft (EN/ES), OAuth consent phishing, suplantación con urgencia
- **Propósito**: Evaluar la detección de amenazas emergentes no cubiertas por el modelo base

### 5.3 Pares Contrastivos Bilingües

- **Tamaño**: 16 pares (8 defensivos + 8 ofensivos)
- **Propósito**: Verificar que el sistema distinga textos defensivos/educativos de ataques reales con vocabulario similar
- **Ejemplo**: "Rechace cualquier solicitud de aprobación que no haya iniciado" (legítimo) vs. "Apruebe ahora la notificación que aparece en su teléfono" (phishing)

---

## 6. Resultados Cuantitativos

### 6.1 Tests Automatizados (pytest)

```
140 passed in ~60s
0 failed
0 errors
```

Todas las 140 pruebas automatizadas pasan consistentemente, incluyendo carga del modelo real XGBoost, llamadas HTTP autenticadas y validación de esquemas Pydantic.

### 6.2 Evaluación del Corpus Diagnóstico v3

| Configuración | Aciertos | FP | FN | Precision | Recall | F1 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Reglas habilitadas** (producción) | **56/56** | **0** | **0** | **1.00** | **1.00** | **1.00** |
| Reglas deshabilitadas (ablación) | 41/56 | 0 | 15 | 1.00 | 0.57 | 0.73 |

### 6.3 Challenge Bilingüe

| Resultado | Valor |
|---|:---:|
| Aciertos | 12/12 (100%) |
| Falsos positivos | 0 |
| Falsos negativos | 0 |

### 6.4 Pares Contrastivos

| Resultado | Valor |
|---|:---:|
| Aciertos | 16/16 (100%) |
| Falsos positivos | 0 |
| Falsos negativos | 0 |

---

## 7. Análisis de Ablación

El análisis de ablación (desactivación controlada de componentes) demuestra el aporte de cada capa del sistema:

### Impacto de las reglas de contenido

Sin las reglas de contenido, el modelo XGBoost por sí solo no detecta 15 de los 56 casos de diagnóstico:

| Categoría no detectada sin reglas | Casos | Motivo |
|---|:---:|---|
| Robo de credenciales por texto | 9 | Solicitudes de contraseña sin URLs maliciosas |
| Desvío de pagos | 4 | Cambios de cuenta bancaria con instrucciones de no verificar |
| Otro phishing textual | 2 | Ataques basados en ingeniería social sin indicadores técnicos |

**Decisión tomada**: Se mantienen las reglas de contenido como componente indispensable del pipeline, con un piso heurístico de score de 0.95 cuando se activan. Este piso se aplica después de los descuentos por cabeceras, no es una probabilidad calibrada del modelo.

### Impacto del matcher bilingüe

La extensión del matcher de spaCy con tokens en inglés permitió detectar las 12 amenazas del challenge bilingüe. Sin la extensión, los 6 casos en inglés no habrían sido detectados por el NLU.

---

## 8. Decisiones Tomadas Basadas en Resultados

### 8.1 Conservación del índice de producción

**Hallazgo**: La evaluación con el índice alternativo (columna 1 de `predict_proba`) produjo 21/56 aciertos vs. 56/56 con el índice 0.

**Decisión**: Se mantiene `PRODUCTION_PHISHING_PROBABILITY_INDEX = 0` como el contrato canónico. Se documenta la auditoría completa en `docs/CLASIFICADOR_NLP_AUDITORIA_Y_CORRECCION.md`.

### 8.2 Adición de reglas de contenido

**Hallazgo**: El modelo XGBoost solo detectaba 41/56 casos. Los 15 falsos negativos correspondían a ataques basados puramente en texto (sin URLs sospechosas, sin adjuntos ejecutables).

**Decisión**: Se implementaron reglas `credential_disclosure_request` y `payment_redirection_no_verification` que complementan al clasificador sin reentrenarlo. Resultado: 56/56.

### 8.3 Extensión bilingüe

**Hallazgo**: Las reglas originales solo cubrían español. Los 6 casos de challenge en inglés no se detectaban.

**Decisión**: Se extendieron todos los patrones regex (`_SEND`, `_SECRET`, `_PAY`, `_VERIFY_TARGET`, etc.) y el matcher de spaCy con equivalentes en inglés. Se agregaron filtros de negación bilingües.

### 8.4 Nuevas reglas para amenazas 2026

**Hallazgo**: Ataques de MFA push fatigue, device code phishing y OAuth consent phishing no tenían cobertura.

**Decisión**: Se implementaron 3 nuevas reglas (`mfa_push_coercion`, `device_code_coercion`, `unverified_app_consent_coercion`) con patrones específicos que requieren la co-ocurrencia de múltiples señales para evitar falsos positivos.

### 8.5 Ajuste del delta de seguridad

**Hallazgo**: Correos con autenticación completa (SPF+DKIM+DMARC pass) de dominios confiables no recibían suficiente descuento.

**Decisión**: Se cambió el piso del delta negativo de -0.25 a -0.35 para permitir descuentos más fuertes en correos completamente autenticados.

### 8.6 Corrección de SHAP

**Hallazgo**: La integración de SHAP fallaba silenciosamente porque `X_input` y `tfidf_vectorizer` no estaban disponibles en el scope de la llamada.

**Decisión**: Se corrigió pasando `diagnostics.get("X_input")` y la referencia correcta al vectorizador TF-IDF. Los insights SHAP ahora se incluyen como evidencia del clasificador.

---

## 9. Límites y Trabajo Futuro

### Limitaciones del corpus actual

- El corpus diagnóstico v3 (56 casos) es un corpus de desarrollo, no un holdout independiente. No debe citarse como métrica de precisión productiva.
- Las variantes del corpus corresponden frecuentemente al mismo escenario base, lo cual infla artificialmente la cobertura aparente.
- No se incluyen correos reales de usuarios (solo ejemplos sintéticos).

### Limitaciones de las reglas de contenido

- Cubren construcciones explícitas en español e inglés. Pueden omitir paráfrasis, órdenes separadas por varias oraciones, texto contenido solo en imágenes.
- Pueden señalar solicitudes reales pero inseguras de compartir secretos.
- No demuestran la identidad o intención del remitente.

### Trabajo futuro

- Reunir correos etiquetados con revisión humana y separar campañas entre desarrollo y validación.
- Construir un holdout independiente con al menos 500 casos para métricas productivas.
- Evaluar el clasificador híbrido (Transformer + XGBoost) de la rama `codex/hybrid-nlp` como alternativa de mayor capacidad.
- Implementar pruebas de usabilidad con usuarios finales del complemento Outlook.
- Agregar pruebas de navegabilidad sobre la interfaz del panel de seguridad.

---

## Reproducción de Resultados

```powershell
# Tests automatizados
python -m pytest -q

# Evaluación del corpus diagnóstico v3
python scripts/compare_classifier.py --dataset data/classifier_diagnostic_v3.jsonl --output reports/classifier_content_v3

# Evaluación sin reglas (ablación)
python scripts/compare_classifier.py --dataset data/classifier_diagnostic_v3.jsonl --output reports/classifier_content_v3_without_rules --disable-content-rules
```
