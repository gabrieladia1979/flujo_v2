# Diagnóstico y mejoras — 13/09/2026

> Actualización posterior: los dos fallos identificados aquí se abordaron con reglas de contenido y pruebas contrastivas. Ver [segunda etapa e integración con backend y Outlook](classifier_content_improvements.md). Este documento conserva las mediciones de la primera etapa.

Se mantiene la columna **0** y el umbral **0.8** del artefacto local. No se reentrenó ni reemplazó el modelo. Los seis casos originales dan 6/6 con 0 y 1/6 con 1. Esto contradice la ejecución histórica; sin reconstruir aquel entorno y artefacto no se puede atribuir la diferencia a una causa concreta.

## Comparación ampliada

Se conservaron los seis casos existentes y se agregaron 18 ejemplos sintéticos de diagnóstico: phishing fiscal y bancario, robo de credenciales, premios, envíos, facturas, malware, newsletters, recuperación de contraseña y comunicaciones legítimas. Las etiquetas representan el escenario sintético diseñado, no una verificación de correos reales.

| Configuración | Aciertos | Falsos positivos | Falsos negativos |
|---|---:|---:|---:|
| Antes, índice 0 | 21/24 | 1 | 2 |
| Después, índice 0 | 22/24 | 0 | 2 |
| Después, índice 1 | 7/24 | 10 | 7 |

Los reportes [antes](classifier_before.md) y [después](classifier_after.md) muestran cada caso. Sus JSON incluyen scores crudos y finales, reglas aplicadas, versiones del entorno y hashes del corpus y modelo. Los casos resueltos por reglas críticas no sirven para distinguir columnas, pues omiten el modelo.

## Cambios

- BCL alto deja de forzar por sí solo un veredicto de phishing comprobado. Conserva el ajuste leve por correo masivo. Esto corrige el falso positivo `challenge-001`: 1.0000 → 0.0643.
- Las URLs de enlaces HTML y destinos de formularios llegan a las features del modelo; se decodifican entidades HTML. Las imágenes de seguimiento no se agregan como enlaces navegables.
- Se elimina únicamente el prefijo literal `www.` al extraer un dominio: `lstrip('www.')` también borraba letras iniciales válidas.
- La caché distingue el remitente y el resto del payload mediante JSON estructurado. La inferencia no modifica las security_features recibidas.
- Los JSONL se conservan con LF para reproducir los checksums del manifiesto también en Windows. El corpus original solo cambió sus saltos de línea locales; su checksum vuelve a coincidir sin alterar ejemplos ni manifiesto.

Las correcciones de HTML, dominios y caché tienen pruebas de regresión específicas. No se les atribuye una mejora de precisión que este corpus no demuestre.

## Fallos pendientes

1. `challenge-014`: estafa de cambio de cuenta bancaria sin URL, score 0.0154. El mensaje exige transferir a una cuenta nueva y evita que se contacte al proveedor. El clasificador no detecta este escenario sintético.
2. `challenge-015`: solicitud de contraseña y código SMS respondiendo el correo, score 0.0129. El modelo falla pese al pedido explícito de secretos, sin enlace.

Estos fallos requieren ampliar ejemplos contrastivos: solicitudes maliciosas frente a advertencias de seguridad, citas educativas y cambios bancarios legítimos. No se bajó el umbral ni se añadieron reglas de palabras aisladas para forzar aciertos en los ejemplos usados durante el desarrollo.

Este corpus es pequeño, sintético, incompleto y no constituye un holdout verificado. Los 22/24 no representan precisión productiva. Antes de ajustar o reentrenar deben separarse los datos de desarrollo de una validación independiente. El runtime además emite una advertencia de compatibilidad al cargar el pickle XGBoost; se registra el entorno en los JSON para facilitar su reproducción.

## Reproducción

Validación realizada: **77 pruebas pasaron**, incluyendo regresiones nuevas, auditoría, métricas, integración del analizador, reglas de seguridad, falsos positivos y los ocho tests del modelo real. Para aislar la clasificación se forzó el fallback del SLM mediante una ruta GGUF inexistente solo dentro del proceso de tests; no se evaluó la generación del modelo de lenguaje. La evaluación original de seis casos también terminó correctamente y `git diff --check` no detectó errores de whitespace.

Desde la raíz del repositorio:

```powershell
python scripts/compare_classifier.py --dataset data/classifier_diagnostic_v2.jsonl --output reports/classifier_after
python scripts/evaluate_classifier.py --dataset data/classifier_eval_v1.jsonl --output reports/classifier_local_v1
```

Suite de clasificación con el SLM aislado:

```powershell
@'
import pytest
from unittest.mock import patch
from services import slm_client
with patch.object(slm_client, 'MODEL_PATH', '__classifier_tests_no_slm__.gguf'):
    raise SystemExit(pytest.main(['test_classifier_regressions.py', 'test_classifier_evaluation_tools.py', 'test_analyzer_slm_integration.py', 'test_security_rules.py', 'test_false_positives.py', 'test_xgboost_analyzer.py', '-q']))
'@ | python
```

La comparación usa ambas columnas solo dentro del proceso de evaluación y restaura el índice productivo incluso si la evaluación falla. El reporte anterior es una captura previa a las correcciones; no se regenera con el código nuevo.
