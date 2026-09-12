# Auditoría del clasificador NLP y propuesta de corrección

## Conclusión ejecutiva

El servidor actual utiliza la primera columna de `predict_proba`, es decir, `predict_proba(X)[0][0]`, como probabilidad de phishing. La ejecución con el modelo real produjo resultados fuertemente compatibles con una inversión de columnas: los correos legítimos obtuvieron puntajes altos y los casos de phishing obtuvieron puntajes bajos.

La evidencia disponible sugiere que la probabilidad de phishing podría estar en la columna de índice `1`. Sin embargo, el artefacto no contiene el dataset, la codificación de etiquetas ni otros metadatos de entrenamiento que permitan demostrarlo de forma independiente. Por eso, cambiar el índice debe tratarse como una **corrección propuesta, mínima, reversible y sujeta a verificación controlada**, no como una conclusión ya probada.

## Ruta rápida de revisión

1. Revisar los hechos de auditoría y los resultados con el índice productivo `0`.
2. Confirmar que el cambio propuesto modifica únicamente el índice de probabilidad, no el modelo ni el umbral.
3. Ejecutar nuevamente la auditoría, la evaluación de seis casos y las ocho pruebas reales.
4. Comparar los resultados antes y después, conservar rollback y registrar la falta de procedencia del entrenamiento.

## Estado implementado

La primera etapa de evaluación incorporó:

- Un `.venv` aislado para ejecutar el stack real de Machine Learning.
- `scripts/audit_classifier.py`, que inspecciona clases, índice configurado, umbral, dimensiones, componentes y procedencia del artefacto.
- `data/classifier_eval.schema.json` y `scripts/classifier_corpus.py`, que definen y validan el contrato del corpus.
- `data/classifier_eval_v1.jsonl`, con seis casos derivados de fixtures existentes.
- `data/classifier_eval_v1.manifest.json`, que declara el corpus como `incomplete` y el holdout como `unverified`.
- `scripts/evaluate_classifier.py`, que separa el score crudo del modelo del resultado final luego de aplicar reglas de seguridad.
- Reportes JSON, Markdown y CSV bajo `reports/`.
- Pruebas para auditoría, corpus, métricas, determinismo, reglas críticas y compatibilidad de la API pública.

No se reentrenó ni reemplazó el modelo. El umbral y el contrato HTTP permanecen sin cambios.

## Entorno local verificado

| Componente | Versión o ubicación |
|---|---|
| Python | 3.12.14 |
| scikit-learn | 1.9.0 |
| XGBoost | 3.4.1 |
| SpaCy | 3.8.16 |
| `es_core_news_sm` | 3.8.0 |
| OpenMP | Runtime local bajo `.venv/lib/libomp.dylib` |

Al activar el entorno, `.venv/bin/activate` agrega `.venv/lib` a `DYLD_LIBRARY_PATH`. Esto permite que XGBoost encuentre el runtime OpenMP local sin depender de una instalación global de Homebrew.

## Hechos de la auditoría

| Dato | Resultado |
|---|---|
| Clases expuestas por el modelo | `[0, 1]` |
| Clase configurada como phishing | `0` |
| Índice productivo configurado | `0` |
| Acceso actual | `predict_proba(X)[0][0]` |
| Umbral | `0.8` |
| Features producidas | `6022` |
| Features esperadas | `6022` |
| Coincidencia dimensional | Sí |
| Procedencia de entrenamiento | No disponible |

La coincidencia de dimensiones demuestra que el vector construido por el servidor es compatible con la entrada esperada por el modelo. No demuestra qué significado semántico tienen las etiquetas numéricas `0` y `1`.

## Qué significa el índice de probabilidad productivo

`predict_proba` devuelve una probabilidad por cada clase, respetando el orden de `classes_`. Si el modelo informa `classes_ = [0, 1]`, el resultado tiene dos columnas:

- Índice `0`: primera columna, asociada a la clase `0`.
- Índice `1`: segunda columna, asociada a la clase `1`.

El servidor toma una de esas columnas como `risk_score`. Luego compara ese valor con el umbral `0.8` para decidir el veredicto.

Ejemplo numérico:

```text
classes_                  = [0, 1]
predict_proba(X)[0]       = [0.04, 0.96]
score leído con índice 0  = 0.04  -> legítimo, porque 0.04 < 0.8
score leído con índice 1  = 0.96  -> phishing, porque 0.96 >= 0.8
```

El ejemplo explica el mecanismo. No demuestra por sí solo que la clase `1` sea phishing; esa semántica debe recuperarse del entrenamiento o confirmarse mediante evidencia controlada suficiente.

## Evidencia real con el índice productivo 0

### Evaluación de seis casos

| Métrica | Resultado |
|---|---:|
| Verdaderos positivos | 0 |
| Verdaderos negativos | 1 |
| Falsos positivos | 3 |
| Falsos negativos | 2 |
| Precision de phishing | 0.0 |
| Recall de phishing | 0.0 |
| F1 de phishing | 0.0 |
| Tasa de falsos positivos | 0.75 |
| Tasa de falsos negativos | 1.0 |

### Pruebas completas del analizador

Con las dependencias reales se ejecutaron las ocho pruebas de `test_xgboost_analyzer.py`:

- 4 pasaron.
- 4 fallaron.
- Los correos legítimos, técnicos e internos obtuvieron puntajes altos.
- El caso de phishing obtuvo un puntaje bajo.

Las 21 pruebas focalizadas de auditoría, evaluación e integración sí pasaron. Esto confirma que las herramientas funcionan según su contrato, pero no corrige el comportamiento del modelo en producción.

## Interpretación responsable

Los seis casos detectan una regresión clara y justifican investigar la correspondencia entre etiquetas y columnas. **No son una medición de calidad productiva** porque:

- El corpus contiene sólo dos casos de phishing y cuatro legítimos.
- Está marcado como incompleto.
- No puede demostrarse que sus ejemplos hayan quedado fuera del entrenamiento original.
- No representa la diversidad de campañas, idiomas, sectores ni correos legítimos reales.

No deben publicarse precision, recall o F1 de estos seis casos como rendimiento general del producto.

## Corrección propuesta

Realizar una prueba controlada cambiando únicamente el índice compartido de probabilidad de `0` a `1`.

Condiciones:

1. Mantener el mismo archivo `model/phisharg_xgboost.pkl`.
2. Mantener el umbral `0.8`.
3. Mantener la API HTTP sin cambios.
4. Conservar los reportes actuales como línea base del índice `0`.
5. Cambiar el índice centralizado a `1` y ajustar solamente las expectativas de tests que representan esa convención.
6. Ejecutar nuevamente auditoría, evaluación y pruebas completas.
7. Comparar caso por caso y conservar una reversión inmediata al índice `0`.
8. Recuperar posteriormente el dataset, el código o los metadatos de entrenamiento para demostrar formalmente la semántica de las etiquetas.

Esta propuesta **no es reentrenamiento**, **no reemplaza el modelo** y **no cambia el umbral**. Es una corrección mínima de la columna que el servidor interpreta como probabilidad de phishing.

## Comandos de reproducción

Desde la raíz de `flujo_v2`:

```bash
source .venv/bin/activate
```

Verificar el entorno y el runtime OpenMP local:

```bash
python -c "import sys, sklearn, xgboost, spacy; nlp = spacy.load('es_core_news_sm'); print(sys.version.split()[0], sklearn.__version__, xgboost.__version__, spacy.__version__, nlp.meta['version'])"
```

Ejecutar la auditoría:

```bash
python scripts/audit_classifier.py \
  --model model/phisharg_xgboost.pkl \
  --output reports/classifier_audit
```

Ejecutar la evaluación:

```bash
python scripts/evaluate_classifier.py \
  --dataset data/classifier_eval_v1.jsonl \
  --model model/phisharg_xgboost.pkl \
  --output reports/classifier_evaluation
```

Ejecutar las pruebas completas del analizador:

```bash
python test_xgboost_analyzer.py
```

Ejecutar las pruebas focalizadas:

```bash
python -m unittest -v \
  test_classifier_evaluation_tools.py \
  test_analyzer_slm_integration.py
```

## Prompt para delegar la corrección a una IA

```text
En flujo_v2, verificá de forma controlada la hipótesis de inversión de probabilidad. Producción usa predict_proba(X)[0][0], pero la auditoría y las pruebas reales sugieren que phishing corresponde al índice 1. Hacé un cambio mínimo y reversible para usar el índice 1 mediante el contrato centralizado. No reentrenes ni reemplaces el modelo, no cambies el umbral 0.8 y no cambies la API. Conservá los reportes del índice 0, regenerá auditoría y evaluación, ejecutá test_xgboost_analyzer.py y las pruebas focalizadas, compará los resultados caso por caso y documentá claramente que la procedencia del entrenamiento sigue ausente. Preservá cambios ajenos y no hagas commit sin autorización.
```

## Checklist de verificación

- [ ] Los reportes del índice `0` quedaron preservados como línea base.
- [ ] El cambio modifica sólo la selección de columna y sus tests asociados.
- [ ] El modelo `.pkl` conserva el mismo checksum.
- [ ] El umbral continúa en `0.8`.
- [ ] La API pública conserva exactamente sus campos actuales.
- [ ] La auditoría informa índice `1` después del cambio propuesto.
- [ ] La evaluación genera JSON, Markdown y CSV sin errores.
- [ ] Las 21 pruebas focalizadas pasan.
- [ ] Las ocho pruebas completas del analizador se ejecutan y sus resultados quedan registrados.
- [ ] Se comparan los seis casos antes y después sin presentar ese corpus como evidencia productiva.
- [ ] Existe un procedimiento inmediato para volver al índice `0`.
- [ ] La falta de procedencia del entrenamiento continúa documentada.

## Fuera de alcance

- Reentrenar XGBoost u otro modelo.
- Reemplazar `phisharg_xgboost.pkl`.
- Cambiar el umbral `0.8`.
- Ajustar hiperparámetros o calibración.
- Ampliar o fabricar artificialmente el corpus.
- Declarar métricas de calidad productiva.
- Modificar el contrato HTTP o la interfaz del Add-in.
- Integrar o modificar el SLM.
- Presentar la inversión como probada antes de recuperar evidencia de entrenamiento o completar una validación controlada.
