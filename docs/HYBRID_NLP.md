# NLP híbrido experimental

Rama: `codex/hybrid-nlp`. El modelo `model/phisharg_xgboost.pkl`, la convención productiva de columna 0 y `POST /api/v1/analyze` se conservan. Los candidatos nuevos se guardan exclusivamente en `artifacts/hybrid/`, excluido de Git. No se despliega ni se promueve automáticamente ningún candidato.

## Qué se entrena

1. Se auditan y agrupan los correos antes de ajustar modelos. Se excluyen duplicados, grupos contradictorios y entradas que exceden los límites del backend.
2. Se entrena una referencia nueva de TF-IDF + XGBoost. Esta referencia usa el mismo texto y las mismas 16 features técnicas que los candidatos neuronales; no es el pickle histórico ni reproduce exactamente su pipeline spaCy.
3. Se generan embeddings multilingües congelados y se entrena otro XGBoost.
4. Se ajustan las dos últimas capas del Transformer con entropía cruzada y una cabeza lineal auxiliar usando solamente entrenamiento. Esa cabeza se descarta: se vuelven a generar embeddings y se entrena el XGBoost final.
5. El checkpoint neuronal se elige con pérdida de validación. Cada umbral se elige exclusivamente en validación, maximizando recall bajo una tasa de falsos positivos máxima del 2%. El test se reserva para la comparación final.

Esto **sí actualiza pesos neuronales**. Los hashes antes/después y el número de actualizaciones quedan en el manifiesto. Es ajuste parcial de un modelo preentrenado, no entrenamiento desde cero. El primer experimento usa una época en CPU; el código permite más épocas o GPU en un entorno apropiado. No se afirma que el híbrido sea superior antes de medirlo.

Base: [paraphrase-multilingual-MiniLM-L12-v2](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2), 384 dimensiones. [Sentence Transformers](https://www.sbert.net/docs/sentence_transformer/training_overview.html) permite adaptar estas representaciones al dominio. El runtime utiliza un presupuesto de 128 tokens, conservando inicio y final; la misma función tokeniza para entrenamiento e inferencia. Correos extensos pueden perder contexto intermedio, limitación registrada del experimento.

## Fuentes y ampliación

`Clasificador_PFI/DataSet` contiene 164.972 filas sumadas entre siete CSV, **no necesariamente correos únicos**; `phishing_email.csv` es un consolidado que no se mezcla automáticamente con los originales. El inventario y los hashes están en `reports/hybrid_sources_audit.json`.

La primera mezcla conserva 7.095 filas de `SpaPhish_Master_Final_v5.csv` y agrega hasta 1.000 filas por fuente seleccionada: Nazario, Nigerian_Fraud, Enron y SpamAssasin. En Enron/SpamAssasin solo se incorpora la etiqueta local de ham. Spam genérico no se convierte automáticamente en phishing. Las etiquetas se heredan de cada fuente, sin afirmar revisión humana individual. La política explícita está en `data/hybrid_sources.json`; los CSV originales se leen sin modificarlos.

El corpus de [SpamAssassin](https://spamassassin.apache.org/old/publiccorpus/readme.html) distingue spam/ham. La equivalencia de spam con phishing no está justificada por esa documentación. CEAS, Ling y el consolidado quedan inventariados para revisión adicional.

El contexto aportado sobre `Phishing_Legitimate_full.csv` describe otro conjunto: 10.000 **páginas web**, 48 features y recolección en 2015/2017. No contiene cuerpos de correos para entrenar el encoder. El importador rechaza fuentes sin cuerpo/texto, en vez de convertir columnas de páginas en ejemplos de NLP. Ese conjunto podría investigarse posteriormente como un detector separado de páginas/enlaces, con extracción equivalente en inferencia.

La mezcla genera 11.095 registros; tras los controles iniciales quedan 11.054. Los grupos normalizan cuerpos, números y URLs, sin depender del asunto. Esto reduce filtraciones por variantes, pero no garantiza independencia por campaña/remitente: los corpus históricos carecen de esa trazabilidad completa. Los reportes desglosan por fuente y por idioma sugerido por la fuente, no por idioma detectado individualmente.

## Preparar y entrenar

Desde la raíz de `flujo_v2`, usando PowerShell:

```powershell
python -m venv --system-site-packages .venv-hybrid
.venv-hybrid/Scripts/python.exe -m pip install -r requirements-hybrid.txt
python scripts/build_hybrid_corpus.py --base ../Clasificador_PFI/SpaPhish_Master_Final_v5.csv --sources-dir ../Clasificador_PFI/DataSet --output artifacts/hybrid/corpus/multilingual-v1.csv --report reports/hybrid_sources_audit.json --max-per-source 1000
.venv-hybrid/Scripts/python.exe scripts/train_hybrid.py --dataset artifacts/hybrid/corpus/multilingual-v1.csv --phishing-label 1 --output artifacts/hybrid/multilingual-candidate-v1 --report reports/hybrid_multilingual_v1 --epochs 1 --batch-size 16 --max-tokens 128 --trainable-layers 2
```

El entorno experimental hereda las librerías instaladas y agrega Sentence Transformers localmente. Los paquetes originales no se reemplazan. Las versiones efectivas se registran en el informe. Para un equipo nuevo, instalar también las dependencias del backend si se necesita probar la API.

Para evitar sobrescrituras, usar **un nombre nuevo de corpus y salida en cada corrida**. `--max-per-source 0` importa todas las filas elegibles de la política actual; no habilita fuentes pendientes de revisión. `--base-model artifacts/hybrid/base-encoder` reutiliza una descarga local. La carga del candidato en el backend es exclusivamente local y no descarga pesos.

La etiqueta `1` de este CSV representa phishing según los scripts de `Clasificador_PFI`; se convierte explícitamente en el manifiesto del candidato. Esto **no cambia la columna 0 del modelo productivo anterior**: son artefactos distintos con contratos distintos.

## Servir y verificar

```powershell
$env:PHISHARG_HYBRID_MODEL_DIR = 'artifacts/hybrid/multilingual-candidate-v1'
.venv-hybrid/Scripts/python.exe -m uvicorn main:app --host 127.0.0.1 --port 8001
```

- `POST /api/v1/analyze`: flujo existente.
- `POST /api/v1/analyze/hybrid`: candidato experimental con la misma autenticación `X-API-Key` y payload. Si no hay configuración o el artefacto no es válido, responde 503.

El loader verifica hashes, orden de features, dimensiones, clases y umbral. XGBoost se serializa en JSON nativo; el encoder se guarda por separado. Las features se extraen con la misma función en entrenamiento y servicio. Se ignoran anotaciones psicológicas/precomputadas del CSV que no podrían reproducirse con seguridad en Outlook.

La ruta experimental conserva ajustes de cabeceras y reglas de contenido. `raw_model_score` es el score anterior a reglas; `risk_score` es el resultado final. Los scores XGBoost no se han calibrado en este experimento y las reglas pueden elevarlos. La explicación experimental es determinista y estructurada, sin invocar Qwen; el explicador y comportamiento de la ruta original se conservan. No se presentan supuestas palabras causales del embedding.

```powershell
.venv-hybrid/Scripts/python.exe -m pytest test_hybrid_pipeline.py -q
$env:HYBRID_TEST_ARTIFACT = 'artifacts/hybrid/multilingual-candidate-v1'
$env:HYBRID_TEST_REPORT = 'reports/hybrid_multilingual_v1.json'
.venv-hybrid/Scripts/python.exe -m pytest test_hybrid_artifact.py -q
```

El segundo bloque requiere entrenamiento completado: comprueba pesos modificados, tokenización, reproducción de scores reservados y respuesta HTTP con el modelo real.

## Ensayo opcional de LIME para el híbrido

`POST /api/v1/analyze/hybrid/lime` es una ruta experimental separada. Requiere `X-API-Key`, `PHISHARG_HYBRID_MODEL_DIR`, instalar `requirements-hybrid.txt` y establecer `ENABLE_HYBRID_LIME=true`. Está desactivada por defecto y no altera `/api/v1/analyze` ni `/api/v1/analyze/hybrid`. Acepta `num_samples` entre 64 y 256 y un cuerpo de hasta 4.000 caracteres.

LIME elimina palabras del cuerpo y consulta el puntaje **crudo** de MiniLM + XGBoost. Mantiene fijo el asunto y las variables de cabeceras, pero recalcula las variables técnicas derivadas del cuerpo. La respuesta incluye probabilidad del modelo, pesos de hasta ocho palabras, tiempo y `local_fidelity_r2`. Los pesos describen la aproximación local; no son atribuciones causales ni explican ajustes de reglas que pueden cambiar el veredicto final. Con fidelidad menor a 0,7 la respuesta indica expresamente que no se debe interpretar la lista como explicación confiable. No usar esta ruta automáticamente en el Add-in antes de medir latencia y estabilidad en el entorno real.

La respuesta también informa `original_surrogate_probability`, `original_prediction_error` y `max_original_prediction_error`. `reliable_local_fit` exige R² interno y nuevo ≥ 0,7 y error sobre el correo original ≤ 0,01 (un punto porcentual). El tercer umbral es un criterio técnico conservador, no una tolerancia validada con usuarios. Se añadió porque un ajuste con buen R² puede representar mal el puntaje del correo original. El indicador tampoco acredita estabilidad de palabras.

Desde el ensayo del 01/10/2026, `word_weights` queda vacío si no se cumplen esos controles. `diagnostic_word_weights` conserva los pesos para investigar una explicación rechazada; no se debe usar como lista de razones para el usuario. La probabilidad real continúa disponible y el indicador positivo solo acredita los controles de fidelidad, no utilidad o estabilidad.

Prueba local con los pesos v3-curated disponibles el 30/09/2026: las probabilidades LIME coincidieron con `raw_score` en tres correos. Con 64/128/256 muestras y modelo ya cargado, el cálculo duró aproximadamente 0,24–1,43 s en esta PC. La fidelidad local fue baja en un correo legítimo (R² 0,29–0,37) y en una solicitud de credenciales (0,41–0,46); en un correo con URL fue 0,75–0,79, aunque algunas palabras recibieron pesos contraintuitivos al perturbar la URL. Es una prueba técnica, no evidencia suficiente para mostrar estas palabras como razones al usuario final.

**Seguimiento del ensayo:** [reporte reproducible](../reports/hybrid_lime_diagnostic_v1.json), generado con `python -m scripts.evaluate_hybrid_lime` sobre 20 correos del test guardado, muestreados con semilla 42 (cinco por etiqueta e idioma de fuente, cuerpo de 120–1.000 caracteres). Con 128 perturbaciones para ajustar LIME, solo 2/20 alcanzaron R² interno ≥ 0,7; la mediana fue 0,326. El endpoint ahora evalúa 32 perturbaciones nuevas: su R² mediano fue 0,132 y **solo 1/20** superó 0,7 en ambas comprobaciones; ese caso era legítimo. En puntajes casi constantes, R² puede ser bajo aunque el error absoluto sea pequeño; por eso el reporte conserva ambas medidas. La mediana de tiempo fue 2,57 s con el modelo cargado. Probamos variar las muestras, permitir más palabras, tratar URLs como una unidad, fijar las variables técnicas y suavizar probabilidades extremas. Las mejoras parciales del ajuste interno no demostraron una explicación generalizable; no se adoptó una transformación de la probabilidad que pudiera confundirse con el puntaje real. `reliable_local_fit` exige ahora ambas comprobaciones y sigue siendo un indicador técnico, no una validación de utilidad para usuarios.

### Ensayo con pocas palabras eliminadas

`python -m scripts.probe_lime_locality` prueba un vecindario distinto usando `LimeBase`: 128 muestras con eliminación de una a tres palabras y 32 combinaciones nuevas de dos o tres palabras. Mantiene asunto y cabeceras, recalcula señales del cuerpo y conserva la probabilidad original del híbrido. Compara 8/32/64 palabras y regularización Ridge 1/0,01; las primeras eliminaciones individuales recorren hasta los primeros 64 tokens distintos. Es un diagnóstico independiente del endpoint.

Con semilla 42 y ocho palabras/Ridge 0,01, **4/20** correos superaron R² ≥ 0,7 tanto en ajuste como en validación: dos legítimos y dos phishing. R² mediano de validación fue 0,255. Los reportes conservan MAE y omiten R² cuando la varianza de probabilidades es ≤ 1e-10. Cambiar el vecindario cambia la pregunta que responde la aproximación; estos resultados no constituyen una comparación directa con el diagnóstico anterior. Los mismos veinte casos se reutilizaron para elegir variantes y no son una evaluación final independiente.

Al repetir los cuatro casos inicialmente favorables, pasaron **1/4** con semilla 7 y **2/4** con semilla 21 para esa misma configuración. La ganancia depende de las perturbaciones; todavía no justifica incorporar la variante al endpoint o mostrar sus palabras al usuario. La rama AWS conserva su implementación anterior.

Evidencia: [20 casos, semilla 42](../reports/hybrid_lime_locality_probe.json), [repetición, semilla 7](../reports/hybrid_lime_locality_seed7.json), [repetición, semilla 21](../reports/hybrid_lime_locality_seed21.json). Para repetir las verificaciones: `python -m scripts.probe_lime_locality --seed 7 --ids row-856 row-1131 row-2760 row-5594 --output reports/hybrid_lime_locality_seed7.json` y el mismo comando con semilla 21 y salida `reports/hybrid_lime_locality_seed21.json`. Requiere los pesos y el CSV locales ignorados; los reportes no contienen el texto de los correos. Próxima comprobación útil: estabilidad de las palabras y sus signos, además de fidelidad, sobre una muestra nueva definida antes de ajustar parámetros.

### Estabilidad de palabras y contraste con eliminación individual

`python -m scripts.evaluate_lime_word_stability` repite los cuatro casos favorables con semillas 42, 7 y 21. Guarda índices de tokens y pesos, sin guardar el texto. Para ocho palabras/Ridge 0,01, la mediana de Jaccard entre listas fue **0,60**; las palabras compartidas conservaron signo en **71/72** comparaciones. La coincidencia de palabras bajó hasta 3 de 8 en un par de semillas del caso `row-5594` (Jaccard 0,231). Conservar signos en las palabras compartidas no equivale a conservar la explicación completa ni su orden.

También se contrastaron los signos con el cambio de probabilidad al eliminar cada palabra individualmente del texto original: coincidieron **82/87** efectos comparables. Se ignoran magnitudes inferiores a 1e-6. La eliminación individual no es verdad causal; registra otra respuesta del mismo modelo. Estos resultados corresponden a una selección favorable y no estiman la fiabilidad general. [Reporte de estabilidad](../reports/hybrid_lime_word_stability.json).

La comprobación adicional usa veinte correos distintos, seleccionados con semilla 1337, cinco por etiqueta e idioma de fuente del test guardado, cuerpo de 120–1.000 caracteres y exclusión de los veinte casos anteriores. La configuración se fijó antes de la ejecución: ocho palabras/Ridge 0,01, 128 muestras y 32 combinaciones nuevas, semillas 42/43. Comando: `python -m scripts.probe_lime_locality --fresh --output reports/hybrid_lime_locality_fresh.json`. Es una muestra nueva para esta explicación, dentro del mismo corpus y modelo; no valida usuarios ni un despliegue.

Resultado: **4/20** superaron ambos R² ≥ 0,7, tres legítimos y un phishing, todos de fuente con idioma declarado español. R² mediano de validación **0,516** y MAE mediano **0,000379**. No hubo R² indefinidos. El conteo reducido no permite concluir diferencias de fiabilidad entre idiomas. Se verificaron la exclusión de los veinte casos previos y los cuatro estratos de cinco casos. [Reporte sobre muestra nueva](../reports/hybrid_lime_locality_fresh.json). La mejora parcial no justifica cambiar el endpoint o entregar LIME al Add-in; el ensayo queda en `codex/hybrid-nlp` y la rama AWS se conserva.

### Cobertura completa y escala logarítmica

`python -m scripts.probe_lime_coverage` incluye una eliminación individual por cada palabra, sin limitarse a las primeras 64. Agrega combinaciones únicas de dos o tres palabras hasta `max(256, 1 + 3 * palabras)` muestras y reserva 32 combinaciones diferentes para validar. Mantiene la probabilidad del híbrido; compara LIME, Ridge anclado al puntaje original y suma de efectos individuales. Las dos últimas son variantes de diagnóstico, no LIME estándar. Se evalúa R² sin ponderar sobre las probabilidades de entrenamiento y validación.

También ajusta LIME sobre `logit(p)`, con recorte de probabilidades a `[1e-6, 1-1e-6]`, y transforma sus predicciones con sigmoid antes de contrastarlas con las probabilidades reales. Los pesos de esa variante explican log-odds; no deben presentarse como cambios directos de probabilidad.

Resultados sobre los veinte casos de desarrollo y los otros veinte ya inspeccionados, usando las mismas perturbaciones para todos los métodos de cada caso:

| Variante | Ambos R² ≥ 0,7, desarrollo | Ambos R² ≥ 0,7, segunda muestra | Segunda muestra, además error original ≤ 0,01 |
| --- | --- | --- | --- |
| LIME log-odds, todas las palabras | 8/20 | 9/20 | 7/20 |

La mediana de R² nuevo de esa variante fue 0,657 y 0,680, respectivamente. Los siete casos de la segunda muestra que pasaron los tres controles incluyeron cuatro phishing y tres legítimos. Es una mejora limitada que necesita todas las palabras; no se puede atribuir su fidelidad a una lista resumida de ocho. LIME con ocho palabras pasó ambos R² en 3/20 y 5/20 con la nueva cobertura; el ajuste logarítmico con ocho pasó en 3/20 y 4/20. La eliminación individual y el anclaje no resolvieron el problema general. Los dos conjuntos se han inspeccionado durante el desarrollo, por lo que no son una evaluación final independiente.

Evidencia: [cobertura inicial](../reports/hybrid_lime_coverage.json), [comparación logarítmica](../reports/hybrid_lime_coverage_logodds.json), [segunda muestra](../reports/hybrid_lime_coverage_confirm.json). Para repetir la segunda muestra: `python -m scripts.probe_lime_coverage --selection reports/hybrid_lime_locality_fresh.json --output reports/hybrid_lime_coverage_confirm.json`. El script puede reutilizar predicciones en la caché local ignorada `artifacts/hybrid/lime-coverage-cache`; verifica máscaras y huella de datos, código de inferencia, pesos, configuración y versiones. Los reportes guardados no incluyen el texto de correos ni pesos del modelo.

Se adoptó en el endpoint únicamente el control adicional del puntaje original, con prueba de regresión que reproduce R² altos y error original de 0,02. Pasaron 21 pruebas focalizadas, incluida la prueba con pesos reales. La variante logarítmica permanece en el laboratorio, pendiente de estabilidad entre semillas y evaluación en casos nuevos. AWS y el flujo habitual siguen en su estado anterior.

### Fragmentos y estabilidad de la variante completa, 01/10/2026

`python -m scripts.probe_lime_fragments` agrupa el cuerpo en hasta ocho bloques continuos de tokens separados por espacios. Conserva el texto exacto y no corta URLs dentro de un token; los bloques no son necesariamente frases gramaticales. Evalúa eliminaciones de uno a tres bloques y separa ajuste/validación en cada partición. Quitar bloques cambia mucho más texto que quitar palabras, por lo que no constituye una comparación directa con el vecindario anterior. Se usaron los veinte casos de la segunda muestra, ya inspeccionados.

La variante en probabilidades pasó los tres controles en 1/20 casos con cada semilla, siempre el mismo legítimo. La logarítmica pasó en 3/20, 2/20 y 2/20 con semillas 42, 7 y 21, respectivamente, y **ninguno** pasó las tres particiones. Pese a cosenos medianos de pesos 0,977 y 0,991, la fidelidad fue insuficiente. Estabilidad de coeficientes y fidelidad son requisitos distintos. Esta variante no se incorporó al endpoint. [Reporte de fragmentos](../reports/hybrid_lime_fragments.json).

`python -m scripts.probe_lime_full_stability` volvió a dividir las predicciones guardadas de LIME log-odds con todas las palabras. Reprodujo los R² de la semilla original antes de comparar particiones adicionales. Pasaron los tres controles en **7/20, 5/20 y 6/20**; **4/20** pasaron con las tres particiones, dos phishing y dos legítimos. En estos cuatro casos, las tres palabras de mayor magnitud coincidieron en cada comparación; coincidieron 363/375 signos comparables y el coseno mediano fue 0,997. Las particiones comparten un mismo conjunto de máscaras ya inferidas y se superponen entre semillas: no equivalen a perturbaciones nuevas generadas independientemente ni a casos nuevos. [Reporte de estabilidad completa](../reports/hybrid_lime_full_stability.json).

El script de estabilidad requiere la caché local ignorada que genera `probe_lime_coverage` y exige su huella registrada. Los reportes contienen índices y pesos, sin texto de correos. La variante completa sigue siendo experimental. Se adoptó el filtrado de `word_weights` para explicaciones rechazadas; pasaron **23 pruebas** del endpoint, pipeline y fragmentación, incluida inferencia con pesos reales. El Add-in y la rama AWS no cambiaron.

## Agregar amenazas actuales después

Incorporar nuevos correos con etiqueta revisada, procedencia, fecha, idioma y, cuando exista, campaña. Separar ejemplos reales revisados de ejemplos sintéticos y de informes que solo describen una amenaza. No etiquetar automáticamente un artículo de seguridad como correo malicioso ni tomar generación sintética como prueba independiente.

Temas a cubrir con casos maliciosos y contrapartes legítimas: consentimiento OAuth, QR que dirige a credenciales, suplantación de reuniones, solicitudes de MFA, cambios de cuenta de proveedores y falsas notificaciones fiscales. La fecha del informe debe distinguirse de la fecha del ataque; los corpus históricos actuales no prueban esa cobertura.

Al crear la siguiente mezcla, reutilizar `--previous-splits artifacts/hybrid/multilingual-candidate-v1/splits.json` en el entrenador. Conserva las particiones de los grupos ya conocidos y asigna los nuevos de manera determinista. Mantener además una evaluación temporal/campañas nueva para detectar regresiones y no ajustar una y otra vez contra el mismo test. El agrupamiento automático actual por cuerpo/plantilla no sustituye particiones humanas por campañas cuando se disponga de ellas.
