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

## Agregar amenazas actuales después

Incorporar nuevos correos con etiqueta revisada, procedencia, fecha, idioma y, cuando exista, campaña. Separar ejemplos reales revisados de ejemplos sintéticos y de informes que solo describen una amenaza. No etiquetar automáticamente un artículo de seguridad como correo malicioso ni tomar generación sintética como prueba independiente.

Temas a cubrir con casos maliciosos y contrapartes legítimas: consentimiento OAuth, QR que dirige a credenciales, suplantación de reuniones, solicitudes de MFA, cambios de cuenta de proveedores y falsas notificaciones fiscales. La fecha del informe debe distinguirse de la fecha del ataque; los corpus históricos actuales no prueban esa cobertura.

Al crear la siguiente mezcla, reutilizar `--previous-splits artifacts/hybrid/multilingual-candidate-v1/splits.json` en el entrenador. Conserva las particiones de los grupos ya conocidos y asigna los nuevos de manera determinista. Mantener además una evaluación temporal/campañas nueva para detectar regresiones y no ajustar una y otra vez contra el mismo test. El agrupamiento automático actual por cuerpo/plantilla no sustituye particiones humanas por campañas cuando se disponga de ellas.
