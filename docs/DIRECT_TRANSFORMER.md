# Clasificador Transformer directo

Rama experimental: `codex/direct-transformer`, creada desde `cbdbdf34d883bcccbf0d0c276516e6ecc04fabbb` de `codex/hybrid-nlp`. No cambia el endpoint `/api/v1/analyze` ni reemplaza el clasificador en uso.

## Pregunta del experimento

El mejor híbrido curado V3 ajusta MiniLM con etiquetas de correos y entrena después XGBoost con sus embeddings y 16 variables técnicas. Este ensayo pregunta si un Transformer con una cabeza binaria propia puede clasificar directamente los mismos correos. Se separan dos comparaciones:

1. **Control MiniLM directo:** reutiliza el encoder del híbrido curado V3 y ajusta solo una cabeza lineal con el conjunto de entrenamiento. Conserva el mismo encoder, pero elimina XGBoost **y las 16 variables técnicas**; por ello mide la diferencia del enfoque directo completo, no el efecto aislado de cambiar la cabeza. No constituye un nuevo fine-tuning completo.
2. **Modelo principal mDeBERTa-v3-base:** parte del checkpoint multilingüe preentrenado y ajusta el Transformer entero junto con su cabeza de clasificación. No utiliza XGBoost, las 16 variables técnicas ni las reglas del servidor.

MiniLM se publicó principalmente como modelo de embeddings y similitud ([ficha oficial](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2)). mDeBERTa-v3-base es una base multilingüe apta para ajuste supervisado; su [ficha oficial](https://huggingface.co/microsoft/mdeberta-v3-base) informa una ventaja sobre XLM-R base en XNLI español, una tarea distinta de phishing. Se eligió por cobertura de español e inglés y por ser una alternativa prometedora para probar clasificación directa; esa referencia no predice cuál ganará aquí. [XLM-R base](https://huggingface.co/FacebookAI/xlm-roberta-base) queda como alternativa posterior si la capacidad de GPU o los resultados lo justifican.

## Comparación válida

- Corpus curado V3: SHA-256 `8aa55e98a0bfd199c6d1416dfa935e0dcc4ed13e5b3e0f7604c97e6527f63f46`; 11.073 filas útiles y 8.594 grupos después de la auditoría del entrenamiento híbrido.
- Usar **exactamente** `artifacts/hybrid/corpus-v3/training.csv` y `artifacts/hybrid/multilingual-candidate-v3-curated/splits.json` de la corrida evaluada. Ambos son archivos locales ignorados por Git; no subirlos al repositorio. El `splits.json` de `corpus-v3` es anterior a la exclusión de filas conflictivas y contiene IDs adicionales. Los scripts conservan los IDs exactos de la corrida evaluada, verifican cobertura completa y rechazan grupos que crucen particiones. El agrupador actual produce 60 claves distintas de las guardadas para las mismas filas, pero no crea cruces entre train, validación y test; regenerar la partición cambiaría la comparación pareada.
- Entrenamiento: 7.792 correos; validación: 1.619; test: 1.662. Se selecciona el mejor checkpoint por pérdida en validación y el umbral por una restricción de falsos positivos de 2 % en validación. El test se usa después de fijar ambas decisiones.
- Referencia del híbrido curado V3 sobre ese test: F1 phishing `0,969832`, 9 falsos positivos y 45 falsos negativos, según `reports/hybrid_multilingual_v3_curated.json` del repositorio original. El TF-IDF + XGBoost reentrenado en la misma corrida obtuvo F1 `0,964326`, 16 FP y 48 FN.
- Comparar además precision, recall, AUC, errores por fuente/idioma, tiempo de inferencia y memoria. El directo usa asunto y cuerpo; el híbrido añade 16 variables técnicas. Cualquier diferencia combina el efecto del modelo y el de esa información adicional. Una diferencia en un solo split no demuestra superioridad general; se necesita repetición y luego un conjunto externo.

## Control MiniLM en CPU

Desde este checkout, con el entorno del repositorio original:

```powershell
& 'C:\Users\gabri\Documents\GitHub\flujo_v2\.venv-hybrid\Scripts\python.exe' scripts/train_direct_transformer.py `
  --dataset 'C:\Users\gabri\Documents\GitHub\flujo_v2\artifacts\hybrid\corpus-v3\training.csv' `
  --previous-splits 'C:\Users\gabri\Documents\GitHub\flujo_v2\artifacts\hybrid\multilingual-candidate-v3-curated\splits.json' `
  --expected-dataset-sha256 8aa55e98a0bfd199c6d1416dfa935e0dcc4ed13e5b3e0f7604c97e6527f63f46 `
  --base-model 'C:\Users\gabri\Documents\GitHub\flujo_v2\artifacts\hybrid\multilingual-candidate-v3-curated\encoder' `
  --output artifacts/direct-transformer/minilm-head-v3 `
  --report reports/direct_minilm_head_v3.json `
  --trainable-layers 0 --max-tokens 384 --epochs 5 --device cpu
```

Esta máquina solo dispone de PyTorch CPU. El control local permite medir la diferencia entre cabezas sin descargar otro modelo. Las rutas son un ejemplo de esta instalación; en otro equipo deben sustituirse por las ubicaciones reales.

### Resultado del control local

La corrida completa de cinco épocas eligió el checkpoint de la época 4 mediante la pérdida de validación. Sobre las mismas 1.662 filas de test, el control directo obtuvo F1 phishing **0,962296**, precision **0,989583**, recall **0,936473**, 9 falsos positivos y 58 falsos negativos. El híbrido curado V3 obtuvo F1 **0,969832**, 9 falsos positivos y 45 falsos negativos. El directo acertó una fila que el híbrido erró; el híbrido acertó 14 que el directo erró. La diferencia pareada de F1 es **−0,007536**; el intervalo descriptivo de remuestreo por grupo fue **[−0,012798; −0,003489]** (1.000 repeticiones). Los resultados completos están en `reports/direct_minilm_head_v3.json` y `reports/direct_minilm_vs_hybrid_v3.json`.

En este control, el híbrido rinde mejor. La diferencia combina la cabeza de clasificación y la ausencia de las variables técnicas en el directo; no identifica cuál de los dos cambios explica la pérdida. El test es histórico y ya participó en el desarrollo de esta línea de modelos, así que el intervalo no estima el rendimiento en nuevas campañas. El ensayo principal con mDeBERTa todavía requiere una GPU; no se le atribuyen las métricas de MiniLM.

## Fine-tuning completo de mDeBERTa en GPU

Crear un entorno aislado con `pip install -r requirements-direct-transformer.txt`. En Colab u otro equipo con CUDA, copiar localmente `training.csv` a `artifacts/hybrid/corpus-v3/` y el `splits.json` del **artefacto curado V3** a `artifacts/hybrid/multilingual-candidate-v3-curated/` de esta rama. El CSV contiene correos: revisar su procedencia y autorización antes de cargarlo a un servicio externo. No incluirlo en un commit.

```bash
python scripts/train_direct_mdeberta.py \
  --dataset artifacts/hybrid/corpus-v3/training.csv \
  --previous-splits artifacts/hybrid/multilingual-candidate-v3-curated/splits.json \
  --expected-dataset-sha256 8aa55e98a0bfd199c6d1416dfa935e0dcc4ed13e5b3e0f7604c97e6527f63f46 \
  --output artifacts/direct-transformer/mdeberta-v3 \
  --report reports/direct_mdeberta_v3.json \
  --epochs 4 --batch-size 8 --gradient-accumulation 4 \
  --max-tokens 384 --device cuda
```

El modelo de base es `microsoft/mdeberta-v3-base`. El script informa la revisión resuelta, conserva el mejor checkpoint por pérdida de validación y guarda predicciones de test identificadas por fila para análisis pareado. En una GPU con poca memoria, bajar `--batch-size` a 4 y subir `--gradient-accumulation` a 8. Repetir con otras semillas y una muestra externa antes de presentar el resultado como una mejora general.

Después de cualquiera de las corridas, `scripts/compare_direct_hybrid.py` compara las mismas filas con el reporte y `splits.json` del híbrido curado V3. Informa F1, falsos positivos, falsos negativos, desacuerdos pareados y un intervalo descriptivo obtenido remuestreando grupos. Por ejemplo:

```bash
python scripts/compare_direct_hybrid.py \
  --direct-report reports/direct_mdeberta_v3.json \
  --hybrid-report ../flujo_v2/reports/hybrid_multilingual_v3_curated.json \
  --hybrid-splits ../flujo_v2/artifacts/hybrid/multilingual-candidate-v3-curated/splits.json \
  --output reports/direct_mdeberta_vs_hybrid_v3.json
```

El resultado de este ensayo debe permanecer separado de las métricas de V5 y del producto desplegado hasta que se pruebe su carga, latencia, contrato e integración con el Add-in.
