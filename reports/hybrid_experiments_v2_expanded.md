# Experimento NLP híbrido

Filas utilizables: 28496. Grupos: 24768.

| Modelo | Umbral (validación) | F1 test | FP test | FN test |
|---|---:|---:|---:|---:|
| tfidf_xgboost | 0.5598 | 0.9565 | 22 | 57 |
| frozen_embeddings_xgboost | 0.8164 | 0.8688 | 6 | 210 |
| finetuned_embeddings_xgboost | 0.8512 | 0.9669 | 27 | 34 |

Ajuste neuronal: 1920 actualizaciones; 7097856 parámetros entrenables.

Se preservan el modelo original y el endpoint productivo. No se promueve automáticamente el candidato.

- Campaign IDs and training provenance are unavailable. Grouping reduces but does not prove absence of leakage.
- Existing legacy pickle may have seen these records; its metrics are not independent holdout performance.
- Scores are uncalibrated XGBoost outputs. Threshold selected only on validation.
- This run is an experiment, not evidence of readiness for production.
