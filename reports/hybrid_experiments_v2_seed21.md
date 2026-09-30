# Experimento NLP híbrido

Filas utilizables: 11054. Grupos: 8573.

| Modelo | Umbral (validación) | F1 test | FP test | FN test |
|---|---:|---:|---:|---:|
| tfidf_xgboost | 0.5475 | 0.9656 | 21 | 41 |
| frozen_embeddings_xgboost | 0.7527 | 0.9061 | 9 | 149 |
| finetuned_embeddings_xgboost | 0.8982 | 0.9651 | 9 | 53 |

Ajuste neuronal: 610 actualizaciones; 7097856 parámetros entrenables.

Se preservan el modelo original y el endpoint productivo. No se promueve automáticamente el candidato.

- Campaign IDs and training provenance are unavailable. Grouping reduces but does not prove absence of leakage.
- Existing legacy pickle may have seen these records; its metrics are not independent holdout performance.
- Scores are uncalibrated XGBoost outputs. Threshold selected only on validation.
- This run is an experiment, not evidence of readiness for production.
