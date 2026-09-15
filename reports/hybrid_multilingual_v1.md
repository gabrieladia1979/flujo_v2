# Experimento NLP híbrido

Filas utilizables: 11054. Grupos: 8573.

| Modelo | Umbral (validación) | F1 test | FP test | FN test |
|---|---:|---:|---:|---:|
| tfidf_xgboost | 0.6337 | 0.9614 | 17 | 52 |
| frozen_embeddings_xgboost | 0.7959 | 0.8812 | 7 | 188 |
| finetuned_embeddings_xgboost | 0.9231 | 0.9041 | 20 | 143 |

Ajuste neuronal: 486 actualizaciones; 3548928 parámetros entrenables.

Se preservan el modelo original y el endpoint productivo. No se promueve automáticamente el candidato.

- Campaign IDs and training provenance are unavailable. Grouping reduces but does not prove absence of leakage.
- Existing legacy pickle may have seen these records; its metrics are not independent holdout performance.
- Scores are uncalibrated XGBoost outputs. Threshold selected only on validation.
- This run is an experiment, not evidence of readiness for production.
