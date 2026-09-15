# Experimento NLP híbrido

Filas utilizables: 11073. Grupos: 8594.

| Modelo | Umbral (validación) | F1 test | FP test | FN test |
|---|---:|---:|---:|---:|
| tfidf_xgboost | 0.6183 | 0.9643 | 16 | 48 |
| frozen_embeddings_xgboost | 0.7505 | 0.9118 | 12 | 138 |
| finetuned_embeddings_xgboost | 0.8901 | 0.9698 | 9 | 45 |

Ajuste neuronal: 610 actualizaciones; 7097856 parámetros entrenables.

Se preservan el modelo original y el endpoint productivo. No se promueve automáticamente el candidato.

- Campaign IDs and training provenance are unavailable. Grouping reduces but does not prove absence of leakage.
- Existing legacy pickle may have seen these records; its metrics are not independent holdout performance.
- Scores are uncalibrated XGBoost outputs. Threshold selected only on validation.
- This run is an experiment, not evidence of readiness for production.
