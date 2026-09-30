# Classifier evaluation

- Dataset: `data\hybrid_challenge_v1.jsonl`
- Model: `artifacts\hybrid\multilingual-candidate-a100`
- Cases: `12`
- Partial run: `false`
- Seed: `42`

## Final outcome

- Precision (phishing): `0.8750`
- Recall (phishing): `1.0000`
- F1 (phishing): `0.9333`
- PR-AUC: `0.8784`
- ROC-AUC: `0.8571`
- Brier score: `0.1538`
- Confusion matrix: `{'true_positive': 7, 'true_negative': 4, 'false_positive': 1, 'false_negative': 0}`

## Raw model

- Cases scored by model: `12`
- Precision (phishing): `0.8333`
- Recall (phishing): `0.7143`
- F1 (phishing): `0.7692`

## Warnings

- The evaluation corpus is incomplete.
- The corpus is not a verified holdout from model training.
- Some category metrics are undefined because the category does not contain both classes.
- Diagnostic corpus is not independent validation.
