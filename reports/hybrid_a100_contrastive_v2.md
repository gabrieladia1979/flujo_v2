# Classifier evaluation

- Dataset: `data\hybrid_contrastive_v2.jsonl`
- Model: `artifacts\hybrid\multilingual-candidate-a100`
- Cases: `16`
- Partial run: `false`
- Seed: `42`

## Final outcome

- Precision (phishing): `0.6000`
- Recall (phishing): `0.7500`
- F1 (phishing): `0.6667`
- PR-AUC: `0.7521`
- ROC-AUC: `0.6562`
- Brier score: `0.4162`
- Confusion matrix: `{'true_positive': 6, 'true_negative': 4, 'false_positive': 4, 'false_negative': 2}`

## Raw model

- Cases scored by model: `16`
- Precision (phishing): `0.6000`
- Recall (phishing): `0.7500`
- F1 (phishing): `0.6667`

## Warnings

- Dataset manifest is missing.
- Some category metrics are undefined because the category does not contain both classes.
- Diagnostic corpus is not independent validation.
