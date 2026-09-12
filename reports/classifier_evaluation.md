# Classifier evaluation

- Dataset: `/Users/tomasbasualdo/Desktop/flujo_v2/data/classifier_eval_v1.jsonl`
- Model: `/Users/tomasbasualdo/Desktop/flujo_v2/model/phisharg_xgboost.pkl`
- Cases: `6`
- Partial run: `false`
- Seed: `42`

## Final outcome

- Precision (phishing): `0.0000`
- Recall (phishing): `0.0000`
- F1 (phishing): `0.0000`
- PR-AUC: `0.2667`
- ROC-AUC: `0.0000`
- Brier score: `0.8061`
- Confusion matrix: `{'true_positive': 0, 'true_negative': 1, 'false_positive': 3, 'false_negative': 2}`

## Raw model

- Cases scored by model: `6`
- Precision (phishing): `0.0000`
- Recall (phishing): `0.0000`
- F1 (phishing): `0.0000`

## Warnings

- Category bank_impersonation needs 9 more cases.
- Category internal_communication needs 7 more cases.
- Category tax_impersonation needs 9 more cases.
- Category technical_email needs 9 more cases.
- Some category metrics are undefined because the category does not contain both classes.
- The corpus is not a verified holdout from model training.
- The corpus needs 196 more legitimate cases.
- The corpus needs 198 more phishing cases.
- The evaluation corpus is incomplete.
