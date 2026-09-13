# Classifier evaluation

- Dataset: `C:\Users\gabri\OneDrive\Documentos\GitHub\flujo_v2\data\classifier_eval_v1.jsonl`
- Model: `C:\Users\gabri\OneDrive\Documentos\GitHub\flujo_v2\model\phisharg_xgboost.pkl`
- Cases: `6`
- Partial run: `false`
- Seed: `42`

## Final outcome

- Precision (phishing): `1.0000`
- Recall (phishing): `1.0000`
- F1 (phishing): `1.0000`
- PR-AUC: `1.0000`
- ROC-AUC: `1.0000`
- Brier score: `0.0001`
- Confusion matrix: `{'true_positive': 2, 'true_negative': 4, 'false_positive': 0, 'false_negative': 0}`

## Raw model

- Cases scored by model: `6`
- Precision (phishing): `1.0000`
- Recall (phishing): `1.0000`
- F1 (phishing): `1.0000`

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
