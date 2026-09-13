# Classifier evaluation

- Dataset: `C:\Users\gabri\OneDrive\Documentos\GitHub\flujo_v2\data\classifier_eval_v1.jsonl`
- Model: `C:\Users\gabri\OneDrive\Documentos\GitHub\flujo_v2\model\phisharg_xgboost.pkl`
- Cases: `14`
- Partial run: `false`
- Seed: `42`

## Final outcome

- Precision (phishing): `1.0000`
- Recall (phishing): `1.0000`
- F1 (phishing): `1.0000`
- PR-AUC: `1.0000`
- ROC-AUC: `1.0000`
- Brier score: `0.0002`
- Confusion matrix: `{'true_positive': 6, 'true_negative': 8, 'false_positive': 0, 'false_negative': 0}`

## Raw model

- Cases scored by model: `12`
- Precision (phishing): `1.0000`
- Recall (phishing): `0.7500`
- F1 (phishing): `0.8571`

## Warnings

- Category bank_impersonation needs 6 more cases.
- Category credential_theft needs 9 more cases.
- Category internal_communication needs 6 more cases.
- Category legitimate_invoice needs 9 more cases.
- Category other_legitimate needs 9 more cases.
- Category tax_impersonation needs 9 more cases.
- Category technical_email needs 8 more cases.
- Raw-model metrics exclude 2 critical-rule cases.
- Some category metrics are undefined because the category does not contain both classes.
- The corpus is not a verified holdout from model training.
- The corpus needs 192 more legitimate cases.
- The corpus needs 194 more phishing cases.
- The evaluation corpus is incomplete.
