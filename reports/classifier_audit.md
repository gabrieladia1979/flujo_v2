# Classifier audit

- Model: `/Users/tomasbasualdo/Desktop/flujo_v2/model/phisharg_xgboost.pkl`
- Loadable: `true`
- Classes: `[0, 1]`
- Phishing class value: `0`
- Phishing probability index: `0`
- Mapping basis: `configured_production_class_convention`
- Current probability access: `predict_proba(X)[0][0]`
- Probability access status: `consistent_with_production_contract`
- Production threshold: `0.8`

## Feature dimensions

- TF-IDF: `6000`
- Metadata: `3`
- Slots: `7`
- URL: `11`
- Readability: `1`
- Produced total: `6022`
- Model expected total: `6022`
- Dimensions match: `True`

## Provenance

- Training provenance available: `false`

## Runtime

- python: `3.12.14`
- numpy: `2.5.3`
- scikit-learn: `1.9.0`
- xgboost: `3.4.1`
- spacy: `3.8.16`

## Warnings

- The numeric phishing label follows the configured production convention and behavioral regression evidence, but its semantics cannot be independently verified without training provenance.
- The artifact does not identify its training dataset or training process.
