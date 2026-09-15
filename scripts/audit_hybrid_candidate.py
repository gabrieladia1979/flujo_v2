"""Group bootstrap, error audit and validation-only calibration of a fixed model."""
import argparse
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, log_loss
from xgboost import DMatrix
from scripts.hybrid_data import load_training_csv
from scripts.train_hybrid import write_json, score_metrics
from services.hybrid_classifier import HybridClassifier
from services.hybrid_encoder import embed
from services.hybrid_features import technical_features


def grouped_f1_bootstrap(labels, candidate, baseline, groups, repeats=2000, seed=42):
    unique, inverse = np.unique(groups, return_inverse=True)
    contributions = []
    for prediction in (candidate, baseline):
        contributions.append(np.stack([np.bincount(inverse, weights=mask, minlength=len(unique))
            for mask in [(labels == 1) & prediction, (labels == 0) & prediction,
                         (labels == 1) & ~prediction]], axis=1))
    rng = np.random.default_rng(seed)
    values = []
    for _ in range(repeats):
        indices = rng.integers(len(unique), size=len(unique))
        f1 = []
        for counts in contributions:
            tp, fp, fn = counts[indices].sum(axis=0)
            denominator = 2 * tp + fp + fn
            f1.append(2 * tp / denominator if denominator else 0.0)
        values.append([*f1, f1[0] - f1[1]])
    return {name: np.quantile(np.asarray(values)[:, i], [.025, .5, .975]).tolist()
            for i, name in enumerate(['candidate_f1', 'baseline_f1', 'difference'])}


def logit(scores):
    scores = np.clip(scores, 1e-7, 1 - 1e-7)
    return np.log(scores / (1 - scores)).reshape(-1, 1)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--model', type=Path, required=True)
    p.add_argument('--dataset', type=Path, required=True)
    p.add_argument('--reference', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--external-cases', type=Path)
    args = p.parse_args()
    model = HybridClassifier(args.model)
    rows, audit = load_training_csv(args.dataset, '1')
    if audit['dataset_sha256'] != model.manifest['dataset_sha256']:
        raise ValueError('Dataset mismatch')
    lookup = {r['id']: r for r in rows}
    split = json.loads((args.model / 'splits.json').read_text())
    test = [lookup[r['id']] for r in split['test']]
    val = [lookup[r['id']] for r in split['validation']]
    ref = json.loads(args.reference.read_text())
    if ref['dataset_audit']['dataset_sha256'] != audit['dataset_sha256']:
        raise ValueError('Reference dataset mismatch')
    candidate = ref['results']['finetuned_embeddings_xgboost']
    base = ref['results']['tfidf_xgboost']
    scores = np.array(candidate['test_scores'])
    if len(scores) != len(test) or candidate['threshold'] != model.manifest['threshold']:
        raise ValueError('Reference test or threshold mismatch')
    labels = np.array([r['label'] for r in test])
    preds = scores >= candidate['threshold']
    bootstrap = grouped_f1_bootstrap(labels, preds, np.array(base['test_scores']) >= base['threshold'],
                                     [r['group'] for r in test])
    errors = []
    for r, s, pred in zip(test, scores, preds):
        if pred == r['label']:
            continue
        features = technical_features(r['subject'], r['body'], **r['metadata'])
        errors.append(dict(id=r['id'], source=r['source'], language_hint=r['language'],
                           label=r['label'], score=float(s), characters=len(r['text']),
                           url_count=features[0], credential_terms=features[10],
                           payment_terms=features[11], action_terms=features[13]))
    print('Scoring validation for calibration; test is not used to fit.', flush=True)
    vectors = embed(model.encoder, [r['text'] for r in val], 16)
    tech = np.array([technical_features(r['subject'], r['body'], **r['metadata']) for r in val], dtype=np.float32)
    validation_scores = model.head.predict(DMatrix(np.hstack([vectors, tech])))
    calibration = LogisticRegression(C=1e6, solver='lbfgs', random_state=42)
    calibration.fit(logit(validation_scores), [r['label'] for r in val])
    calibrated = calibration.predict_proba(logit(scores))[:, 1]
    groups = {}
    for field in ['source', 'language']:
        groups[field] = {}
        for value in sorted({r[field] for r in test}):
            mask = np.array([r[field] == value for r in test])
            groups[field][value] = score_metrics(labels[mask], scores[mask], candidate['threshold'])
    result = dict(dataset_sha256=audit['dataset_sha256'], seed=42, bootstrap_repeats=2000,
        bootstrap_unit='normalized template group', bootstrap_95_percent=bootstrap,
        by_group=groups, errors=errors,
        calibration=dict(method='Platt on logit; fit only on original validation',
                         coefficient=float(calibration.coef_[0, 0]), intercept=float(calibration.intercept_[0]),
                         raw_brier=float(brier_score_loss(labels, scores)),
                         calibrated_brier=float(brier_score_loss(labels, calibrated)),
                         raw_log_loss=float(log_loss(labels, scores)),
                         calibrated_log_loss=float(log_loss(labels, calibrated)),
                         deployed=False),
        warnings=['Bootstrap measures sampling uncertainty, not training seed variation.',
                  'The original test has already been inspected; future tuning needs an independent test.',
                  'Language is inferred from source, not detected per message.'])
    if args.external_cases:
        with args.external_cases.open(encoding='utf-8-sig', newline='') as f:
            external = list(csv.DictReader(f))
        ys = np.array([r['expected_label'] == 'phishing' for r in external])
        raw = np.array([float(r['raw_score']) for r in external])
        adjusted = calibration.predict_proba(logit(raw))[:, 1]
        result['external_calibration'] = dict(count=len(external),
            raw_brier=float(brier_score_loss(ys, raw)), calibrated_brier=float(brier_score_loss(ys, adjusted)),
            raw_log_loss=float(log_loss(ys, raw)), calibrated_log_loss=float(log_loss(ys, adjusted)),
            fit_source='original validation only', deployed=False)
    write_json(args.output, result)
    print(json.dumps({k: result[k] for k in ['bootstrap_95_percent', 'calibration']}, indent=2))


if __name__ == '__main__':
    main()
