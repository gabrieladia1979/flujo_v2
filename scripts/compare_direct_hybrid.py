"""Paired comparison of a direct-classifier run against hybrid curated V3."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np
from sklearn.metrics import f1_score

from scripts.direct_eval import score_metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--direct-report', required=True, type=Path)
    parser.add_argument('--hybrid-report', required=True, type=Path)
    parser.add_argument('--hybrid-splits', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--bootstrap-repetitions', type=int, default=2000)
    args = parser.parse_args()
    direct = json.loads(args.direct_report.read_text(encoding='utf-8'))
    hybrid = json.loads(args.hybrid_report.read_text(encoding='utf-8'))
    splits = json.loads(args.hybrid_splits.read_text(encoding='utf-8'))
    if direct['dataset_audit']['dataset_sha256'] != hybrid['dataset_audit']['dataset_sha256']:
        parser.error('Runs have different dataset hashes')
    baseline = hybrid['results']['finetuned_embeddings_xgboost']
    saved_ids = [item['id'] for item in splits['test']]
    if len(saved_ids) != len(baseline['test_scores']):
        parser.error('Hybrid test scores and IDs differ in length')
    predictions = {item['id']: item for item in direct['test_predictions']}
    if len(predictions) != len(direct['test_predictions']):
        parser.error('Direct report contains duplicate test IDs')
    if set(predictions) != set(saved_ids):
        parser.error('Direct and hybrid test IDs differ')
    labels = np.asarray([predictions[row_id]['label'] for row_id in saved_ids], dtype=int)
    direct_scores = np.asarray([predictions[row_id]['score'] for row_id in saved_ids])
    hybrid_scores = np.asarray(baseline['test_scores'])
    direct_threshold = direct['threshold']
    hybrid_threshold = baseline['threshold']
    direct_metrics = score_metrics(labels, direct_scores, direct_threshold)
    hybrid_metrics = score_metrics(labels, hybrid_scores, hybrid_threshold)
    if hybrid_metrics['confusion_matrix'] != baseline['test']['confusion_matrix']:
        parser.error('Hybrid predictions do not reproduce the recorded confusion matrix')
    direct_correct = (direct_scores >= direct_threshold) == labels
    hybrid_correct = (hybrid_scores >= hybrid_threshold) == labels
    paired = {
        'both_correct': int(np.sum(direct_correct & hybrid_correct)),
        'direct_only_correct': int(np.sum(direct_correct & ~hybrid_correct)),
        'hybrid_only_correct': int(np.sum(~direct_correct & hybrid_correct)),
        'both_wrong': int(np.sum(~direct_correct & ~hybrid_correct)),
    }
    group_ids = [item['group'] for item in splits['test']]
    groups = sorted(set(group_ids))
    by_group = {group: np.asarray([i for i, value in enumerate(group_ids) if value == group])
                for group in groups}
    rng = np.random.default_rng(42)
    f1_deltas = []
    for _ in range(args.bootstrap_repetitions):
        sampled = rng.choice(groups, size=len(groups), replace=True)
        indices = np.concatenate([by_group[group] for group in sampled])
        d = f1_score(labels[indices], direct_scores[indices] >= direct_threshold)
        h = f1_score(labels[indices], hybrid_scores[indices] >= hybrid_threshold)
        f1_deltas.append(float(d - h))
    result = {
        'dataset_sha256': direct['dataset_audit']['dataset_sha256'],
        'test_count': len(labels), 'test_groups': len(groups),
        'direct': direct_metrics, 'hybrid': hybrid_metrics,
        'delta_f1_direct_minus_hybrid': direct_metrics['f1_phishing'] - hybrid_metrics['f1_phishing'],
        'group_bootstrap_f1_delta_95_percent_interval': np.percentile(f1_deltas, [2.5, 97.5]).tolist(),
        'paired_correctness': paired,
        'caveat': 'Same historical test used for model development; the interval characterizes this split only, not future campaigns.',
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
