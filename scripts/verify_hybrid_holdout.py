"""Re-evaluate an exported hybrid model through the serving path, without training."""

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np
from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema
from scripts.hybrid_data import load_training_csv
from scripts.train_hybrid import score_metrics, write_json
from services.hybrid_classifier import HybridClassifier


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding='utf-8'))
    rows, audit = load_training_csv(args.dataset, report['configuration']['phishing_label'])
    model = HybridClassifier(args.model)
    if audit['dataset_sha256'] != model.manifest['dataset_sha256'] or audit['dataset_sha256'] != report['dataset_audit']['dataset_sha256']:
        raise ValueError('Dataset does not match the trained artifact and report')
    split = json.loads((args.model / 'splits.json').read_text(encoding='utf-8'))
    lookup = {r['id']: r for r in rows}
    selected = [lookup[r['id']] for r in split['test']]
    if any(r['group'] != s['group'] for r, s in zip(selected, split['test'])):
        raise ValueError('Test groups changed')
    reference = report['results']['finetuned_embeddings_xgboost']
    expected = np.asarray(reference['test_scores'])
    if len(expected) != len(selected) or reference['threshold'] != model.manifest['threshold']:
        raise ValueError('Reference scores/threshold do not match')
    scores = []
    for i, row in enumerate(selected, 1):
        payload = EmailPayloadSchema(metadata=MetadataSchema(asunto=row['subject']),
                                     contenido=row['body'], security_features=SecurityFeaturesSchema(**row['metadata']))
        scores.append(model.raw_score(payload))
        if i % 100 == 0:
            print(f'Evaluated {i}/{len(selected)}', flush=True)
    actual = np.asarray(scores)
    labels = np.asarray([r['label'] for r in selected])
    threshold = model.manifest['threshold']
    predicted = actual >= threshold
    errors = [dict(id=r['id'], source=r['source'], language_hint=r['language'],
                   expected_label=int(label), score=float(score), reference_score=float(old),
                   error='false_negative' if label else 'false_positive')
              for r, label, score, old, pred in zip(selected, labels, actual, expected, predicted) if pred != label]
    by_source = {}
    for source in sorted({r['source'] for r in selected}):
        mask = np.asarray([r['source'] == source for r in selected])
        by_source[source] = score_metrics(labels[mask], actual[mask], threshold)
    result = dict(model=str(args.model), reference_report=str(args.report),
                  manifest_sha256=hashlib.sha256((args.model / 'manifest.json').read_bytes()).hexdigest(),
                  dataset_sha256=audit['dataset_sha256'], threshold=threshold,
                  environment={p: importlib.metadata.version(p) for p in ['torch', 'transformers', 'sentence-transformers', 'tokenizers', 'xgboost']},
                  metrics=score_metrics(labels, actual, threshold), by_source=by_source,
                  comparison=dict(max_absolute_score_difference=float(np.max(np.abs(actual-expected))),
                                  mean_absolute_score_difference=float(np.mean(np.abs(actual-expected))),
                                  score_mismatches_at_1e_6=int(np.sum(np.abs(actual-expected)>1e-6)),
                                  decision_disagreements=int(np.sum(predicted != (expected >= threshold)))),
                  errors=errors, test_ids=[r['id'] for r in selected], test_scores=scores)
    write_json(args.output, result)
    print(json.dumps({k: result[k] for k in ['metrics', 'comparison']}, indent=2))


if __name__ == '__main__':
    main()
