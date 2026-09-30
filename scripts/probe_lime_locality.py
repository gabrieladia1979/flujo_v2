"""Compare LIME fits on a small-deletion neighborhood; research only."""
import argparse
import csv
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

import numpy as np
from lime.lime_base import LimeBase
from lime.lime_text import IndexedString
from sklearn.linear_model import Ridge
from sklearn.metrics import r2_score
from xgboost import DMatrix

from services.hybrid_classifier import HybridClassifier
from services.hybrid_encoder import embed
from services.hybrid_features import encoder_text, technical_features


def run(seed=42, selected=None, output='reports/hybrid_lime_locality_probe.json', fresh=False):
    previous = json.loads(Path('reports/hybrid_lime_diagnostic_v1.json').read_text())
    wanted = {case['id'] for case in previous['cases']}
    if selected:
        if not set(selected) <= wanted:
            raise ValueError('Requested IDs are outside the diagnostic selection')
        wanted = set(selected)
    rows = {}
    strata = defaultdict(list)
    test_ids = {item['id'] for item in json.loads(Path('artifacts/hybrid/corpus-v3/splits.json').read_text())['test']}
    csv.field_size_limit(10_000_000)
    with Path('artifacts/hybrid/corpus-v3/training.csv').open(encoding='utf-8-sig', newline='') as source:
        for line, row in enumerate(csv.DictReader(source), 2):
            identifier = f'row-{line}'
            if fresh and identifier in test_ids and identifier not in wanted and 120 <= len(row['body']) <= 1000:
                strata[(row['Label'], row['language'])].append((identifier, row))
            if f'row-{line}' in wanted:
                rows[f'row-{line}'] = row
    if fresh:
        if selected:
            raise ValueError('Fresh selection cannot be combined with IDs')
        selection_rng = random.Random(1337)
        rows = dict(item for key in sorted(strata)
                    for item in selection_rng.sample(strata[key], min(5, len(strata[key]))))
        wanted = set(rows)
    if not rows or set(rows) != wanted:
        raise ValueError('Requested diagnostic cases are missing or invalid')
    classifier = HybridClassifier('artifacts/hybrid/multilingual-candidate-v3-curated')
    results = []
    for identifier, row in rows.items():
        body, subject = row['body'], row['subject']
        indexed = IndexedString(body)
        n = indexed.num_words()
        if n < 6:
            raise ValueError('This diagnostic requires at least six distinct words')
        rng = random.Random(seed)
        train = [frozenset()] + [frozenset([i]) for i in range(min(n, 64))]
        seen = set(train)
        while len(train) < 128:
            removed = frozenset(rng.sample(range(n), rng.randint(1, min(3, n))))
            train.append(removed)
            seen.add(removed)
        heldout = []
        rng = random.Random(seed + 1)
        attempts = 0
        while len(heldout) < 32:
            attempts += 1
            if attempts > 10000:
                raise ValueError('Not enough unseen masks for this diagnostic')
            removed = frozenset(rng.sample(range(n), rng.randint(2, min(3, n))))
            if removed not in seen:
                heldout.append(removed)
                seen.add(removed)
        masks = np.ones((160, n))
        for i, removed in enumerate(train + heldout):
            masks[i, list(removed)] = 0
        bodies = [indexed.inverse_removing(sorted(removed)) for removed in train + heldout]
        attachments = int(float(row.get('attachments_count') or 0))
        hops = int(float(row.get('hops_count') or 0))
        features = np.asarray([technical_features(subject, text, attachments, hops) for text in bodies], dtype=np.float32)
        with classifier.lock:
            vectors = embed(classifier.encoder, [encoder_text(subject, text) for text in bodies])
            scores = classifier.head.predict(DMatrix(np.hstack([vectors, features])))
        labels = np.column_stack((1 - scores, scores))
        distances = (1 - np.sqrt(masks[:128].sum(axis=1) / n)) * 100
        base = LimeBase(lambda distance: np.sqrt(np.exp(-(distance ** 2) / 25 ** 2)), random_state=seed)
        for count in ((8,) if fresh else (8, 32, 64)):
            for alpha in ((0.01,) if fresh else (1.0, 0.01)):
                intercept, weights, fit, _ = base.explain_instance_with_data(
                    masks[:128], labels[:128], distances, 1, min(count, n),
                    model_regressor=Ridge(alpha=alpha),
                )
                predicted = np.full(32, intercept)
                for feature, weight in weights:
                    predicted += masks[128:, feature] * weight
                heldout_r2 = float(r2_score(scores[128:], predicted)) if np.var(scores[128:]) > 1e-10 else None
                results.append(dict(id=identifier, label=row['Label'], features=count, alpha=alpha,
                                    source_language_hint=row['language'],
                                    original_probability=float(scores[0]),
                                    word_weights=[dict(token_index=int(feature), weight=float(weight),
                                        single_deletion_delta=float(scores[0] - scores[1 + feature])
                                        if feature < min(n, 64) else None)
                                        for feature, weight in weights],
                                    fit_r2=float(fit), heldout_r2=heldout_r2,
                                    mae=float(np.mean(np.abs(scores[128:] - predicted)))))
        print(identifier, flush=True)
    summary = []
    for count in ((8,) if fresh else (8, 32, 64)):
        for alpha in ((0.01,) if fresh else (1.0, 0.01)):
            group = [r for r in results if r['features'] == count and r['alpha'] == alpha]
            defined = [r['heldout_r2'] for r in group if r['heldout_r2'] is not None]
            summary.append(dict(features=count, alpha=alpha, count=len(group),
                                median_heldout_r2=float(np.median(defined)) if defined else None,
                                passes=sum(r['fit_r2'] >= .7 and r['heldout_r2'] is not None and r['heldout_r2'] >= .7 for r in group)))
    report = {'scope': 'raw hybrid score; remove 1-3 words; validation removes 2-3 words absent from training masks',
              'training_seed': seed, 'validation_seed': seed + 1,
              'training_samples': 128, 'validation_samples': 32,
              'minimum_validation_probability_variance': 1e-10,
              'singleton_selection': 'first up to 64 distinct tokens',
              'selection': ('seed 1337; up to five per label/source language; saved test IDs; body 120-1000 chars; '
                            'excludes previous 20 cases; fixed eight words/Ridge 0.01' if fresh else
                            'previous 20 diagnostic cases, optionally filtered; reused for tuning, not independent final validation'),
              'sha256': {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in (
                  'artifacts/hybrid/corpus-v3/training.csv',
                  'artifacts/hybrid/corpus-v3/splits.json',
                  'artifacts/hybrid/multilingual-candidate-v3-curated/manifest.json')},
              'summary': summary, 'cases': results}
    Path(output).write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--ids', nargs='+')
    parser.add_argument('--fresh', action='store_true')
    parser.add_argument('--output', default='reports/hybrid_lime_locality_probe.json')
    args = parser.parse_args()
    run(args.seed, args.ids, args.output, args.fresh)
