"""Validate the four favorable all-word cases on newly generated mask pools."""
import argparse
import csv
import hashlib
import json
import random
from pathlib import Path

import numpy as np
from lime.lime_base import LimeBase
from lime.lime_text import IndexedString
from scipy.special import expit, logit
from sklearn.linear_model import Ridge
from sklearn.metrics import r2_score
from xgboost import DMatrix

from scripts.probe_lime_fragments import measure_stability
from services.hybrid_classifier import HybridClassifier
from services.hybrid_encoder import embed
from services.hybrid_features import encoder_text, technical_features


def evaluate(training_samples=256, validation_samples=64,
             output='reports/hybrid_lime_independent_masks.json'):
    previous = json.loads(Path('reports/hybrid_lime_full_stability.json').read_text())
    selected = {c['id'] for c in previous['summary']['passes_all_seeds']}
    csv.field_size_limit(10_000_000)
    with Path('artifacts/hybrid/corpus-v3/training.csv').open(encoding='utf-8-sig', newline='') as source:
        rows = [(f'row-{i}', r) for i, r in enumerate(csv.DictReader(source), 2) if f'row-{i}' in selected]
    if {i for i, _ in rows} != selected:
        raise ValueError('Selected cases missing from the local dataset')
    classifier = HybridClassifier('artifacts/hybrid/multilingual-candidate-v3-curated')
    results = []
    for identifier, row in rows:
        indexed = IndexedString(row['body'])
        n = indexed.num_words()
        with np.load(Path('artifacts/hybrid/lime-coverage-cache') / (identifier + '.npz'), allow_pickle=False) as cache:
            if str(cache['fingerprint']) != previous['inference_cache_fingerprint']:
                raise ValueError('Cache does not match historical mask pool')
            old_masks = cache['absent'].copy()
        if old_masks.shape[1] != n:
            raise ValueError('Word indexing differs from the historical pool')
        seen = {frozenset(np.flatnonzero(mask).tolist()) for mask in old_masks}
        for seed in (101, 202):
            rng = random.Random(seed)
            train = [frozenset()] + [frozenset([i]) for i in range(n)]
            target = max(training_samples, 1 + 3 * n)
            validation = []
            attempts = 0
            # Original/single deletions are intentionally shared; all new 2-3 word masks are disjoint.
            while len(train) < target or len(validation) < validation_samples:
                attempts += 1
                if attempts > 100000:
                    raise ValueError('Not enough unseen masks')
                removed = frozenset(rng.sample(range(n), rng.randint(2, 3)))
                if removed in seen:
                    continue
                seen.add(removed)
                (train if len(train) < target else validation).append(removed)
            assert not set(train) & set(validation)
            masks = np.ones((target + validation_samples, n))
            for i, removed in enumerate(train + validation):
                masks[i, list(removed)] = 0
            bodies = [indexed.inverse_removing(sorted(removed)) for removed in train + validation]
            subject = row['subject']
            features = np.asarray([technical_features(subject, text,
                int(float(row.get('attachments_count') or 0)), int(float(row.get('hops_count') or 0)))
                for text in bodies], dtype=np.float32)
            with classifier.lock:
                vectors = embed(classifier.encoder, [encoder_text(subject, text) for text in bodies])
                scores = classifier.head.predict(DMatrix(np.hstack([vectors, features]))).astype(float)
            distances = (1 - np.sqrt(masks[:target].sum(axis=1) / n)) * 100
            targets = logit(np.clip(scores[:target], 1e-6, 1 - 1e-6))
            intercept, weights, _, _ = LimeBase(lambda d: np.sqrt(np.exp(-d ** 2 / 25 ** 2)),
                random_state=seed).explain_instance_with_data(masks[:target],
                np.column_stack((np.zeros(target), targets)), distances, 1, n,
                model_regressor=Ridge(alpha=.01))
            coefficients = np.zeros(n)
            for token, weight in weights:
                coefficients[token] = weight
            prediction = expit(intercept + masks @ coefficients)
            fit = float(r2_score(scores[:target], prediction[:target]))
            fresh = float(r2_score(scores[target:], prediction[target:])) if np.var(scores[target:]) > 1e-10 else None
            error = float(abs(prediction[0] - scores[0]))
            results.append(dict(id=identifier, label=row['Label'], seed=seed, scale='logodds', word_count=n,
                training_samples=target, validation_samples=validation_samples, original_probability=float(scores[0]),
                fit_r2=fit, heldout_r2=fresh, original_score_error=error,
                mae=float(np.mean(np.abs(scores[target:] - prediction[target:]))),
                weights=[dict(token_index=i, weight=float(w)) for i, w in enumerate(coefficients)],
                passes=fit >= .7 and fresh is not None and fresh >= .7 and error <= .01))
            print(identifier, seed, flush=True)
    combined = results + [c for c in previous['cases'] if c['id'] in selected]
    summary = dict(cases=len(selected),
        passes_per_new_seed={str(s): sum(c['passes'] for c in results if c['seed'] == s) for s in (101, 202)},
        passes_all_five=[dict(id=i, label=next(c['label'] for c in results if c['id'] == i)) for i in sorted(selected)
                        if all(c['passes'] for c in combined if c['id'] == i)])
    report = dict(scope='all-word logodds LIME, validated on raw probability after sigmoid',
        selection='four favorable previously inspected cases; cannot estimate population reliability',
        masks='Original/single word deletions shared. New 2-3 word fit and validation masks exclude historical pool '
              'and each other across seeds 101/202. Increased budgets use the same seeds and can overlap earlier budget trials.',
        thresholds=dict(r2=.7, max_original_score_error=.01, minimum_probability_variance=1e-10),
        sha256={p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in (
            'reports/hybrid_lime_full_stability.json', 'artifacts/hybrid/corpus-v3/training.csv',
            'artifacts/hybrid/multilingual-candidate-v3-curated/manifest.json')},
        summary=summary, stability=measure_stability(combined), cases=results)
    Path(output).write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--training-samples', type=int, default=256)
    parser.add_argument('--validation-samples', type=int, default=64)
    parser.add_argument('--output', default='reports/hybrid_lime_independent_masks.json')
    args = parser.parse_args()
    if args.training_samples < 256 or args.validation_samples < 32:
        parser.error('Diagnostic requires at least 256 training and 32 validation samples')
    evaluate(args.training_samples, args.validation_samples, args.output)
