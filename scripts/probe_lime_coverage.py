"""Compare complete singleton coverage and anchored local surrogates."""
import argparse
import csv
import hashlib
import json
import math
import random
import importlib.metadata
import sys
from pathlib import Path

import numpy as np
from lime.lime_base import LimeBase
from lime.lime_text import IndexedString
from sklearn.linear_model import Ridge
from sklearn.metrics import r2_score
from scipy.special import expit, logit
from xgboost import DMatrix

from services.hybrid_classifier import HybridClassifier
from services.hybrid_encoder import embed
from services.hybrid_features import encoder_text, technical_features


def evaluate(selection='reports/hybrid_lime_diagnostic_v1.json', output='reports/hybrid_lime_coverage.json'):
    original = json.loads(Path(selection).read_text())
    wanted = {c['id'] for c in original['cases']}
    csv.field_size_limit(10_000_000)
    with Path('artifacts/hybrid/corpus-v3/training.csv').open(encoding='utf-8-sig', newline='') as source:
        rows = [(f'row-{i}', row) for i, row in enumerate(csv.DictReader(source), 2) if f'row-{i}' in wanted]
    classifier = HybridClassifier('artifacts/hybrid/multilingual-candidate-v3-curated')
    fingerprint = hashlib.sha256()
    cache_inputs = ['services/hybrid_classifier.py', 'services/hybrid_encoder.py', 'services/hybrid_features.py',
                 'artifacts/hybrid/corpus-v3/training.csv',
                 'artifacts/hybrid/multilingual-candidate-v3-curated/manifest.json',
                 'artifacts/hybrid/multilingual-candidate-v3-curated/finetuned_embeddings_xgboost.json']
    cache_inputs += [str(p) for p in sorted(Path('artifacts/hybrid/multilingual-candidate-v3-curated/encoder').rglob('*')) if p.is_file()]
    for path in cache_inputs:
        fingerprint.update(str(path).encode())
        with Path(path).open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                fingerprint.update(block)
    fingerprint.update(sys.version.encode())
    for package in ['numpy', 'torch', 'transformers', 'sentence-transformers', 'xgboost', 'lime']:
        fingerprint.update((package + importlib.metadata.version(package)).encode())
    cache_dir = Path('artifacts/hybrid/lime-coverage-cache')
    cache_dir.mkdir(parents=True, exist_ok=True)
    results = []
    cache_hits = 0
    for identifier, row in rows:
        indexed = IndexedString(row['body'])
        n = indexed.num_words()
        rng = random.Random(42)
        train = [frozenset()] + [frozenset([i]) for i in range(n)]
        seen = set(train)
        target = max(256, 1 + 3 * n)
        if n < 3 or 1 + n + math.comb(n, 2) + math.comb(n, 3) < target + 32:
            raise ValueError('Insufficient distinct words for this sampling budget')
        attempts = 0
        while len(train) < target:
            attempts += 1
            if attempts > 100000:
                raise ValueError('Unable to fill unique training masks')
            removed = frozenset(rng.sample(range(n), rng.randint(2, 3)))
            if removed not in seen:
                train.append(removed)
                seen.add(removed)
        heldout = []
        rng = random.Random(43)
        attempts = 0
        while len(heldout) < 32:
            attempts += 1
            if attempts > 10000:
                raise ValueError('Insufficient unseen combinations')
            removed = frozenset(rng.sample(range(n), rng.randint(2, 3)))
            if removed not in seen:
                heldout.append(removed)
                seen.add(removed)
        absent = np.zeros((target + 32, n))
        for i, removed in enumerate(train + heldout):
            absent[i, list(removed)] = 1
        bodies = [indexed.inverse_removing(sorted(removed)) for removed in train + heldout]
        subject = row['subject']
        features = np.asarray([technical_features(subject, body,
            int(float(row.get('attachments_count') or 0)), int(float(row.get('hops_count') or 0)))
            for body in bodies], dtype=np.float32)
        cache_path = cache_dir / f'{identifier}.npz'
        scores = None
        if cache_path.exists():
            with np.load(cache_path, allow_pickle=False) as cache:
                if str(cache['fingerprint']) == fingerprint.hexdigest() and np.array_equal(cache['absent'], absent):
                    scores = cache['scores'].copy()
                    cache_hits += 1
        if scores is None:
            with classifier.lock:
                vectors = embed(classifier.encoder, [encoder_text(subject, body) for body in bodies])
                scores = classifier.head.predict(DMatrix(np.hstack([vectors, features]))).astype(float)
            np.savez_compressed(cache_path, fingerprint=fingerprint.hexdigest(), absent=absent, scores=scores)
        if scores.shape != (target + 32,) or not np.isfinite(scores).all() or ((scores < 0) | (scores > 1)).any():
            raise ValueError('Invalid cached or inferred probabilities')
        distances = (1 - np.sqrt(1 - absent[:target].sum(axis=1) / n)) * 100
        kernel = lambda d: np.sqrt(np.exp(-d ** 2 / 25 ** 2))
        single_effects = scores[0] - scores[1:n + 1]
        for method, count in [('lime', 8), ('lime', n), ('lime_logodds', 8), ('lime_logodds', n), ('anchored', 8), ('anchored', 16),
                              ('anchored', n), ('single_deletion', n)]:
            count = min(count, n)
            if method in ('lime', 'lime_logodds'):
                target_scores = logit(np.clip(scores[:target], 1e-6, 1 - 1e-6)) if method == 'lime_logodds' else scores[:target]
                intercept, weights, _, _ = LimeBase(kernel, random_state=42).explain_instance_with_data(
                    1 - absent[:target], np.column_stack((np.zeros(target), target_scores)),
                    distances, 1, count, model_regressor=Ridge(alpha=0.01))
                coefficients = np.zeros(n)
                for token, weight in weights:
                    coefficients[token] = weight
                predicted = intercept + (1 - absent) @ coefficients
                if method == 'lime_logodds':
                    predicted = expit(predicted)
            else:
                chosen = np.argsort(-np.abs(single_effects), kind='stable')[:count]
                coefficients = np.zeros(n)
                if method == 'anchored':
                    model = Ridge(alpha=0.01, fit_intercept=False).fit(absent[:target, chosen],
                        scores[0] - scores[:target], sample_weight=kernel(distances))
                    coefficients[chosen] = model.coef_
                else:
                    coefficients[chosen] = single_effects[chosen]
                predicted = scores[0] - absent @ coefficients
            fit = float(r2_score(scores[:target], predicted[:target]))
            fresh = float(r2_score(scores[target:], predicted[target:])) if np.var(scores[target:]) > 1e-10 else None
            results.append(dict(id=identifier, label=row['Label'], method=method, word_count=count,
                all_words=count == n, training_samples=target, fit_r2=fit, heldout_r2=fresh,
                mae=float(np.mean(np.abs(scores[target:] - predicted[target:]))),
                original_score_error=float(abs(predicted[0] - scores[0])),
                passes=fit >= .7 and fresh is not None and fresh >= .7,
                passes_with_original_check=fit >= .7 and fresh is not None and fresh >= .7
                    and abs(predicted[0] - scores[0]) <= .01))
        print(identifier, flush=True)
    groups = {}
    for case in results:
        key = case['method'] + ('_all' if case['all_words'] else '_' + str(case['word_count']))
        groups.setdefault(key, []).append(case)
    summary = {key: dict(cases=len(group), passes=sum(c['passes'] for c in group),
        passes_with_original_check=sum(c['passes_with_original_check'] for c in group),
        median_heldout_r2=float(np.median([c['heldout_r2'] for c in group if c['heldout_r2'] is not None])))
        for key, group in groups.items()}
    report = dict(scope='raw hybrid probability; complete singleton coverage; unique 2-3 word deletions',
        selection=selection, selection_warning='Previously inspected corpus cases; not final independent validation',
        seed=42, validation_seed=43, validation_samples=32,
        max_original_score_error=0.01,
        inference_cache_hits=cache_hits, inference_cache_fingerprint=fingerprint.hexdigest(),
        distinction='Anchored Ridge and single-deletion baselines are not the standard LIME estimator. '
                    'All-word fidelity cannot be attributed to a shortened eight-word explanation. '
                    'Logodds weights explain logit(p), clipped at 1e-6; fidelity is evaluated after sigmoid on raw probabilities.',
        sha256={p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in (
            'artifacts/hybrid/corpus-v3/training.csv',
            'artifacts/hybrid/multilingual-candidate-v3-curated/manifest.json')},
        summary=summary, cases=results)
    Path(output).write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', default='reports/hybrid_lime_diagnostic_v1.json')
    parser.add_argument('--output', default='reports/hybrid_lime_coverage.json')
    args = parser.parse_args()
    evaluate(args.selection, args.output)
