"""Evaluate at most eight contiguous fragments without breaking whitespace tokens."""
import csv
import hashlib
import itertools
import json
import random
import re
from pathlib import Path

import numpy as np
from lime.lime_base import LimeBase
from scipy.special import expit, logit
from sklearn.linear_model import Ridge
from sklearn.metrics import r2_score
from xgboost import DMatrix

from services.hybrid_classifier import HybridClassifier
from services.hybrid_encoder import embed
from services.hybrid_features import encoder_text, technical_features


def fragment_spans(body, maximum=8):
    tokens = list(re.finditer(r'\S+', body))
    if not tokens:
        return []
    groups = np.array_split(np.arange(len(tokens)), min(maximum, len(tokens)))
    starts = [0] + [tokens[int(group[0])].start() for group in groups[1:]]
    return list(zip(starts, starts[1:] + [len(body)]))


def measure_stability(results):
    stability = []
    for identifier in sorted({r['id'] for r in results}):
        for scale in ('probability', 'logodds'):
            group = [r for r in results if r['id'] == identifier and r['scale'] == scale]
            for a, b in itertools.combinations(group, 2):
                wa = np.asarray([w['weight'] for w in a['weights']])
                wb = np.asarray([w['weight'] for w in b['weights']])
                significant = (np.abs(wa) >= 1e-6) & (np.abs(wb) >= 1e-6)
                top_a = set(np.argsort(-np.abs(wa))[:3].tolist())
                top_b = set(np.argsort(-np.abs(wb))[:3].tolist())
                denominator = np.linalg.norm(wa) * np.linalg.norm(wb)
                stability.append(dict(id=identifier, scale=scale, seeds=[a['seed'], b['seed']],
                    comparable_signs=int(significant.sum()),
                    matching_signs=int(((np.sign(wa) == np.sign(wb)) & significant).sum()),
                    shared_top_three=len(top_a & top_b),
                    cosine=float(wa @ wb / denominator) if denominator > 1e-20 else None))
    return stability


def evaluate():
    selection = Path('reports/hybrid_lime_locality_fresh.json')
    wanted = {case['id'] for case in json.loads(selection.read_text())['cases']}
    csv.field_size_limit(10_000_000)
    with Path('artifacts/hybrid/corpus-v3/training.csv').open(encoding='utf-8-sig', newline='') as source:
        rows = [(f'row-{i}', row) for i, row in enumerate(csv.DictReader(source), 2) if f'row-{i}' in wanted]
    classifier = HybridClassifier('artifacts/hybrid/multilingual-candidate-v3-curated')
    results = []
    for identifier, row in rows:
        body, subject = row['body'], row['subject']
        spans = fragment_spans(body)
        n = len(spans)
        if n < 5:
            raise ValueError('At least five fragments required for unseen validation masks')
        fragments = [body[start:end] for start, end in spans]
        assert ''.join(fragments) == body
        removed = [frozenset()] + [frozenset([i]) for i in range(n)]
        removed += [frozenset(c) for count in (2, 3) for c in itertools.combinations(range(n), count)]
        masks = np.ones((len(removed), n))
        for i, indices in enumerate(removed):
            masks[i, list(indices)] = 0
        bodies = [''.join(text for j, text in enumerate(fragments) if j not in indices) for indices in removed]
        features = np.asarray([technical_features(subject, text,
            int(float(row.get('attachments_count') or 0)), int(float(row.get('hops_count') or 0)))
            for text in bodies], dtype=np.float32)
        with classifier.lock:
            vectors = embed(classifier.encoder, [encoder_text(subject, text) for text in bodies])
            scores = classifier.head.predict(DMatrix(np.hstack([vectors, features]))).astype(float)
        for seed in (42, 7, 21):
            combinations = list(range(n + 1, len(removed)))
            random.Random(seed).shuffle(combinations)
            validation_count = min(32, len(combinations) // 2)
            valid = combinations[:validation_count]
            train = list(range(n + 1)) + combinations[validation_count:]
            assert not set(train) & set(valid)
            distance = (1 - np.sqrt(masks[train].sum(axis=1) / n)) * 100
            for scale in ('probability', 'logodds'):
                targets = logit(np.clip(scores[train], 1e-6, 1 - 1e-6)) if scale == 'logodds' else scores[train]
                intercept, weights, _, _ = LimeBase(
                    lambda d: np.sqrt(np.exp(-d ** 2 / 25 ** 2)), random_state=seed).explain_instance_with_data(
                    masks[train], np.column_stack((np.zeros(len(train)), targets)), distance, 1, n,
                    model_regressor=Ridge(alpha=0.01))
                coefficients = np.zeros(n)
                for fragment, weight in weights:
                    coefficients[fragment] = weight
                prediction = intercept + masks @ coefficients
                if scale == 'logodds':
                    prediction = expit(prediction)
                fit = float(r2_score(scores[train], prediction[train]))
                fresh = float(r2_score(scores[valid], prediction[valid])) if np.var(scores[valid]) > 1e-10 else None
                error = float(abs(prediction[0] - scores[0]))
                results.append(dict(id=identifier, label=row['Label'], source_language_hint=row['language'],
                    seed=seed, scale=scale, fragments=n, fragment_lengths=[len(s) for s in fragments],
                    training_samples=len(train), validation_samples=len(valid), fit_r2=fit, heldout_r2=fresh,
                    original_score_error=error, mae=float(np.mean(np.abs(scores[valid] - prediction[valid]))),
                    weights=[dict(fragment_index=i, weight=float(w)) for i, w in enumerate(coefficients)],
                    passes=fit >= .7 and fresh is not None and fresh >= .7 and error <= .01))
        print(identifier, flush=True)
    summary = []
    for scale in ('probability', 'logodds'):
        group = [r for r in results if r['scale'] == scale]
        summary.append(dict(scale=scale, cases=len(rows),
            passes_per_seed={str(seed): sum(r['passes'] for r in group if r['seed'] == seed) for seed in (42, 7, 21)},
            passes_all_seeds=sum(all(r['passes'] for r in group if r['id'] == identifier) for identifier, _ in rows),
            median_heldout_r2=float(np.median([r['heldout_r2'] for r in group if r['heldout_r2'] is not None]))))
    stability = measure_stability(results)
    report = dict(scope='raw hybrid probability; at most eight contiguous whitespace-token blocks; URLs not split inside tokens',
        selection=str(selection), limitation='Previously inspected development cases. Removing fragments changes the neighborhood. '
            'Fragments are positional groups, not guaranteed grammatical phrases. All eight fitted coefficients are reported.',
        evaluation='Disjoint fit/validation masks per seed; partitions overlap across seeds; all probabilities inferred once.',
        thresholds=dict(r2=.7, max_original_score_error=.01, minimum_probability_variance=1e-10),
        sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (selection,
            Path('artifacts/hybrid/corpus-v3/training.csv'),
            Path('artifacts/hybrid/multilingual-candidate-v3-curated/manifest.json'))},
        summary=summary, stability=stability, cases=results)
    Path('reports/hybrid_lime_fragments.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    evaluate()
