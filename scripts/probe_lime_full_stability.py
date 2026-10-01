"""Repartition cached model predictions to check all-word logodds LIME."""
import argparse
import json
import random
from pathlib import Path

import numpy as np
from lime.lime_base import LimeBase
from scipy.special import expit, logit
from sklearn.linear_model import Ridge
from sklearn.metrics import r2_score

from scripts.probe_lime_fragments import measure_stability


def evaluate(anchored=False, output='reports/hybrid_lime_full_stability.json'):
    source = Path('reports/hybrid_lime_coverage_confirm.json')
    previous = json.loads(source.read_text())
    expected = {c['id']: c for c in previous['cases'] if c['method'] == 'lime_logodds' and c['all_words']}
    results = []
    for identifier, reference in expected.items():
        with np.load(Path('artifacts/hybrid/lime-coverage-cache') / (identifier + '.npz'), allow_pickle=False) as cache:
            if str(cache['fingerprint']) != previous['inference_cache_fingerprint']:
                raise ValueError('Cache does not match recorded model predictions')
            absent, scores = cache['absent'], cache['scores']
        n = absent.shape[1]
        target = reference['training_samples']
        if absent.shape[0] != target + 32 or scores.shape != (target + 32,):
            raise ValueError('Unexpected cached prediction dimensions')
        masks = 1 - absent
        for seed in (42, 7, 21):
            if seed == 42:
                train, valid = list(range(target)), list(range(target, target + 32))
            else:
                pool = list(range(n + 1, len(scores)))
                random.Random(seed).shuffle(pool)
                valid, train = pool[:32], list(range(n + 1)) + pool[32:]
            assert not set(train) & set(valid)
            distances = (1 - np.sqrt(masks[train].sum(axis=1) / n)) * 100
            targets = logit(np.clip(scores[train], 1e-6, 1 - 1e-6))
            if anchored:
                original_logit = float(logit(np.clip(scores[0], 1e-6, 1 - 1e-6)))
                model = Ridge(alpha=.01, fit_intercept=False).fit(absent[train], original_logit - targets,
                    sample_weight=np.sqrt(np.exp(-distances ** 2 / 25 ** 2)))
                coefficients = model.coef_
                prediction = expit(original_logit - absent @ coefficients)
            else:
                intercept, weights, _, _ = LimeBase(lambda d: np.sqrt(np.exp(-d ** 2 / 25 ** 2)),
                    random_state=seed).explain_instance_with_data(masks[train],
                    np.column_stack((np.zeros(len(train)), targets)), distances, 1, n,
                    model_regressor=Ridge(alpha=.01))
                coefficients = np.zeros(n)
                for token, weight in weights:
                    coefficients[token] = weight
                prediction = expit(intercept + masks @ coefficients)
            fit = float(r2_score(scores[train], prediction[train]))
            fresh = float(r2_score(scores[valid], prediction[valid])) if np.var(scores[valid]) > 1e-10 else None
            error = float(abs(prediction[0] - scores[0]))
            if seed == 42 and not anchored:
                assert abs(fit - reference['fit_r2']) < 1e-6
                assert fresh is not None and abs(fresh - reference['heldout_r2']) < 1e-6
            results.append(dict(id=identifier, label=reference['label'], seed=seed, scale='logodds',
                word_count=n, fit_r2=fit, heldout_r2=fresh, original_score_error=error,
                weights=[dict(token_index=i, weight=float(w)) for i, w in enumerate(coefficients)],
                passes=fit >= .7 and fresh is not None and fresh >= .7 and error <= .01))
    summary = dict(cases=len(expected),
        passes_per_seed={str(s): sum(c['passes'] for c in results if c['seed'] == s) for s in (42, 7, 21)},
        passes_all_seeds=[dict(id=i, label=expected[i]['label']) for i in expected
                          if all(c['passes'] for c in results if c['id'] == i)])
    report = dict(source=str(source), inference_cache_fingerprint=previous['inference_cache_fingerprint'],
        scope=('Anchored all-word logodds Ridge, not standard LIME' if anchored else 'All-word logodds LIME')
              + '; reuses recorded probabilities; validation on raw probabilities after sigmoid',
        limitation='Twenty previously inspected cases. Three disjoint fit/validation partitions of one cached mask pool. '
                   'Partitions overlap across seeds; this is not validation on a new independently generated mask pool.',
        thresholds=dict(r2=.7, max_original_score_error=.01, minimum_probability_variance=1e-10),
        summary=summary, stability=measure_stability(results), cases=results)
    Path(output).write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--anchored', action='store_true')
    parser.add_argument('--output', default='reports/hybrid_lime_full_stability.json')
    args = parser.parse_args()
    evaluate(args.anchored, args.output)
