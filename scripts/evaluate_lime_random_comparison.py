"""Compare full-vocabulary LIME and anchored Ridge on a frozen random sample."""
import argparse
import csv
import hashlib
import json
import math
import random
import os
from collections import Counter
from pathlib import Path

import numpy as np
from lime.lime_base import LimeBase
from lime.lime_text import IndexedString
from scipy.special import expit, logit
from sklearn.linear_model import Ridge
from sklearn.metrics import r2_score
from xgboost import DMatrix

from scripts.hybrid_lime_cache import inference_fingerprint
from services.hybrid_classifier import HybridClassifier
from services.hybrid_encoder import embed
from services.hybrid_features import encoder_text, technical_features


def evaluate(selection_path, output, training_samples=768, validation_samples=128, seeds=(101, 202)):
    selection_path = Path(selection_path)
    selection = json.loads(selection_path.read_text())
    wanted = {case['id']: case for case in selection['cases']}
    csv.field_size_limit(10_000_000)
    with Path('artifacts/hybrid/corpus-v3/training.csv').open(encoding='utf-8-sig', newline='') as source:
        rows = {f'row-{i}': row for i, row in enumerate(csv.DictReader(source), 2) if f'row-{i}' in wanted}
    if set(rows) != set(wanted):
        raise ValueError('The frozen random sample is missing cases from the local corpus')
    for identifier, row in rows.items():
        if (row['Label'], row['language']) != (wanted[identifier]['label'], wanted[identifier]['language']):
            raise ValueError('The frozen sample labels or language strata have changed')

    model_path = Path('artifacts/hybrid/multilingual-candidate-v3-curated')
    dataset_path = Path('artifacts/hybrid/corpus-v3/training.csv')
    classifier = HybridClassifier(model_path)
    fingerprint = inference_fingerprint(model_path, dataset_path, classifier.encoder.device)
    results, cache_hits = [], 0
    inference_cache = Path('artifacts/hybrid/lime-random-cache')
    inference_cache.mkdir(parents=True, exist_ok=True)
    for identifier, row in rows.items():
        indexed = IndexedString(row['body'])
        n = indexed.num_words()
        target = max(training_samples, 1 + 3 * n)
        body_masks, body_scores, validation_ranges = [], [], {}
        seen = {frozenset(), *(frozenset([i]) for i in range(n))}
        for seed in seeds:
            rng = random.Random(seed)
            train, valid = [], []
            attempts = 0
            while len(train) < target or len(valid) < validation_samples:
                attempts += 1
                if attempts > 100_000:
                    raise ValueError(f'Unable to generate unseen masks for {identifier}')
                removed = frozenset(rng.sample(range(n), rng.randint(2, 3)))
                if removed in seen:
                    continue
                seen.add(removed)
                (train if len(train) < target else valid).append(removed)
            masks = np.ones((target + validation_samples, n))
            for i, deleted in enumerate(train + valid):
                masks[i, list(deleted)] = 0
            key = f'{identifier}-{training_samples}-{validation_samples}-{seed}.npz'
            cache_path = inference_cache / key
            scores = None
            if cache_path.exists():
                with np.load(cache_path, allow_pickle=False) as cache:
                    if str(cache['fingerprint']) == fingerprint and np.array_equal(cache['masks'], masks):
                        scores = cache['scores'].copy()
                        cache_hits += 1
            if scores is None:
                deleted_masks = train + valid
                bodies = [indexed.inverse_removing(sorted(deleted)) for deleted in deleted_masks]
                attachments = int(float(row.get('attachments_count') or 0))
                hops = int(float(row.get('hops_count') or 0))
                features = np.asarray([technical_features(row['subject'], body, attachments, hops)
                                       for body in bodies], dtype=np.float32)
                with classifier.lock:
                    vectors = embed(classifier.encoder, [encoder_text(row['subject'], body) for body in bodies])
                    scores = classifier.head.predict(DMatrix(np.hstack([vectors, features]))).astype(float)
                temporary = cache_path.with_name(f'{cache_path.stem}.{os.getpid()}.tmp.npz')
                np.savez_compressed(temporary, fingerprint=fingerprint, masks=masks, scores=scores)
                temporary.replace(cache_path)
            if scores.shape != (target + validation_samples,) or not np.isfinite(scores).all() or ((scores < 0) | (scores > 1)).any():
                raise ValueError(f'Invalid probabilities in {identifier}, seed {seed}')
            body_masks.append(masks)
            body_scores.append(scores)
            validation_ranges[seed] = (target, validation_samples)

        for seed, masks, scores in zip(seeds, body_masks, body_scores):
            target, _ = validation_ranges[seed]
            distance = (1 - np.sqrt(masks[:target].sum(axis=1) / n)) * 100
            logit_targets = logit(np.clip(scores[:target], 1e-6, 1 - 1e-6))
            lime_intercept, lime_weights, _, _ = LimeBase(
                lambda d: np.sqrt(np.exp(-d ** 2 / 25 ** 2)), random_state=seed).explain_instance_with_data(
                    masks[:target], np.column_stack((np.zeros(target), logit_targets)), distance, 1, n,
                    model_regressor=Ridge(alpha=.01))
            lime_coef = np.zeros(n)
            for token, weight in lime_weights:
                lime_coef[token] = weight
            anchor = Ridge(alpha=.01, fit_intercept=False).fit(
                (1 - masks[:target]), float(logit(np.clip(scores[0], 1e-6, 1-1e-6))) - logit_targets,
                sample_weight=np.sqrt(np.exp(-distance ** 2 / 25 ** 2)))
            methods = {
                'lime_logodds': expit(lime_intercept + masks @ lime_coef),
                'anchored_logodds_ridge': expit(float(logit(np.clip(scores[0], 1e-6, 1-1e-6))) - (1-masks) @ anchor.coef_),
            }
            for method, prediction in methods.items():
                actual = scores[target:]
                variance_sum = float(np.square(actual - actual.mean()).sum())
                heldout = float(r2_score(actual, prediction[target:])) if variance_sum > 1e-10 else None
                fit = float(r2_score(scores[:target], prediction[:target]))
                error = float(abs(prediction[0] - scores[0]))
                passes = fit >= .7 and heldout is not None and heldout >= .7 and error <= .01
                results.append(dict(id=identifier, label=row['Label'], language=row['language'],
                    seed=seed, method=method, word_count=n, training_samples=target,
                    validation_samples=validation_samples, fit_r2=fit, heldout_r2=heldout,
                    original_score_error=error, mae=float(np.mean(np.abs(actual - prediction[target:]))),
                    passes=passes))
        print(identifier, flush=True)

    methods = ('lime_logodds', 'anchored_logodds_ridge')
    summary = []
    for method in methods:
        group = [case for case in results if case['method'] == method]
        summary.append(dict(method=method, cases=len(rows), passes_per_seed={
            str(seed): sum(c['passes'] for c in group if c['seed'] == seed) for seed in seeds},
            passes_all_seeds=sum(all(c['passes'] for c in group if c['id'] == identifier)
                                 for identifier in rows),
            median_heldout_r2_by_seed={str(seed): float(np.median([c['heldout_r2'] for c in group
                if c['seed'] == seed and c['heldout_r2'] is not None])) for seed in seeds}))
    paired = []
    for identifier, reference in wanted.items():
        for seed in seeds:
            cells = {c['method']: c for c in results if c['id'] == identifier and c['seed'] == seed}
            paired.append(dict(id=identifier, label=reference['label'], language=reference['language'], seed=seed,
                lime_passes=cells['lime_logodds']['passes'], anchored_passes=cells['anchored_logodds_ridge']['passes'],
                heldout_r2_delta=cells['anchored_logodds_ridge']['heldout_r2'] - cells['lime_logodds']['heldout_r2']
                    if cells['anchored_logodds_ridge']['heldout_r2'] is not None and cells['lime_logodds']['heldout_r2'] is not None else None))
    report = dict(scope='Frozen stratified sample; standard all-word logodds LIME vs anchored Ridge on identical masks/scores',
        selection=str(selection_path), selection_sha256=hashlib.sha256(selection_path.read_bytes()).hexdigest(),
        inference_cache_fingerprint=fingerprint, inference_cache_hits=cache_hits,
        sampling=dict(training_samples=training_samples, validation_samples=validation_samples,
            training_seeds=list(seeds), validation_threshold='SSE probability variance > 1e-10',
            fit_validation_masks_disjoint=True,
            second_seed_excludes_all_first_seed_new_masks=True,
            original_and_all_single_word_masks_are_shared=True,
            number_of_classes=len(rows), strata={f'{k[0]}-{k[1]}': v for k, v in sorted(Counter((r['label'],r['language']) for r in selection['cases']).items())}),
        caution='One independent email sample from the same saved test split, 20 cases total. '
                'The small selected-case experiments informed this comparison. This does not validate end-user utility or deployment.',
        sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (dataset_path, Path('artifacts/hybrid/corpus-v3/splits.json'), model_path/'manifest.json')},
        summary=summary, paired=paired, cases=results)
    Path(output).write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', default='reports/hybrid_lime_random_selection.json')
    parser.add_argument('--output', default='reports/hybrid_lime_random_comparison.json')
    parser.add_argument('--training-samples', type=int, default=768)
    parser.add_argument('--validation-samples', type=int, default=128)
    parser.add_argument('--seeds', nargs='+', type=int, default=[303, 404])
    args = parser.parse_args()
    if args.training_samples < 256 or args.validation_samples < 32 or len(set(args.seeds)) != len(args.seeds):
        parser.error('Need at least 256 fit and 32 validation samples, with unique seeds')
    evaluate(args.selection, args.output, args.training_samples, args.validation_samples, tuple(args.seeds))
