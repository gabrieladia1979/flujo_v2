"""Check word-index/sign stability for the four favorable locality cases."""
import itertools
import json
from pathlib import Path

import numpy as np

from scripts.probe_lime_locality import run


def evaluate():
    ids = ['row-856', 'row-1131', 'row-2760', 'row-5594']
    seeds = [42, 7, 21]
    reports = {}
    for seed in seeds:
        path = f'reports/hybrid_lime_words_seed{seed}.json'
        run(seed, ids, path)
        reports[seed] = {case['id']: case for case in json.loads(Path(path).read_text())['cases']
                         if case['features'] == 8 and case['alpha'] == 0.01}
    comparisons = []
    for identifier in ids:
        for left, right in itertools.combinations(seeds, 2):
            a, b = reports[left][identifier], reports[right][identifier]
            wa = {w['token_index']: w['weight'] for w in a['word_weights'] if abs(w['weight']) >= 1e-6}
            wb = {w['token_index']: w['weight'] for w in b['word_weights'] if abs(w['weight']) >= 1e-6}
            common, union = wa.keys() & wb.keys(), wa.keys() | wb.keys()
            agreement = sum(np.sign(wa[i]) == np.sign(wb[i]) for i in common)
            comparisons.append(dict(id=identifier, seeds=[left, right],
                shared_words=len(common), union_words=len(union),
                jaccard=len(common) / len(union) if union else None,
                same_sign_shared_words=int(agreement),
                sign_agreement=agreement / len(common) if common else None))
    ablations = []
    for seed in seeds:
        for identifier, case in reports[seed].items():
            usable = [w for w in case['word_weights'] if w['single_deletion_delta'] is not None
                      and abs(w['weight']) >= 1e-6 and abs(w['single_deletion_delta']) >= 1e-6]
            consistent = sum(np.sign(w['weight']) == np.sign(w['single_deletion_delta']) for w in usable)
            ablations.append(dict(id=identifier, seed=seed, comparable_words=len(usable),
                consistent_signs=int(consistent),
                agreement=consistent / len(usable) if usable else None))
    report = dict(scope='eight word indices, Ridge 0.01, four previously favorable cases; no raw email text',
        seeds=seeds, negligible_effect_threshold=1e-6,
        interpretation='Sign agreement on shared words alone does not establish stable explanations. '
                       'Single deletion measures a model response, not causal ground truth. '
                       'This selected sample cannot estimate population reliability.',
        comparisons=comparisons, single_deletion_checks=ablations,
        median_pairwise_jaccard=float(np.median([c['jaccard'] for c in comparisons if c['jaccard'] is not None])))
    Path('reports/hybrid_lime_word_stability.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    evaluate()
