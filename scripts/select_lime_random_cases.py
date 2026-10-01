"""Freeze a stratified, previously unused corpus sample for LIME experiments."""
import argparse
import csv
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path


def select(output='reports/hybrid_lime_random_selection.json', seed=20261001, per_stratum=5):
    splits_path = Path('artifacts/hybrid/corpus-v3/splits.json')
    test_ids = {item['id'] for item in json.loads(splits_path.read_text())['test']}
    exclusions = set()
    for name in ('hybrid_lime_diagnostic_v1.json', 'hybrid_lime_locality_fresh.json',
                 'hybrid_lime_locality_probe.json'):
        path = Path('reports') / name
        if path.exists():
            exclusions.update(case['id'] for case in json.loads(path.read_text())['cases'])
    strata = defaultdict(list)
    csv.field_size_limit(10_000_000)
    dataset = Path('artifacts/hybrid/corpus-v3/training.csv')
    with dataset.open(encoding='utf-8-sig', newline='') as source:
        for line, row in enumerate(csv.DictReader(source), 2):
            identifier = f'row-{line}'
            if identifier in test_ids and identifier not in exclusions and 120 <= len(row['body']) <= 1000:
                strata[(row['Label'], row['language'])].append(identifier)
    rng = random.Random(seed)
    cases = [dict(id=identifier, label=label, language=language)
             for (label, language), available in sorted(strata.items())
             for identifier in rng.sample(available, min(per_stratum, len(available)))]
    counts = Counter((case['label'], case['language']) for case in cases)
    if len(counts) != 4 or any(counts[stratum] != per_stratum for stratum in counts):
        raise ValueError(f'Could not balance the four label/language strata: {dict(counts)}')
    report = dict(selection_seed=seed, per_stratum=per_stratum,
        criteria='Saved test IDs; body 120-1000 characters; excludes all previous 20-case LIME selections; '
                 'five randomly selected IDs per label/source-language stratum; IDs frozen before model evaluation.',
        excluded_previous_cases=sorted(exclusions),
        sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (dataset, splits_path)},
        cases=cases)
    Path(output).write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'cases'}, indent=2))
    print(json.dumps(cases, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='reports/hybrid_lime_random_selection.json')
    parser.add_argument('--seed', type=int, default=20261001)
    parser.add_argument('--per-stratum', type=int, default=5)
    args = parser.parse_args()
    select(args.output, args.seed, args.per_stratum)
