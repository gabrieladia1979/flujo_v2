"""Inventory massive local email sources and create a bounded reproducible mix.

Only configured source/label combinations enter training. Every other file is
inventoried for review. Text and sender addresses are never written to reports.
"""

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import random

FIELDS = ['subject', 'body', 'Label', 'attachments_count', 'hops_count', 'source', 'language', 'source_row', 'observed_at']


def collect_source(path, policy, cap, seed):
    selected = []
    labels = Counter()
    accepted = 0
    rng = random.Random(seed)
    with path.open(encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle)
        columns = reader.fieldnames or []
        if not ('body' in columns or 'text_combined' in columns):
            return [], dict(columns=columns, status='not_email_text')
        label_col = 'Label' if 'Label' in columns else 'label'
        for number, row in enumerate(reader, 2):
            value = row.get(label_col, '')
            labels[value] += 1
            if not policy or value not in policy['labels']:
                continue
            if not (row.get('body') or row.get('text_combined') or row.get('subject')):
                continue
            accepted += 1
            item = dict(subject=row.get('subject') or '', body=row.get('body') or row.get('text_combined') or '',
                        Label=policy['labels'][value], attachments_count=row.get('attachments_count') or 0,
                        hops_count=row.get('hops_count') or 0, source=path.name,
                        language=policy['language'], source_row=number, observed_at=row.get('date') or '')
            if not cap or len(selected) < cap:
                selected.append(item)
            else:
                position = rng.randrange(accepted)
                if position < cap:
                    selected[position] = item
    return selected, dict(columns=columns, rows=sum(labels.values()), labels=dict(labels),
                          eligible=accepted, selected=len(selected), status='sampled' if policy else 'review_required',
                          sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                          mapping_basis=policy['basis'] if policy else 'not approved for this experiment')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--sources-dir', type=Path, required=True)
    parser.add_argument('--config', type=Path, default=Path('data/hybrid_sources.json'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--max-per-source', type=int, default=1000, help='0 uses all eligible records')
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()
    if args.output.exists() or args.max_per_source < 0:
        parser.error('Use a new output path and a nonnegative cap')
    csv.field_size_limit(10_000_000)
    config = json.loads(args.config.read_text(encoding='utf-8'))
    rows, base_audit = collect_source(args.base, {'labels': {'0': '0', '1': '1'}, 'language': 'es', 'basis': 'Existing SpaPhish mapping; language is a source hint, not detected per row'}, 0, args.seed)
    audits = {args.base.name: base_audit}
    policies = {p['file']: p for p in config['sources']}
    seen_files = set()
    for number, path in enumerate(sorted(args.sources_dir.rglob('*.csv'))):
        if not path.is_file():
            continue
        if path.name in seen_files:
            raise ValueError(f'Duplicate source filename: {path.name}')
        seen_files.add(path.name)
        selected, audit = collect_source(path, policies.get(path.name), args.max_per_source, args.seed + number)
        rows.extend(selected)
        audits[path.name] = audit
    missing = set(policies) - seen_files
    if missing:
        raise ValueError(f'Configured sources missing: {sorted(missing)}')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    report = dict(sources=audits, total_output_rows=len(rows), seed=args.seed, cap_per_source=args.max_per_source,
                  dataset_sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
                  warnings=['Rows are sampled, then global duplicates and conflicting groups are removed by the trainer.',
                            'Source labels are inherited, not individually human-verified.',
                            'Source language is a hint; old corpora do not establish coverage of current attacks.'],
                  excluded_policies=config['not_automatically_used'])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps({'output_rows':len(rows), 'selected_by_source':{name:a['selected'] for name,a in audits.items() if 'selected' in a}},indent=2))


if __name__ == '__main__':
    main()
