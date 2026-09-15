"""Prepare an expanded corpus with old splits preserved and new groups reserved."""
import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.hybrid_data import load_training_csv, group_key
from scripts.train_hybrid import write_json
from scripts.build_hybrid_corpus import collect_source


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--full-corpus', type=Path, required=True)
    p.add_argument('--previous-splits', type=Path, required=True)
    p.add_argument('--unseen-ham', type=Path, required=True)
    p.add_argument('--output-dir', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    if a.output_dir.exists():
        raise ValueError('Use a new output directory')
    rows, audit = load_training_csv(a.full_corpus, '1')
    previous = json.loads(a.previous_splits.read_text())
    old_groups = {r['group'] for split in previous.values() for r in split}
    all_groups = {r['group'] for r in rows}
    if not old_groups.issubset(all_groups):
        # Added sources can reveal conflicts in old labels. Never silently change test.
        raise ValueError(f'Expanded corpus lost {len(old_groups-all_groups)} old groups; review conflicts first')
    reserved_groups = {g for g in all_groups-old_groups
                       if int(hashlib.sha256(('reserve-v2:'+g).encode()).hexdigest()[:8], 16) / 2**32 < .15}
    reserved = [r for r in rows if r['group'] in reserved_groups]
    training = [r for r in rows if r['group'] not in reserved_groups]
    a.output_dir.mkdir(parents=True)
    dataset = a.output_dir / 'training.csv'
    fields = ['subject', 'body', 'Label', 'attachments_count', 'hops_count', 'source', 'language']
    with dataset.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in training:
            w.writerow(dict(subject=r['subject'], body=r['body'], Label=r['label'],
                attachments_count=r['metadata']['attachment_count'], hops_count=r['metadata']['received_hop_count'],
                source=r['source'], language=r['language']))
    clean, _ = load_training_csv(dataset, '1')
    ownership = {r['group']: name for name, rr in previous.items() for r in rr}
    splits = {name: [] for name in previous}
    for r in clean:
        splits[ownership.get(r['group'], 'train')].append(dict(id=r['id'], group=r['group']))
    write_json(a.output_dir / 'splits.json', splits)
    # Reserve every eligible new group; evaluate a bounded sample per source.
    sample = []
    for source in sorted({r['source'] for r in reserved}):
        pool = sorted([r for r in reserved if r['source'] == source], key=lambda r: hashlib.sha256(r['text'].encode()).hexdigest())
        seen = set()
        for r in pool:
            if r['group'] in seen:
                continue
            seen.add(r['group']); sample.append(r)
            if len(seen) >= 100:
                break
    unseen, source_audit = collect_source(a.unseen_ham, {'labels': {'0': '0'}, 'language': 'en',
        'basis': 'Inherited ham=0 only; source spam is excluded'}, 0, 42)
    novel_ham = []
    seen = set(all_groups)
    for r in unseen:
        g = group_key(r['subject'], r['body'])
        if g in seen:
            continue
        seen.add(g)
        novel_ham.append(dict(subject=r['subject'], body=r['body'], label=0,
                              source=a.unseen_ham.name, group=g, metadata={}, language='en'))
    sample += sorted(novel_ham, key=lambda r: r['group'])[:100]
    with (a.output_dir / 'external_eval.jsonl').open('w', encoding='utf-8') as f:
        for i, r in enumerate(sample):
            f.write(json.dumps(dict(id=f'external-v2-{i+1:04}', subject=r['subject'], body=r['body'],
                label='phishing' if r['label'] else 'legitimate',
                category='other_phishing' if r['label'] else 'other_legitimate', campaign_id=r['group'],
                security_features=r['metadata'], source=r['source']), ensure_ascii=False)+'\n')
    write_json(a.output_dir / 'reserved_groups.json', sorted(reserved_groups))
    report = dict(full_audit=audit, training_rows=len(clean), reserved_rows=len(reserved),
        reserved_groups=len(reserved_groups), old_groups_preserved=len(old_groups),
        splits={k: len(v) for k,v in splits.items()}, external_evaluation_rows=len(sample),
        external_sources=dict(Counter(r['source'] for r in sample)), unseen_ham_audit=source_audit,
        novel_unseen_ham=len(novel_ham),
        warnings=['Labels are inherited, not individually verified.',
                  'Group exclusion reduces overlap but is not proof of campaign independence.',
                  'Ling ham tests false positives on an unseen source, not phishing recall.',
                  'No verified collection dates: this is not a temporal holdout.'])
    write_json(a.report, report)
    print(json.dumps({k:v for k,v in report.items() if k not in ['full_audit', 'unseen_ham_audit']}, indent=2))


if __name__ == '__main__':
    main()
