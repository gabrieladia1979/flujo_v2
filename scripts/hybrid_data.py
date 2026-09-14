"""Audit local CSV and split normalized body/template groups before any fit."""

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.model_selection import GroupShuffleSplit

from services.hybrid_features import encoder_text, normalized, prepare_email, URL_PATTERN


def group_key(subject, body):
    visible, _ = prepare_email('', body)
    text = normalized(visible or subject)
    text = URL_PATTERN.sub(' URL ', text)
    text = re.sub(r'\b[^\s@]+@[^\s@]+\b', ' EMAIL ', text)
    text = re.sub(r'\d+', ' NUM ', text)
    text = re.sub(r'[^a-z\s]', ' ', text)
    return hashlib.sha256(re.sub(r'\s+', ' ', text).strip().encode()).hexdigest()


def load_training_csv(path, phishing_label):
    csv.field_size_limit(10_000_000)
    path = Path(path)
    rows = []
    groups = defaultdict(set)
    seen = set()
    skipped = Counter()
    with path.open(encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle)
        if not {'subject', 'body', 'Label'}.issubset(reader.fieldnames or []):
            raise ValueError('Dataset must contain subject, body and Label')
        for line, row in enumerate(reader, 2):
            if row['Label'] not in {'0', '1'}:
                raise ValueError(f'Unknown label at line {line}')
            if len(row['body']) > 1_000_000 or len(row['subject']) > 1000:
                skipped['exceeds_api_limits'] += 1
                continue
            text = encoder_text(row['subject'], row['body'])
            if not text:
                skipped['empty'] += 1
                continue
            label = int(row['Label'] == str(phishing_label))
            group = group_key(row['subject'], row['body'])
            groups[group].add(label)
            identity = hashlib.sha256(text.lower().encode()).hexdigest()
            if (identity, label) in seen:
                skipped['duplicates'] += 1
                continue
            seen.add((identity, label))
            metadata = {}
            for source, target in [('attachments_count', 'attachment_count'), ('hops_count', 'received_hop_count')]:
                value = float(row.get(source) or 0)
                if not np.isfinite(value) or value < 0 or value != int(value):
                    raise ValueError(f'Invalid {source} at line {line}')
                metadata[target] = int(value)
            rows.append(dict(id=f'row-{line}', subject=row['subject'], body=row['body'],
                             text=text, label=label, group=group, metadata=metadata,
                             source=row.get('source') or path.name, language=row.get('language') or 'unknown'))
    conflicting = {key for key, values in groups.items() if len(values) > 1}
    clean = [row for row in rows if row['group'] not in conflicting]
    skipped['conflicting_group_rows'] = len(rows) - len(clean)
    audit = dict(dataset_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                 source_rows=len(rows) + skipped['empty'] + skipped['duplicates'] + skipped['exceeds_api_limits'],
                 usable_rows=len(clean), groups=len({r['group'] for r in clean}),
                 label_counts=dict(Counter(r['label'] for r in clean)), skipped=dict(skipped),
                 source_phishing_label=str(phishing_label),
                 grouping='normalized body without URLs/numbers; fallback to subject for empty body',
                 warnings=['Campaign IDs and training provenance are unavailable. Grouping reduces but does not prove absence of leakage.',
                           'Existing legacy pickle may have seen these records; its metrics are not independent holdout performance.'])
    return clean, audit


def _split(indices, rows, test_size, seed):
    labels = np.array([rows[i]['label'] for i in indices])
    groups = np.array([rows[i]['group'] for i in indices])
    best = None
    for train, test in GroupShuffleSplit(n_splits=32, test_size=test_size, random_state=seed).split(indices, labels, groups):
        if len(set(labels[train])) < 2 or len(set(labels[test])) < 2:
            continue
        error = abs(len(test) / len(indices) - test_size) + abs(labels[test].mean() - labels.mean())
        if best is None or error < best[0]:
            best = (error, indices[train], indices[test])
    if best is None:
        raise ValueError('Need enough independent groups of both classes for splitting')
    return best[1], best[2]


def grouped_split(rows, seed=42, previous=None):
    if previous is not None:
        ownership = {}
        for name in ('train', 'validation', 'test'):
            for item in previous[name]:
                group = item['group']
                if group in ownership and ownership[group] != name:
                    raise ValueError('Previous split contains overlapping groups')
                ownership[group] = name
        splits = {'train': [], 'validation': [], 'test': []}
        for index, row in enumerate(rows):
            group = row['group']
            if group not in ownership:
                bucket = int(hashlib.sha256(f'{seed}:{group}'.encode()).hexdigest()[:8], 16) / 2**32
                ownership[group] = 'train' if bucket < 0.7 else 'validation' if bucket < 0.85 else 'test'
            splits[ownership[group]].append(index)
        for name, ids in splits.items():
            if {rows[i]['label'] for i in ids} != {0, 1}:
                raise ValueError(f'Partition {name} must contain both classes')
        return {name: np.array(ids, dtype=int) for name, ids in splits.items()}
    trainval, test = _split(np.arange(len(rows)), rows, 0.15, seed)
    train, val = _split(trainval, rows, 0.15 / 0.85, seed + 1)
    splits = {'train': train, 'validation': val, 'test': test}
    sets = [{rows[i]['group'] for i in ids} for ids in splits.values()]
    assert all(not sets[i] & sets[j] for i in range(3) for j in range(i))
    return splits
