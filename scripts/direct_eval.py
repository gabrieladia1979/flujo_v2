"""Validation threshold and test metrics shared by direct-classifier trials."""

import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score


def threshold_on_validation(labels, scores, max_fpr):
    labels = np.asarray(labels)
    scores = np.asarray(scores)
    if set(labels.tolist()) != {0, 1}:
        raise ValueError('Validation must contain both classes')
    candidates = np.unique(np.concatenate(([0.5, 1.0], scores)))
    feasible = []
    for threshold in candidates:
        predicted = scores >= threshold
        fpr = float(predicted[labels == 0].mean())
        recall = float(predicted[labels == 1].mean())
        if fpr <= max_fpr:
            feasible.append((recall, -fpr, float(threshold)))
    if not feasible:
        raise ValueError('No threshold meets the validation false-positive constraint')
    return max(feasible)[2]


def score_metrics(labels, scores, threshold):
    labels = np.asarray(labels)
    scores = np.asarray(scores)
    predicted = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, predicted, labels=[0, 1]).ravel()
    return {
        'precision_phishing': float(precision_score(labels, predicted, zero_division=0)),
        'recall_phishing': float(recall_score(labels, predicted, zero_division=0)),
        'f1_phishing': float(f1_score(labels, predicted, zero_division=0)),
        'roc_auc': float(roc_auc_score(labels, scores)),
        'average_precision': float(average_precision_score(labels, scores)),
        'confusion_matrix': {'true_positive': int(tp), 'true_negative': int(tn),
                             'false_positive': int(fp), 'false_negative': int(fn)},
    }


def exact_saved_splits(rows, previous):
    """Reuse evaluated row IDs, then reject missing rows or cross-split groups."""
    by_id = {row['id']: index for index, row in enumerate(rows)}
    if len(by_id) != len(rows):
        raise ValueError('Duplicate row IDs in corpus')
    splits = {}
    seen_ids = set()
    group_sets = []
    for name in ('train', 'validation', 'test'):
        items = previous[name]
        ids = [item['id'] for item in items]
        if len(ids) != len(set(ids)) or seen_ids.intersection(ids):
            raise ValueError('Saved split has duplicated row IDs')
        if any(row_id not in by_id for row_id in ids):
            raise ValueError(f'Saved {name} split contains unknown row IDs')
        indices = np.asarray([by_id[row_id] for row_id in ids], dtype=int)
        if {rows[i]['label'] for i in indices} != {0, 1}:
            raise ValueError(f'Saved {name} split must contain both classes')
        splits[name] = indices
        seen_ids.update(ids)
        group_sets.append({rows[i]['group'] for i in indices})
    if seen_ids != set(by_id):
        raise ValueError('Saved split does not cover exactly the audited corpus')
    if any(group_sets[i] & group_sets[j] for i in range(3) for j in range(i)):
        raise ValueError('Current grouping finds a cross-split duplicate')
    return splits
