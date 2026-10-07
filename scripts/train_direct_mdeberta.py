"""Fine-tune mDeBERTa as a direct phishing/legitimate text classifier.

Uses the same audited corpus and group split as the hybrid v3 experiment.
No XGBoost, technical feature vector, rules, or production endpoint is involved.
"""

import argparse
import importlib.metadata
import json
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import log_loss
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from scripts.hybrid_data import load_training_csv
from scripts.direct_eval import exact_saved_splits, score_metrics, threshold_on_validation


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def head_tail_ids(tokenizer, text, capacity):
    ids = tokenizer(text, add_special_tokens=True, truncation=False)['input_ids']
    if len(ids) > capacity:
        left = capacity // 2
        ids = ids[:left] + ids[-(capacity - left):]
    return ids


class EmailDataset(Dataset):
    def __init__(self, token_ids, labels, indices):
        self.token_ids = token_ids
        self.labels = labels
        self.indices = indices

    def __len__(self):
        return len(self.indices)

    def __getitem__(self, index):
        row = self.indices[index]
        return {'input_ids': self.token_ids[row], 'label': int(self.labels[row])}


def make_loader(dataset, tokenizer, batch_size, shuffle):
    def collate(items):
        features = tokenizer.pad([{'input_ids': item['input_ids']} for item in items],
                                 padding=True, return_tensors='pt')
        features['labels'] = torch.tensor([item['label'] for item in items], dtype=torch.long)
        return features
    return DataLoader(dataset, batch_size=batch_size, shuffle=shuffle, collate_fn=collate)


def predict(model, loader, device):
    model.eval()
    scores = []
    with torch.inference_mode():
        for batch in loader:
            labels = batch.pop('labels')
            del labels
            inputs = {key: value.to(device) for key, value in batch.items()}
            logits = model(**inputs).logits
            scores.extend(torch.softmax(logits, dim=1)[:, 1].cpu().tolist())
    return np.asarray(scores)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--previous-splits', required=True, type=Path)
    parser.add_argument('--expected-dataset-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--base-model', default='microsoft/mdeberta-v3-base')
    parser.add_argument('--revision', default='main')
    parser.add_argument('--phishing-label', choices=['0', '1'], default='1')
    parser.add_argument('--epochs', type=int, default=4)
    parser.add_argument('--batch-size', type=int, default=8)
    parser.add_argument('--gradient-accumulation', type=int, default=4)
    parser.add_argument('--max-tokens', type=int, default=384)
    parser.add_argument('--learning-rate', type=float, default=2e-5)
    parser.add_argument('--max-fpr', type=float, default=0.02)
    parser.add_argument('--max-steps', type=int, default=0,
                        help='For smoke runs; the resulting report is marked incomplete')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--device', choices=['cpu', 'cuda'], default='cuda')
    parser.add_argument('--threads', type=int, default=4)
    args = parser.parse_args()
    if (args.epochs < 1 or args.batch_size < 1 or args.gradient_accumulation < 1
            or args.max_tokens < 8 or args.max_steps < 0 or not 0 <= args.max_fpr < 1):
        parser.error('Invalid training configuration')
    if args.device == 'cuda' and not torch.cuda.is_available():
        parser.error('CUDA requested but unavailable')
    if args.output.exists() and any(args.output.iterdir()):
        parser.error('Output directory is not empty')

    started = time.perf_counter()
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    torch.set_num_threads(args.threads)
    rows, audit = load_training_csv(args.dataset, args.phishing_label)
    if audit['dataset_sha256'] != args.expected_dataset_sha256:
        parser.error('Dataset hash differs from the comparison corpus')
    previous = json.loads(args.previous_splits.read_text(encoding='utf-8'))
    splits = exact_saved_splits(rows, previous)
    labels = np.asarray([row['label'] for row in rows], dtype=np.int64)
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, revision=args.revision,
                                               trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model, revision=args.revision, num_labels=2,
        id2label={0: 'legitimate', 1: 'phishing'},
        label2id={'legitimate': 0, 'phishing': 1}, trust_remote_code=False
    ).to(args.device)
    token_ids = [head_tail_ids(tokenizer, row['text'], args.max_tokens) for row in rows]
    loaders = {name: make_loader(EmailDataset(token_ids, labels, ids), tokenizer,
                                 args.batch_size, name == 'train')
               for name, ids in splits.items()}
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate, weight_decay=0.01)
    history = []
    best_loss = float('inf')
    best_weights = None
    steps = 0
    for epoch in range(args.epochs):
        model.train()
        losses = []
        optimizer.zero_grad()
        total_batches = len(loaders['train'])
        for batch_number, batch in enumerate(loaders['train'], 1):
            batch = {key: value.to(args.device) for key, value in batch.items()}
            loss = model(**batch).loss
            (loss / args.gradient_accumulation).backward()
            losses.append(float(loss.detach()))
            if batch_number % args.gradient_accumulation == 0 or batch_number == total_batches:
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                optimizer.zero_grad()
                steps += 1
                if steps % 20 == 0:
                    print(f'epoch={epoch + 1} optimizer_step={steps} loss={np.mean(losses[-20:]):.4f}', flush=True)
                if args.max_steps and steps >= args.max_steps:
                    break
        validation = predict(model, loaders['validation'], args.device)
        validation_loss = float(log_loss(labels[splits['validation']], validation, labels=[0, 1]))
        history.append({'epoch': epoch + 1, 'optimizer_steps': steps,
                        'train_loss': float(np.mean(losses)), 'validation_loss': validation_loss})
        print(json.dumps(history[-1]), flush=True)
        if validation_loss < best_loss:
            best_loss = validation_loss
            best_weights = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
        if args.max_steps and steps >= args.max_steps:
            break

    model.load_state_dict(best_weights)
    validation = predict(model, loaders['validation'], args.device)
    threshold = threshold_on_validation(labels[splits['validation']], validation, args.max_fpr)
    test = predict(model, loaders['test'], args.device)
    results = {'validation': score_metrics(labels[splits['validation']], validation, threshold),
               'test': score_metrics(labels[splits['test']], test, threshold)}
    args.output.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(args.output, safe_serialization=True)
    tokenizer.save_pretrained(args.output)
    write_json(args.output / 'experiment_manifest.json', {
        'model_type': 'direct_sequence_classifier', 'base_model': args.base_model,
        'base_revision': args.revision, 'resolved_base_commit': model.config._commit_hash,
        'class_mapping': {'0': 'legitimate', '1': 'phishing'},
        'threshold': threshold, 'max_tokens': args.max_tokens,
        'token_selection': 'head_tail', 'dataset_sha256': audit['dataset_sha256'],
        'status': 'incomplete_smoke' if args.max_steps else 'experimental_not_promoted',
    })
    report = {'configuration': {key: str(value) if isinstance(value, Path) else value
                                for key, value in vars(args).items()},
              'dataset_audit': audit,
              'split_counts': {name: len(ids) for name, ids in splits.items()},
              'history': history, 'threshold': threshold, 'results': results,
              'test_predictions': [{'id': rows[i]['id'], 'label': int(labels[i]), 'score': float(score)}
                                   for i, score in zip(splits['test'], test)],
              'elapsed_seconds': time.perf_counter() - started,
              'environment': {name: importlib.metadata.version(name)
                              for name in ('torch', 'transformers', 'scikit-learn')},
              'limitations': ['Shared grouped holdout permits paired comparison but not external validation.',
                              'Threshold chosen only on validation.',
                              'Scores are not calibrated probabilities.',
                              'Corpus labels and campaign provenance need independent audit.']}
    write_json(args.report, report)
    cm = results['test']['confusion_matrix']
    print(f"test F1={results['test']['f1_phishing']:.6f} FP={cm['false_positive']} FN={cm['false_negative']} threshold={threshold:.6f}", flush=True)
    print(f'report={args.report} artifact={args.output}', flush=True)


if __name__ == '__main__':
    main()
