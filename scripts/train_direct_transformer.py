"""Train a direct MiniLM email classifier on the existing grouped corpus.

The saved neural head replaces XGBoost. Validation selects the checkpoint and
decision threshold; the held-out test is scored only after both are fixed.
"""

import argparse
import copy
import hashlib
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
from sentence_transformers import SentenceTransformer
from sklearn.metrics import log_loss

from scripts.hybrid_data import load_training_csv
from scripts.direct_eval import exact_saved_splits, score_metrics, threshold_on_validation
from services.hybrid_encoder import embed, tokenize_texts


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def evaluate(encoder, head, texts, ids, batch_size, cached=None):
    encoder.eval()
    head.eval()
    with torch.inference_mode():
        vectors = cached[ids] if cached is not None else embed(
            encoder, [texts[i] for i in ids], batch_size
        )
        scores = []
        for start in range(0, len(ids), batch_size):
            batch = torch.as_tensor(vectors[start:start + batch_size], device=encoder.device)
            scores.extend(torch.softmax(head(batch), dim=1)[:, 1].cpu().tolist())
    return np.asarray(scores)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--previous-splits', required=True, type=Path)
    parser.add_argument('--base-model', required=True,
                        help='Pretrained MiniLM ID or a local SentenceTransformer encoder')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--expected-dataset-sha256', required=True)
    parser.add_argument('--phishing-label', choices=['0', '1'], default='1')
    parser.add_argument('--epochs', type=int, default=5)
    parser.add_argument('--batch-size', type=int, default=64)
    parser.add_argument('--max-tokens', type=int, default=384)
    parser.add_argument('--trainable-layers', type=int, default=0,
                        help='0 trains only the direct head; >0 also fine-tunes the last Transformer layers')
    parser.add_argument('--learning-rate', type=float, default=2e-5)
    parser.add_argument('--head-learning-rate', type=float, default=1e-3)
    parser.add_argument('--max-steps', type=int, default=0,
                        help='Training smoke runs only; reports are marked incomplete')
    parser.add_argument('--max-fpr', type=float, default=0.02)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--device', choices=['cpu', 'cuda'], default='cpu')
    parser.add_argument('--threads', type=int, default=4)
    args = parser.parse_args()
    if (args.epochs < 1 or args.batch_size < 1 or args.max_tokens < 8
            or args.trainable_layers < 0 or args.max_steps < 0
            or not 0 <= args.max_fpr < 1):
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
        parser.error('Dataset hash differs from the intended comparison corpus')
    previous = json.loads(args.previous_splits.read_text(encoding='utf-8'))
    splits = exact_saved_splits(rows, previous)
    texts = [r['text'] for r in rows]
    labels = np.asarray([r['label'] for r in rows], dtype=np.int64)
    encoder = SentenceTransformer(args.base_model, device=args.device, trust_remote_code=False)
    encoder.max_seq_length = args.max_tokens
    for parameter in encoder.parameters():
        parameter.requires_grad = False
    if args.trainable_layers:
        layers = encoder[0].auto_model.encoder.layer
        if args.trainable_layers > len(layers):
            parser.error('More trainable layers requested than the encoder contains')
        for layer in layers[-args.trainable_layers:]:
            for parameter in layer.parameters():
                parameter.requires_grad = True
    head = torch.nn.Linear(encoder.get_sentence_embedding_dimension(), 2).to(encoder.device)
    parameters = [p for p in encoder.parameters() if p.requires_grad]
    optimizer = torch.optim.AdamW([
        {'params': parameters, 'lr': args.learning_rate},
        {'params': head.parameters(), 'lr': args.head_learning_rate},
    ], weight_decay=0.01)
    cached = embed(encoder, texts, args.batch_size) if not parameters else None
    rng = np.random.default_rng(args.seed)
    history = []
    best_loss = float('inf')
    best_encoder = None
    best_head = None
    steps = 0
    for epoch in range(args.epochs):
        ids = rng.permutation(splits['train'])
        encoder.train() if parameters else encoder.eval()
        head.train()
        losses = []
        for start in range(0, len(ids), args.batch_size):
            batch_ids = ids[start:start + args.batch_size]
            if cached is None:
                features = tokenize_texts(encoder, [texts[i] for i in batch_ids])
                vectors = F.normalize(encoder(features)['sentence_embedding'], dim=1)
            else:
                vectors = torch.as_tensor(cached[batch_ids], device=encoder.device)
            loss = F.cross_entropy(head(vectors), torch.as_tensor(labels[batch_ids], device=encoder.device))
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(parameters + list(head.parameters()), 1.0)
            optimizer.step()
            losses.append(float(loss.detach()))
            steps += 1
            if steps % 20 == 0:
                print(f'epoch={epoch + 1} step={steps} loss={np.mean(losses[-20:]):.4f}', flush=True)
            if args.max_steps and steps >= args.max_steps:
                break
        validation_scores = evaluate(encoder, head, texts, splits['validation'], args.batch_size, cached)
        validation_loss = float(log_loss(labels[splits['validation']], validation_scores, labels=[0, 1]))
        history.append({'epoch': epoch + 1, 'steps': steps, 'train_loss': float(np.mean(losses)),
                        'validation_loss': validation_loss})
        print(json.dumps(history[-1]), flush=True)
        if validation_loss < best_loss:
            best_loss = validation_loss
            best_head = copy.deepcopy(head.state_dict())
            best_encoder = copy.deepcopy(encoder.state_dict()) if parameters else None
        if args.max_steps and steps >= args.max_steps:
            break

    if best_encoder is not None:
        encoder.load_state_dict(best_encoder)
    head.load_state_dict(best_head)
    validation_scores = evaluate(encoder, head, texts, splits['validation'], args.batch_size, cached)
    threshold = threshold_on_validation(labels[splits['validation']], validation_scores, args.max_fpr)
    test_scores = evaluate(encoder, head, texts, splits['test'], args.batch_size, cached)
    result = {'validation': score_metrics(labels[splits['validation']], validation_scores, threshold),
              'test': score_metrics(labels[splits['test']], test_scores, threshold)}
    args.output.mkdir(parents=True, exist_ok=True)
    encoder.save(str(args.output / 'encoder'))
    torch.save(head.cpu().state_dict(), args.output / 'head.pt')
    head_hash = hashlib.sha256((args.output / 'head.pt').read_bytes()).hexdigest()
    manifest = {'model_type': 'MiniLM_sentence_embeddings_plus_linear_head',
                'encoder_source': args.base_model, 'head_sha256': head_hash,
                'class_mapping': {'0': 'legitimate', '1': 'phishing'},
                'threshold': threshold, 'max_tokens': args.max_tokens,
                'token_selection': 'head_tail', 'embedding_normalization': 'l2',
                'dataset_sha256': audit['dataset_sha256'],
                'status': 'incomplete_smoke' if args.max_steps else 'experimental_not_promoted'}
    write_json(args.output / 'manifest.json', manifest)
    report = {'configuration': {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
              'dataset_audit': audit,
              'split_counts': {name: len(ids) for name, ids in splits.items()},
              'history': history, 'threshold': threshold, 'results': result,
              'test_predictions': [{'id': rows[i]['id'], 'label': int(labels[i]), 'score': float(score)}
                                   for i, score in zip(splits['test'], test_scores)],
              'elapsed_seconds': time.perf_counter() - started,
              'environment': {name: importlib.metadata.version(name)
                              for name in ('torch', 'transformers', 'sentence-transformers', 'scikit-learn')},
              'limitations': ['Same grouped holdout as hybrid v3; shared test supports a paired comparison, not external validation.',
                              'Threshold chosen on validation only.',
                              'Probabilities are not calibrated.',
                              'Labels and campaign provenance have not been independently audited.']}
    write_json(args.report, report)
    cm = result['test']['confusion_matrix']
    print(f"test F1={result['test']['f1_phishing']:.6f} FP={cm['false_positive']} FN={cm['false_negative']} threshold={threshold:.6f}", flush=True)
    print(f'report={args.report} artifact={args.output}', flush=True)


if __name__ == '__main__':
    main()
