"""Train neural + XGBoost candidates locally without replacing the legacy model.

Split groups first, fit only on train, choose thresholds on validation, report
test once. The optional legacy pickle is not used to claim holdout performance.
"""

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import log_loss
from xgboost import XGBClassifier

from scripts.hybrid_data import load_training_csv, grouped_split
from scripts.evaluate_classifier import calculate_metrics
from services.hybrid_features import FEATURE_NAMES, FEATURE_VERSION, technical_features
from services.hybrid_encoder import embed, tokenize_texts


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def threshold_on_validation(labels, scores, max_fpr):
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
    return calculate_metrics(['phishing' if y else 'legitimate' for y in labels],
                             ['phishing' if s >= threshold else 'legitimate' for s in scores], scores)


def fit_head(features, labels, splits, seed, output, name, max_fpr):
    model = XGBClassifier(n_estimators=180, max_depth=4, learning_rate=0.06,
                          subsample=0.85, colsample_bytree=0.85, reg_lambda=2,
                          objective='binary:logistic', eval_metric='logloss',
                          tree_method='hist', n_jobs=4, random_state=seed)
    model.fit(features[splits['train']], labels[splits['train']])
    validation = model.predict_proba(features[splits['validation']])[:, list(model.classes_).index(1)]
    threshold = threshold_on_validation(labels[splits['validation']], validation, max_fpr)
    test_scores = model.predict_proba(features[splits['test']])[:, list(model.classes_).index(1)]
    # Native JSON avoids pickle and sklearn-wrapper serialization differences.
    model.get_booster().save_model(output / f'{name}.json')
    return dict(threshold=threshold,
                validation=score_metrics(labels[splits['validation']], validation, threshold),
                test=score_metrics(labels[splits['test']], test_scores, threshold),
                test_scores=test_scores.tolist()), model


def fine_tune(encoder, texts, labels, train_ids, validation_ids, args, output):
    import torch
    import torch.nn.functional as F
    torch.manual_seed(args.seed)
    for parameter in encoder.parameters():
        parameter.requires_grad = False
    transformer = encoder[0].auto_model
    layers = transformer.encoder.layer
    if not 1 <= args.trainable_layers <= len(layers):
        raise ValueError('Invalid trainable layer count')
    for layer in layers[-args.trainable_layers:]:
        for parameter in layer.parameters():
            parameter.requires_grad = True
    # Supervised auxiliary head updates actual encoder weights. It is discarded
    # after training; the production head is a separately trained XGBoost.
    head = torch.nn.Linear(encoder.get_sentence_embedding_dimension(), 2).to(encoder.device)
    parameters = [p for p in encoder.parameters() if p.requires_grad]
    before = hashlib.sha256(b''.join(p.detach().cpu().numpy().tobytes() for p in parameters)).hexdigest()
    optimizer = torch.optim.AdamW([
        {'params': parameters, 'lr': args.learning_rate},
        {'params': head.parameters(), 'lr': 1e-3},
    ], weight_decay=0.01)
    rng = np.random.default_rng(args.seed)
    history = []
    best_loss = float('inf')
    step = 0
    started = time.perf_counter()
    for epoch in range(args.epochs):
        ids = rng.permutation(train_ids)
        encoder.train()
        head.train()
        losses = []
        for start in range(0, len(ids), args.batch_size):
            batch = ids[start:start + args.batch_size]
            features = tokenize_texts(encoder, [texts[i] for i in batch])
            vectors = F.normalize(encoder(features)['sentence_embedding'], dim=1)
            loss = F.cross_entropy(head(vectors), torch.as_tensor(labels[batch], device=encoder.device))
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(parameters + list(head.parameters()), 1.0)
            optimizer.step()
            losses.append(float(loss.detach()))
            step += 1
            if step % 10 == 0:
                print(f'fine_tune epoch={epoch + 1} step={step} loss={np.mean(losses[-10:]):.4f} seconds={time.perf_counter()-started:.1f}', flush=True)
            if args.max_steps and step >= args.max_steps:
                break
        vectors = embed(encoder, [texts[i] for i in validation_ids], args.batch_size)
        head.eval()
        with torch.inference_mode():
            probabilities = torch.softmax(head(torch.as_tensor(vectors, device=encoder.device)), dim=1).cpu().numpy()
        validation_loss = float(log_loss(labels[validation_ids], probabilities, labels=[0, 1]))
        history.append(dict(epoch=epoch + 1, steps=step, train_loss=float(np.mean(losses)), validation_loss=validation_loss))
        if validation_loss < best_loss:
            best_loss = validation_loss
            encoder.save(str(output / 'encoder'))
        if args.max_steps and step >= args.max_steps:
            break
    after = hashlib.sha256(b''.join(p.detach().cpu().numpy().tobytes() for p in parameters)).hexdigest()
    if before == after:
        raise RuntimeError('Fine-tuning did not change encoder weights')
    return dict(objective='supervised cross_entropy with auxiliary linear head',
                updated_transformer_layers=args.trainable_layers, trainable_parameters=sum(p.numel() for p in parameters),
                before_sha256=before, after_last_epoch_sha256=after, steps=step,
                elapsed_seconds=time.perf_counter()-started, history=history,
                limited_steps=bool(args.max_steps), checkpoint_selection='minimum validation cross-entropy')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--phishing-label', choices=['0', '1'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--base-model', default='sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2')
    parser.add_argument('--epochs', type=int, default=1)
    parser.add_argument('--max-steps', type=int, default=0)
    parser.add_argument('--batch-size', type=int, default=16)
    parser.add_argument('--max-tokens', type=int, default=128)
    parser.add_argument('--trainable-layers', type=int, default=2)
    parser.add_argument('--learning-rate', type=float, default=2e-5)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--max-fpr', type=float, default=0.02)
    parser.add_argument('--device', choices=['cpu', 'cuda'], default='cpu')
    parser.add_argument('--previous-splits', type=Path, help='Preserve group membership when adding data in later runs')
    args = parser.parse_args()
    if args.epochs < 1 or args.batch_size < 1 or args.max_steps < 0 or args.max_tokens < 8 or not 0 <= args.max_fpr < 1:
        parser.error('Invalid training parameters')
    if args.output.exists() and any(args.output.iterdir()):
        parser.error('Output directory is not empty; use a new directory to preserve prior models')
    args.output.mkdir(parents=True, exist_ok=True)
    random.seed(args.seed)
    np.random.seed(args.seed)
    rows, audit = load_training_csv(args.dataset, args.phishing_label)
    previous = json.loads(args.previous_splits.read_text(encoding='utf-8')) if args.previous_splits else None
    splits = grouped_split(rows, args.seed, previous)
    audit['splits'] = {name: {'count': len(ids), 'labels': {str(label): sum(rows[i]['label'] == label for i in ids) for label in (0, 1)}} for name, ids in splits.items()}
    write_json(args.output / 'dataset_audit.json', audit)
    write_json(args.output / 'splits.json', {name: [{'id': rows[i]['id'], 'group': rows[i]['group']} for i in ids] for name, ids in splits.items()})
    print(json.dumps(audit), flush=True)
    texts = [r['text'] for r in rows]
    labels = np.array([r['label'] for r in rows])
    technical = np.array([technical_features(r['subject'], r['body'], **r['metadata']) for r in rows], dtype=np.float32)
    vectorizer = TfidfVectorizer(max_features=6000, ngram_range=(1, 2), sublinear_tf=True, strip_accents='unicode')
    vectorizer.fit([texts[i] for i in splits['train']])
    results = {}
    print('Training fresh TF-IDF baseline on train partition only', flush=True)
    results['tfidf_xgboost'], _ = fit_head(hstack([vectorizer.transform(texts), csr_matrix(technical)], format='csr'), labels, splits, args.seed, args.output, 'tfidf_xgboost', args.max_fpr)
    # Keep baseline reproducible locally, never load untrusted pickle files.
    import pickle
    with (args.output / 'tfidf_vectorizer.pkl').open('wb') as handle:
        pickle.dump(vectorizer, handle)
    import torch
    from sentence_transformers import SentenceTransformer
    torch.set_num_threads(4)
    encoder = SentenceTransformer(args.base_model, device=args.device, trust_remote_code=False, cache_folder=str(ROOT / '.cache-hybrid'))
    encoder.max_seq_length = args.max_tokens
    print('Encoding with frozen pretrained encoder', flush=True)
    started = time.perf_counter()
    frozen = embed(encoder, texts, args.batch_size)
    frozen_seconds = time.perf_counter()-started
    results['frozen_embeddings_xgboost'], _ = fit_head(np.hstack([frozen, technical]), labels, splits, args.seed, args.output, 'frozen_embeddings_xgboost', args.max_fpr)
    print('Fine-tuning neural encoder (training partition only)', flush=True)
    tuning = fine_tune(encoder, texts, labels, splits['train'], splits['validation'], args, args.output)
    del encoder
    encoder = SentenceTransformer(str(args.output / 'encoder'), device=args.device, local_files_only=True)
    print('Encoding with fine-tuned encoder', flush=True)
    started = time.perf_counter()
    tuned = embed(encoder, texts, args.batch_size)
    tuned_seconds = time.perf_counter()-started
    results['finetuned_embeddings_xgboost'], head = fit_head(np.hstack([tuned, technical]), labels, splits, args.seed, args.output, 'finetuned_embeddings_xgboost', args.max_fpr)
    for result in results.values():
        scores = np.array(result['test_scores'])
        test_ids = splits['test']
        result['by_source'] = {}
        result['by_source_language_hint'] = {}
        for field, key in [('source', 'by_source'), ('language', 'by_source_language_hint')]:
            for value in sorted({rows[i][field] for i in test_ids}):
                mask = np.array([rows[i][field] == value for i in test_ids])
                result[key][value] = score_metrics(labels[test_ids][mask], scores[mask], result['threshold'])
    file_hashes = {str(p.relative_to(args.output)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted((args.output / 'encoder').rglob('*')) if p.is_file()}
    file_hashes['finetuned_embeddings_xgboost.json'] = hashlib.sha256((args.output / 'finetuned_embeddings_xgboost.json').read_bytes()).hexdigest()
    manifest = dict(format_version=1, feature_version=FEATURE_VERSION, feature_names=FEATURE_NAMES,
                    encoder_path='encoder', head_path='finetuned_embeddings_xgboost.json',
                    embedding_dimension=int(tuned.shape[1]), total_features=int(head.n_features_in_),
                    class_mapping={'0': 'legitimate', '1': 'phishing'}, phishing_class=1,
                    threshold=results['finetuned_embeddings_xgboost']['threshold'],
                    max_tokens=args.max_tokens, normalization='l2', token_selection='head_tail',
                    dataset_sha256=audit['dataset_sha256'], hashes=file_hashes,
                    status='experimental_not_promoted', fine_tuning=tuning)
    write_json(args.output / 'manifest.json', manifest)
    report = dict(dataset_audit=audit, configuration={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                  fine_tuning=tuning, results=results, environment={p: importlib.metadata.version(p) for p in ['torch','sentence-transformers','transformers','scikit-learn','xgboost','numpy']},
                  encoding_seconds={'frozen': frozen_seconds, 'finetuned': tuned_seconds},
                  warnings=audit['warnings'] + ['Scores are uncalibrated XGBoost outputs. Threshold selected only on validation.',
                                              'This run is an experiment, not evidence of readiness for production.'])
    write_json(args.report.with_suffix('.json'), report)
    lines = ['# Experimento NLP híbrido', '', f"Filas utilizables: {audit['usable_rows']}. Grupos: {audit['groups']}.", '',
             '| Modelo | Umbral (validación) | F1 test | FP test | FN test |', '|---|---:|---:|---:|---:|']
    for name, result in results.items():
        cm = result['test']['confusion_matrix']
        lines.append(f"| {name} | {result['threshold']:.4f} | {result['test']['f1_phishing'] or 0:.4f} | {cm['false_positive']} | {cm['false_negative']} |")
    lines += ['', f"Ajuste neuronal: {tuning['steps']} actualizaciones; {tuning['trainable_parameters']} parámetros entrenables.",
              '', 'Se preservan el modelo original y el endpoint productivo. No se promueve automáticamente el candidato.',
              '', *[f'- {w}' for w in report['warnings']]]
    args.report.with_suffix('.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('\n'.join(lines), flush=True)


if __name__ == '__main__':
    main()
