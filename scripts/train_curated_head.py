"""Entrenamiento local de la cabeza XGBoost sobre el Corpus Curado v3 usando el encoder A100.

Permite validar experimentalmente si la curación de datos (eliminación de 5 ruidos
e inyección de pares contrastivos) mejora el rendimiento antes del reentrenamiento
completo del transformer en Colab.
"""

import csv
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
from sentence_transformers import SentenceTransformer
from xgboost import XGBClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix, roc_auc_score

from services.hybrid_features import FEATURE_NAMES, FEATURE_VERSION, technical_features
from services.hybrid_encoder import embed
from services.hybrid_classifier import HybridClassifier
from scripts.compare_holdout_exact import load_cases, evaluate_model

A100_DIR = ROOT / "artifacts" / "hybrid" / "multilingual-candidate-a100"
CORPUS_DIR = ROOT / "artifacts" / "hybrid" / "corpus-v3"
OUTPUT_DIR = ROOT / "artifacts" / "hybrid" / "multilingual-candidate-v3-head"
REPORT_PATH = ROOT / "reports" / "curated_v3_improvement_report.json"


def threshold_on_validation(labels, scores, max_fpr=0.02):
    candidates = np.unique(np.concatenate(([0.5, 1.0], scores)))
    feasible = []
    for threshold in candidates:
        predicted = scores >= threshold
        fpr = float(predicted[labels == 0].mean())
        recall = float(predicted[labels == 1].mean())
        if fpr <= max_fpr:
            feasible.append((recall, -fpr, float(threshold)))
    if not feasible:
        return 0.5
    return max(feasible)[2]


def main():
    print("=" * 70)
    print("EXPERIMENTO DE MEJORA: Corpus Curado v3 + Encoder Fine-Tuned A100")
    print("=" * 70)

    # 1. Cargar corpus v3 y particiones
    csv_path = CORPUS_DIR / "training.csv"
    splits_path = CORPUS_DIR / "splits.json"
    splits_data = json.loads(splits_path.read_text(encoding="utf-8"))

    rows = []
    csv.field_size_limit(10_000_000)
    with csv_path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for line_num, r in enumerate(reader, 2):
            rows.append({
                "id": f"row-{line_num}",
                "subject": r.get("subject", ""),
                "body": r.get("body", ""),
                "text": f"Subject: {r.get('subject', '')}\n\n{r.get('body', '')}".strip(),
                "label": int(r.get("Label", 0)),
                "attachments_count": int(float(r.get("attachments_count") or 0)),
                "hops_count": int(float(r.get("hops_count") or 0))
            })

    row_idx_by_id = {r["id"]: i for i, r in enumerate(rows)}
    train_indices = np.array([row_idx_by_id[item["id"]] for item in splits_data["train"] if item["id"] in row_idx_by_id])
    val_indices = np.array([row_idx_by_id[item["id"]] for item in splits_data["validation"] if item["id"] in row_idx_by_id])
    test_indices = np.array([row_idx_by_id[item["id"]] for item in splits_data["test"] if item["id"] in row_idx_by_id])

    print(f"Total registros: {len(rows)} | Train: {len(train_indices)} | Val: {len(val_indices)} | Test: {len(test_indices)}")

    # 2. Cargar encoder A100 y generar embeddings
    print("\nCargando encoder fine-tuned A100...")
    encoder_path = A100_DIR / "encoder"
    encoder = SentenceTransformer(str(encoder_path), device="cpu")
    encoder.max_seq_length = 384

    texts = [r["text"] for r in rows]
    labels = np.array([r["label"] for r in rows])
    
    t0 = time.perf_counter()
    print("Extrayendo embeddings neuronales...")
    embeddings = embed(encoder, texts, batch_size=64)
    print(f"Embeddings generados en {time.perf_counter() - t0:.1f}s. Shape: {embeddings.shape}")

    # 3. Features tecnicas
    technical = np.array([
        technical_features(r["subject"], r["body"],
                           attachments_count=r["attachments_count"],
                           hops_count=r["hops_count"])
        for r in rows
    ], dtype=np.float32)

    X_all = np.hstack([embeddings, technical])

    # 4. Entrenar cabeza XGBoost
    print("\nEntrenando cabeza XGBoost en particion 'train' de corpus v3...")
    xgb = XGBClassifier(
        n_estimators=180, max_depth=4, learning_rate=0.06,
        subsample=0.85, colsample_bytree=0.85, reg_lambda=2,
        objective="binary:logistic", eval_metric="logloss",
        tree_method="hist", n_jobs=4, random_state=42
    )
    xgb.fit(X_all[train_indices], labels[train_indices])

    # 5. Calibrar umbral en validation
    val_probs = xgb.predict_proba(X_all[val_indices])[:, 1]
    threshold = threshold_on_validation(labels[val_indices], val_probs, max_fpr=0.02)
    print(f"Umbral calibrado en validación: {threshold:.4f}")

    # 6. Guardar modelo candidato v3-head
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    head_json_name = "finetuned_embeddings_xgboost.json"
    xgb.get_booster().save_model(OUTPUT_DIR / head_json_name)

    # Crear symlink o copiar encoder
    # Para ahorrar espacio en disco, referenciamos o copiamos archivos ligeros del encoder
    out_encoder_dir = OUTPUT_DIR / "encoder"
    out_encoder_dir.mkdir(parents=True, exist_ok=True)
    for p in encoder_path.iterdir():
        if p.is_file():
            (out_encoder_dir / p.name).write_bytes(p.read_bytes())

    # Manifest del nuevo candidato
    manifest = {
        "format_version": 1,
        "feature_version": FEATURE_VERSION,
        "feature_names": FEATURE_NAMES,
        "encoder_path": "encoder",
        "head_path": head_json_name,
        "embedding_dimension": int(embeddings.shape[1]),
        "total_features": int(X_all.shape[1]),
        "class_mapping": {"0": "legitimate", "1": "phishing"},
        "phishing_class": 1,
        "threshold": float(threshold),
        "dataset_name": "corpus-v3-curated",
        "parent_encoder": "multilingual-candidate-a100"
    }
    (OUTPUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (OUTPUT_DIR / "splits.json").write_text(json.dumps(splits_data, indent=2), encoding="utf-8")
    print(f"Nuevo candidato guardado en: {OUTPUT_DIR}")

    # 7. Evaluación comparativa
    print("\n" + "=" * 70)
    print("EVALUACIÓN COMPARATIVA: A100 Original vs Curado v3 (Head)")
    print("=" * 70)

    model_base = HybridClassifier(A100_DIR)
    model_v3 = HybridClassifier(OUTPUT_DIR)

    # Test set de corpus v3
    test_cases = load_cases(csv_path, splits_path, "test")
    m_base_test = evaluate_model(model_base, test_cases)
    m_v3_test = evaluate_model(model_v3, test_cases)

    # Contrastive v3
    contrastive_cases = load_cases(ROOT / "data" / "hybrid_contrastive_curated_v3.jsonl")
    m_base_contra = evaluate_model(model_base, contrastive_cases)
    m_v3_contra = evaluate_model(model_v3, contrastive_cases)

    # Challenge cases (14 correos dificiles)
    challenge_cases = load_cases(ROOT / "data" / "classifier_eval_v1.jsonl")
    m_base_chal = evaluate_model(model_base, challenge_cases)
    m_v3_chal = evaluate_model(model_v3, challenge_cases)

    print("\n--- 1. HOLDOUT TEST CORPUS V3 (1.671 casos) ---")
    print(f"A100 Original:   F1 = {m_base_test['f1']:.4f} | Prec = {m_base_test['precision']:.4f} | Rec = {m_base_test['recall']:.4f} | FP = {m_base_test['confusion_matrix']['false_positive']} | FN = {m_base_test['confusion_matrix']['false_negative']}")
    print(f"Curado v3 Head:  F1 = {m_v3_test['f1']:.4f} | Prec = {m_v3_test['precision']:.4f} | Rec = {m_v3_test['recall']:.4f} | FP = {m_v3_test['confusion_matrix']['false_positive']} | FN = {m_v3_test['confusion_matrix']['false_negative']}")

    print("\n--- 2. BENCHMARK CONTRASTIVO V3 (24 casos: advertencias vs ataques) ---")
    print(f"A100 Original:   F1 = {m_base_contra['f1']:.4f} | Prec = {m_base_contra['precision']:.4f} | Rec = {m_base_contra['recall']:.4f} | FP = {m_base_contra['confusion_matrix']['false_positive']} | FN = {m_base_contra['confusion_matrix']['false_negative']}")
    print(f"Curado v3 Head:  F1 = {m_v3_contra['f1']:.4f} | Prec = {m_v3_contra['precision']:.4f} | Rec = {m_v3_contra['recall']:.4f} | FP = {m_v3_contra['confusion_matrix']['false_positive']} | FN = {m_v3_contra['confusion_matrix']['false_negative']}")

    print("\n--- 3. CASOS DESAFÍO PRODUCCIÓN (14 casos difíciles) ---")
    print(f"A100 Original:   F1 = {m_base_chal['f1']:.4f} | Prec = {m_base_chal['precision']:.4f} | Rec = {m_base_chal['recall']:.4f} | FP = {m_base_chal['confusion_matrix']['false_positive']} | FN = {m_base_chal['confusion_matrix']['false_negative']}")
    print(f"Curado v3 Head:  F1 = {m_v3_chal['f1']:.4f} | Prec = {m_v3_chal['precision']:.4f} | Rec = {m_v3_chal['recall']:.4f} | FP = {m_v3_chal['confusion_matrix']['false_positive']} | FN = {m_v3_chal['confusion_matrix']['false_negative']}")

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "holdout_test": {
            "a100_base": m_base_test,
            "curated_v3_head": m_v3_test,
            "f1_difference": m_v3_test["f1"] - m_base_test["f1"],
            "fp_difference": m_v3_test["confusion_matrix"]["false_positive"] - m_base_test["confusion_matrix"]["false_positive"],
            "fn_difference": m_v3_test["confusion_matrix"]["false_negative"] - m_base_test["confusion_matrix"]["false_negative"]
        },
        "contrastive_benchmark": {
            "a100_base": m_base_contra,
            "curated_v3_head": m_v3_contra,
            "f1_difference": m_v3_contra["f1"] - m_base_contra["f1"],
            "fp_difference": m_v3_contra["confusion_matrix"]["false_positive"] - m_base_contra["confusion_matrix"]["false_positive"],
            "fn_difference": m_v3_contra["confusion_matrix"]["false_negative"] - m_base_contra["confusion_matrix"]["false_negative"]
        },
        "challenge_cases": {
            "a100_base": m_base_chal,
            "curated_v3_head": m_v3_chal,
            "f1_difference": m_v3_chal["f1"] - m_base_chal["f1"]
        }
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nReporte completo guardado en: {REPORT_PATH}")


if __name__ == "__main__":
    main()
