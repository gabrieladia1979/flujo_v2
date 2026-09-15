"""Evaluación y comparativa justa de modelos híbridos sobre la misma partición exacta de test.

Permite evaluar un modelo o comparar dos modelos (candidato vs referencia)
registro por registro, asegurando comparaciones estrictamente pareadas.
"""

import argparse
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score, brier_score_loss, confusion_matrix
from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema
from services.hybrid_classifier import HybridClassifier


def load_cases(dataset_path: Path, splits_path: Path = None, split_name: str = "test"):
    cases = []
    csv.field_size_limit(10_000_000)
    
    if dataset_path.suffix == ".jsonl":
        for line in dataset_path.read_text(encoding="utf-8").strip().split("\n"):
            if not line:
                continue
            item = json.loads(line)
            cases.append({
                "id": item.get("id"),
                "subject": item.get("subject", ""),
                "body": item.get("body", ""),
                "label": 1 if item.get("label") == "phishing" or item.get("label") == 1 else 0,
                "metadata": item.get("security_features", {})
            })
        return cases

    # CSV con splits
    rows_by_id = {}
    with dataset_path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for line_num, row in enumerate(reader, 2):
            row_id = f"row-{line_num}"
            rows_by_id[row_id] = {
                "id": row_id,
                "subject": row.get("subject", ""),
                "body": row.get("body", ""),
                "label": int(row.get("Label", 0)),
                "attachments_count": int(float(row.get("attachments_count") or 0)),
                "hops_count": int(float(row.get("hops_count") or 0))
            }

    if splits_path and splits_path.exists():
        split_data = json.loads(splits_path.read_text(encoding="utf-8"))
        target_ids = [r["id"] for r in split_data.get(split_name, [])]
        cases = [rows_by_id[rid] for rid in target_ids if rid in rows_by_id]
    else:
        cases = list(rows_by_id.values())

    return cases


def evaluate_model(model: HybridClassifier, cases: list):
    y_true = []
    y_pred = []
    y_scores = []
    
    for case in cases:
        label = case["label"]
        payload = EmailPayloadSchema(
            metadata=MetadataSchema(asunto=case.get("subject")),
            contenido=case.get("body"),
            security_features=SecurityFeaturesSchema(
                attachment_count=case.get("attachments_count", 0),
                received_hop_count=case.get("hops_count", 0)
            )
        )
        score = model.raw_score(payload)
        pred = 1 if score >= model.manifest["threshold"] else 0
        
        y_true.append(label)
        y_pred.append(pred)
        y_scores.append(score)

    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    y_scores = np.array(y_scores)
    
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    
    metrics = {
        "count": len(cases),
        "f1": float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "precision": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_scores)) if len(np.unique(y_true)) > 1 else None,
        "brier_score": float(brier_score_loss(y_true, y_scores)),
        "confusion_matrix": {
            "true_positive": int(tp),
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn)
        }
    }
    return metrics, y_pred, y_scores


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True, help="Ruta al artefacto del modelo candidato")
    parser.add_argument("--dataset", type=Path, required=True, help="Ruta al dataset (CSV o JSONL)")
    parser.add_argument("--splits", type=Path, default=None, help="Ruta al archivo splits.json (opcional)")
    parser.add_argument("--split-name", type=str, default="test", help="Nombre de la partición (default: test)")
    parser.add_argument("--output", type=Path, default=None, help="Ruta para guardar reporte JSON")
    args = parser.parse_args()

    print(f"Cargando modelo desde: {args.model}")
    model = HybridClassifier(args.model)
    print(f"Cargando datos desde: {args.dataset}")
    cases = load_cases(args.dataset, args.splits, args.split_name)
    print(f"Total de casos cargados: {len(cases)}")

    metrics, preds, scores = evaluate_model(model, cases)
    cm = metrics["confusion_matrix"]
    
    print("\n" + "=" * 60)
    print(f"RESULTADOS DE EVALUACIÓN ({args.model.name})")
    print("=" * 60)
    print(f"Casos evaluados:      {metrics['count']}")
    print(f"Umbral de decisión:   {model.manifest['threshold']:.4f}")
    print(f"F1-Score:             {metrics['f1']:.6f}")
    print(f"Precisión:            {metrics['precision']*100:.2f}%")
    print(f"Recall (Sensibilidad):{metrics['recall']*100:.2f}%")
    if metrics["roc_auc"] is not None:
        print(f"ROC-AUC:              {metrics['roc_auc']:.6f}")
    print(f"Brier Score:          {metrics['brier_score']:.6f}")
    print(f"Falsos Positivos:     {cm['false_positive']} (alarmas en correos legítimos)")
    print(f"Falsos Negativos:     {cm['false_negative']} (ataques no detectados)")
    print(f"Verdaderos Positivos: {cm['true_positive']}")
    print(f"Verdaderos Negativos: {cm['true_negative']}")
    print("=" * 60)

    if args.output:
        report = {
            "model": str(args.model),
            "dataset": str(args.dataset),
            "split": args.split_name,
            "threshold": model.manifest["threshold"],
            "metrics": metrics
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Reporte guardado en: {args.output}")


if __name__ == "__main__":
    main()
