"""Choose a stricter false-positive budget on validation only, preserving weights."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import pickle
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
from schemas import EmailPayloadSchema
from scripts.train_audit_candidate import choose_threshold
from scripts.evaluate_classifier import calculate_metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output already exists; keep previous artifacts intact")
    from services import analyzer
    analyzer._load_model(args.model)
    if analyzer.calibrated_model is None:
        raise RuntimeError("Cannot load the candidate")
    corpus_hash = hashlib.sha256(args.dataset.read_bytes()).hexdigest()
    if analyzer.modelo_exportado["training_metadata"]["dataset_sha256"] != corpus_hash:
        raise ValueError("Validation corpus differs from the candidate's corpus")
    csv.field_size_limit(20_000_000)
    values, rows = [], []
    with args.dataset.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            if row["particion"] != "validation":
                continue
            payload = EmailPayloadSchema(metadata={"asunto": row["subject"]}, contenido=row["body"],
                security_features={"attachment_count": int(float(row.get("attachments_count") or 0)),
                                   "received_hop_count": int(float(row.get("hops_count") or 0))})
            values.append(analyzer.extract_model_inputs(payload))
            rows.append(row)
            if len(rows) % 200 == 0:
                print(f"Validation-only features {len(rows)}/1619", flush=True)
    matrix = np.hstack([analyzer.tfidf.transform([v["text"] for v in values]).toarray(),
                       analyzer.scaler_meta.transform([v["metadata"] for v in values]),
                       analyzer.scaler_slots.transform([v["slots"] for v in values]),
                       np.asarray([v["urls"] for v in values]),
                       analyzer.scaler_legibilidad.transform([v["readability"] for v in values])]).astype(np.float32)
    labels = np.array([int(row["Label"]) for row in rows])
    scores = analyzer.calibrated_model.predict_proba(matrix)[:, 0]
    threshold = choose_threshold(labels, scores, args.max_fpr)
    metrics = calculate_metrics(["phishing" if y else "legitimate" for y in labels],
        ["phishing" if p >= threshold else "legitimate" for p in scores], scores)
    artifact = dict(analyzer.modelo_exportado)
    artifact["umbral_critico"] = threshold
    policy = {"partition": "validation", "max_fpr": args.max_fpr,
              "parent_model_sha256": hashlib.sha256(analyzer.LOADED_MODEL_PATH.read_bytes()).hexdigest(),
              "selection_code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    artifact["training_metadata"] = dict(artifact["training_metadata"], operating_point_policy=policy)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as stream:
        pickle.dump(artifact, stream)
    report = {"threshold": threshold, "policy": policy, "dataset_sha256": corpus_hash,
              "model_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(), "validation_metrics": metrics,
              "validation_rows": [{"id": row["row_id"], "label": int(y), "score": float(p)} for row, y, p in zip(rows, labels, scores)]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"threshold": threshold, "validation_metrics": metrics}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
