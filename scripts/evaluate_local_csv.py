"""Evaluate the audit XGBoost on a source-stratified historical CSV sample.

This is diagnostic: the legacy artifact has no verified training provenance.
Reports contain row IDs and scores, never subjects or bodies.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import hashlib
import json
import importlib.metadata
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.evaluate_classifier import calculate_metrics
from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema


def select_rows(path, partition, limit, seed):
    csv.field_size_limit(20_000_000)
    groups = defaultdict(list)
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for position, row in enumerate(csv.DictReader(stream), 1):
            if partition and row.get("particion") != partition:
                continue
            if row.get("Label") not in {"0", "1"}:
                raise ValueError(f"Unknown label at row {position}")
            row["audit_row"] = position
            groups[(row.get("source", "unknown"), row["Label"])].append(row)
    rng = random.Random(seed)
    chosen = []
    for key in sorted(groups):
        values = groups[key]
        chosen.extend(rng.sample(values, min(limit, len(values))) if limit else values)
    return sorted(chosen, key=lambda row: row["audit_row"])


def summarize(rows, score_key, threshold):
    return calculate_metrics([r["label"] for r in rows],
                             ["phishing" if r[score_key] >= threshold else "legitimate" for r in rows],
                             [r[score_key] for r in rows])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--partition", default="test")
    parser.add_argument("--max-per-source-label", type=int, default=40)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", type=Path, help="Explicit separate artifact to evaluate")
    args = parser.parse_args()
    if args.max_per_source_label < 0:
        parser.error("--max-per-source-label must be nonnegative (0 means all)")
    selected = select_rows(args.dataset, args.partition, args.max_per_source_label, args.seed)
    if not selected:
        parser.error("No rows selected; check the partition")
    from services import analyzer
    if args.model:
        analyzer._load_model(args.model)
    if analyzer.calibrated_model is None:
        raise analyzer.ClassifierUnavailableError("Cannot evaluate: model is unavailable")
    results, errors = [], []
    started = time.perf_counter()
    for index, row in enumerate(selected, 1):
        row_id = row.get("row_id") or f"csv-row-{row['audit_row']}"
        try:
            payload = EmailPayloadSchema(
                metadata=MetadataSchema(asunto=row.get("subject", "")), contenido=row.get("body", ""),
                security_features=SecurityFeaturesSchema(
                    attachment_count=int(float(row.get("attachments_count") or 0)),
                    received_hop_count=int(float(row.get("hops_count") or 0))))
            diagnostics = analyzer._classify_payload(payload)
            if diagnostics["raw_score"] is None:
                raise ValueError("Expected model inference, got a critical shortcut")
            results.append({"id": row_id, "source": row.get("source", "unknown"),
                            "label": "phishing" if row["Label"] == "1" else "legitimate",
                            "raw_score": diagnostics["raw_score"], "inverse_raw_score": 1 - diagnostics["raw_score"],
                            "final_score": diagnostics["risk_score"],
                            "decision_source": diagnostics["decision_source"],
                            "bank_mentions": diagnostics["bank_context"].mentioned_banks if diagnostics.get("bank_context") else [],
                            "content_signals": [s.rule for s in diagnostics.get("content_signals", [])]})
        except (ValueError, analyzer.ClassifierUnavailableError) as exc:
            errors.append({"id": row_id, "source": row.get("source", "unknown"), "error_type": type(exc).__name__})
        if index % 20 == 0 or index == len(selected):
            print(f"Evaluated {index}/{len(selected)}; failures={len(errors)}", flush=True)
    by_source = {}
    for source in sorted({r["source"] for r in results}):
        subset = [r for r in results if r["source"] == source]
        by_source[source] = summarize(subset, "final_score", analyzer.UMBRAL_CRITICO)
    report = {
        "dataset_path": str(args.dataset.resolve()), "dataset_sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
        "model_sha256": hashlib.sha256(analyzer.LOADED_MODEL_PATH.read_bytes()).hexdigest(),
        "model_path": str(analyzer.LOADED_MODEL_PATH),
        "partition": args.partition, "seed": args.seed, "max_per_source_label": args.max_per_source_label,
        "selected": len(selected), "scored": len(results), "errors": errors,
        "threshold": float(analyzer.UMBRAL_CRITICO), "production_probability_index": analyzer.PRODUCTION_PHISHING_PROBABILITY_INDEX,
        "runtime_versions": {key: importlib.metadata.version(key) for key in ("numpy", "scikit-learn", "spacy", "xgboost")},
        "pipeline_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                            ("services/analyzer.py", "services/bank_identity.py", "data/argentine_banks.json")},
        "metrics": {"raw": summarize(results, "raw_score", analyzer.UMBRAL_CRITICO),
                    "final": summarize(results, "final_score", analyzer.UMBRAL_CRITICO),
                    "inverse_raw_diagnostic_only": summarize(results, "inverse_raw_score", analyzer.UMBRAL_CRITICO)},
        "by_source": by_source, "rows": results, "elapsed_seconds": time.perf_counter() - started,
        "limitations": ["Legacy model training overlap is unknown: NOT an independent holdout result.",
                        "Labels are inherited from the local corpus; not individually verified.",
                        "Sample caps change the class/source distribution; not population accuracy.",
                        "CSV lacks sender and authentication: real Outlook evidence is not represented.",
                        "Inverse scores are diagnostic only; production class mapping is unchanged."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["metrics"], ensure_ascii=False, indent=2))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
