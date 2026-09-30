"""Measure LIME local fit on a deterministic, stratified slice of a saved test split."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import statistics
from collections import defaultdict
from pathlib import Path

from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema
from services.hybrid_classifier import HybridClassifier
from services.hybrid_lime import VALIDATION_SAMPLES, explain_hybrid_text


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def evaluate(model: Path, dataset: Path, splits: Path, *, per_stratum: int = 5,
             num_samples: int = 128) -> dict:
    test_ids = {item["id"] for item in json.loads(splits.read_text(encoding="utf-8"))["test"]}
    strata = defaultdict(list)
    csv.field_size_limit(10_000_000)
    with dataset.open(encoding="utf-8-sig", newline="") as source:
        for line, row in enumerate(csv.DictReader(source), 2):
            identifier = f"row-{line}"
            if identifier in test_ids and 120 <= len(row["body"]) <= 1000:
                strata[(row["Label"], row["language"])].append((identifier, row))

    rng = random.Random(42)
    selected = [item for key in sorted(strata)
                for item in rng.sample(strata[key], min(per_stratum, len(strata[key])))]
    classifier = HybridClassifier(model)
    cases = []
    for identifier, row in selected:
        payload = EmailPayloadSchema(
            metadata=MetadataSchema(asunto=row["subject"]),
            contenido=row["body"],
            security_features=SecurityFeaturesSchema(
                attachment_count=int(float(row.get("attachments_count") or 0)),
                received_hop_count=int(float(row.get("hops_count") or 0)),
            ),
        )
        result = explain_hybrid_text(classifier, payload, num_samples=num_samples)
        cases.append({
            "id": identifier,
            "label": row["Label"],
            "source_language_hint": row["language"],
            "raw_model_score": result["phishing_probability"],
            "fit_r2": result["local_fidelity_r2"],
            "fresh_perturbation_r2": result["heldout_fidelity_r2"],
            "fresh_perturbation_mae": result["heldout_mae"],
            "passes_both_checks": result["reliable_local_fit"],
            "elapsed_seconds": result["elapsed_seconds"],
        })

    fresh_r2 = [case["fresh_perturbation_r2"] for case in cases
                if case["fresh_perturbation_r2"] is not None]
    return {
        "model_manifest_sha256": file_sha256(model / "manifest.json"),
        "dataset_sha256": file_sha256(dataset),
        "splits_sha256": file_sha256(splits),
        "selection": "seed 42; up to 5 per label and source language; saved test IDs; body 120-1000 characters",
        "num_samples_for_fit": num_samples,
        "num_fresh_perturbations": VALIDATION_SAMPLES,
        "summary": {
            "cases": len(cases),
            "median_fit_r2": statistics.median(case["fit_r2"] for case in cases),
            "fit_r2_at_least_0_7": sum(case["fit_r2"] >= 0.7 for case in cases),
            "median_fresh_r2_when_defined": statistics.median(fresh_r2) if fresh_r2 else None,
            "passes_both_checks": sum(case["passes_both_checks"] for case in cases),
            "median_elapsed_seconds": statistics.median(case["elapsed_seconds"] for case in cases),
        },
        "cases": cases,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--splits", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--per-stratum", type=int, default=5)
    parser.add_argument("--num-samples", type=int, default=128)
    args = parser.parse_args()
    report = evaluate(args.model, args.dataset, args.splits,
                      per_stratum=args.per_stratum, num_samples=args.num_samples)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
