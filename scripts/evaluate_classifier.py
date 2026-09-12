#!/usr/bin/env python3
"""Evaluate the production classifier on a validated JSONL corpus."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema  # noqa: E402
from scripts.audit_classifier import AuditError, audit_artifact  # noqa: E402
from scripts.classifier_corpus import (  # noqa: E402
    CorpusValidationError,
    dataset_sha256,
    validate_dataset,
)
from services.classifier_contract import (  # noqa: E402
    DEFAULT_MODEL_PATH,
    PRODUCTION_PHISHING_PROBABILITY_INDEX,
)


class EvaluationError(RuntimeError):
    """Raised when an evaluation cannot produce trustworthy results."""


def _safe_divide(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def _average_precision(labels: list[int], scores: list[float]) -> float | None:
    positive_count = sum(labels)
    if positive_count == 0:
        return None
    ranked = sorted(zip(scores, labels), key=lambda item: -item[0])
    true_positives = 0
    seen = 0
    area = 0.0
    index = 0
    while index < len(ranked):
        score = ranked[index][0]
        group_positive = 0
        group_size = 0
        while index < len(ranked) and ranked[index][0] == score:
            group_positive += ranked[index][1]
            group_size += 1
            index += 1
        true_positives += group_positive
        seen += group_size
        area += (group_positive / positive_count) * (true_positives / seen)
    return area


def _roc_auc(labels: list[int], scores: list[float]) -> float | None:
    positives = [score for label, score in zip(labels, scores) if label == 1]
    negatives = [score for label, score in zip(labels, scores) if label == 0]
    if not positives or not negatives:
        return None
    wins = 0.0
    for positive in positives:
        for negative in negatives:
            wins += 1.0 if positive > negative else 0.5 if positive == negative else 0.0
    return wins / (len(positives) * len(negatives))


def calculate_metrics(
    expected_labels: Iterable[str],
    predicted_labels: Iterable[str],
    scores: Iterable[float],
) -> dict[str, Any]:
    expected = list(expected_labels)
    predicted = list(predicted_labels)
    score_values = [float(value) for value in scores]
    if not (len(expected) == len(predicted) == len(score_values)):
        raise ValueError("Expected labels, predicted labels, and scores must have equal lengths")

    tp = sum(e == "phishing" and p == "phishing" for e, p in zip(expected, predicted))
    tn = sum(e == "legitimate" and p == "legitimate" for e, p in zip(expected, predicted))
    fp = sum(e == "legitimate" and p == "phishing" for e, p in zip(expected, predicted))
    fn = sum(e == "phishing" and p == "legitimate" for e, p in zip(expected, predicted))
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    if precision is None or recall is None:
        f1 = None
    elif precision == 0.0 and recall == 0.0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    numeric_labels = [1 if value == "phishing" else 0 for value in expected]

    return {
        "count": len(expected),
        "confusion_matrix": {"true_positive": tp, "true_negative": tn, "false_positive": fp, "false_negative": fn},
        "precision_phishing": precision,
        "recall_phishing": recall,
        "f1_phishing": f1,
        "pr_auc": _average_precision(numeric_labels, score_values),
        "roc_auc": _roc_auc(numeric_labels, score_values),
        "false_positive_rate": _safe_divide(fp, fp + tn),
        "false_negative_rate": _safe_divide(fn, fn + tp),
        "brier_score": (
            sum((score - label) ** 2 for score, label in zip(score_values, numeric_labels)) / len(score_values)
            if score_values
            else None
        ),
    }


def _percentile_95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[index]


def _manifest_warnings(dataset_path: Path) -> list[str]:
    manifest_path = dataset_path.with_name(f"{dataset_path.stem}.manifest.json")
    if not manifest_path.is_file():
        return ["Dataset manifest is missing."]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    warnings: list[str] = []
    if manifest.get("sha256") != dataset_sha256(dataset_path):
        raise EvaluationError("Dataset checksum does not match its manifest")
    if manifest.get("status") != "complete":
        warnings.append("The evaluation corpus is incomplete.")
    if manifest.get("holdout_status") != "verified":
        warnings.append("The corpus is not a verified holdout from model training.")
    return warnings


def select_records(
    records: list[dict[str, Any]],
    *,
    category: str | None,
    label: str | None,
    limit: int | None,
    seed: int,
) -> list[dict[str, Any]]:
    selected = [
        record
        for record in records
        if (category is None or record["category"] == category) and (label is None or record["label"] == label)
    ]
    selected.sort(key=lambda record: record["id"])
    if limit is not None and limit < len(selected):
        selected = random.Random(seed).sample(selected, limit)
        selected.sort(key=lambda record: record["id"])
    return selected


def evaluate_records(
    records: list[dict[str, Any]],
    analyzer: Any,
    *,
    timer: Callable[[], float] = time.perf_counter,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    for record in records:
        security = record["security_features"]
        payload = EmailPayloadSchema(
            metadata=MetadataSchema(asunto=record["subject"]),
            contenido=record["body"],
            security_features=SecurityFeaturesSchema(**security) if security else None,
        )
        started = timer()
        diagnostics = analyzer._classify_payload(payload)
        elapsed_ms = (timer() - started) * 1000
        predicted_label = "phishing" if diagnostics["is_phishing"] else "legitimate"
        adjustments = [
            adjustment.model_dump() if hasattr(adjustment, "model_dump") else dict(adjustment)
            for adjustment in diagnostics.get("security_adjustments") or []
        ]
        rows.append(
            {
                "id": record["id"],
                "expected_label": record["label"],
                "predicted_label": predicted_label,
                "raw_score": diagnostics["raw_score"],
                "final_score": diagnostics["risk_score"],
                "decision_source": diagnostics["decision_source"],
                "security_adjustments": adjustments,
                "elapsed_ms": elapsed_ms,
                "category": record["category"],
                "correct": predicted_label == record["label"],
            }
        )

    final_metrics = calculate_metrics(
        [row["expected_label"] for row in rows],
        [row["predicted_label"] for row in rows],
        [row["final_score"] for row in rows],
    )
    raw_rows = [row for row in rows if row["raw_score"] is not None]
    if len(raw_rows) != len(rows):
        warnings.append(f"Raw-model metrics exclude {len(rows) - len(raw_rows)} critical-rule cases.")
    raw_metrics = calculate_metrics(
        [row["expected_label"] for row in raw_rows],
        ["phishing" if row["raw_score"] >= analyzer.UMBRAL_CRITICO else "legitimate" for row in raw_rows],
        [row["raw_score"] for row in raw_rows],
    )
    for name, value in final_metrics.items():
        if value is None:
            warnings.append(f"Final metric {name} is undefined for the selected data.")
    for name, value in raw_metrics.items():
        if value is None:
            warnings.append(f"Raw-model metric {name} is undefined for the scored data.")

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["category"]].append(row)
    category_metrics = {
        category: calculate_metrics(
            [row["expected_label"] for row in category_rows],
            [row["predicted_label"] for row in category_rows],
            [row["final_score"] for row in category_rows],
        )
        for category, category_rows in sorted(grouped.items())
    }
    if any(
        value is None
        for category_result in category_metrics.values()
        for value in category_result.values()
    ):
        warnings.append("Some category metrics are undefined because the category does not contain both classes.")
    elapsed = [row["elapsed_ms"] for row in rows]
    metrics = {
        "final": final_metrics,
        "raw_model": raw_metrics,
        "by_category": category_metrics,
        "timing_ms": {
            "average": statistics.fmean(elapsed) if elapsed else None,
            "p95": _percentile_95(elapsed),
        },
    }
    return rows, metrics, warnings


def _render_metric(value: Any) -> str:
    return "n/a" if value is None else f"{value:.4f}" if isinstance(value, float) else str(value)


def render_markdown(report: dict[str, Any]) -> str:
    final = report["metrics"]["final"]
    raw = report["metrics"]["raw_model"]
    lines = [
        "# Classifier evaluation",
        "",
        f"- Dataset: `{report['dataset']}`",
        f"- Model: `{report['model']}`",
        f"- Cases: `{report['case_count']}`",
        f"- Partial run: `{str(report['partial']).lower()}`",
        f"- Seed: `{report['seed']}`",
        "",
        "## Final outcome",
        "",
        f"- Precision (phishing): `{_render_metric(final['precision_phishing'])}`",
        f"- Recall (phishing): `{_render_metric(final['recall_phishing'])}`",
        f"- F1 (phishing): `{_render_metric(final['f1_phishing'])}`",
        f"- PR-AUC: `{_render_metric(final['pr_auc'])}`",
        f"- ROC-AUC: `{_render_metric(final['roc_auc'])}`",
        f"- Brier score: `{_render_metric(final['brier_score'])}`",
        f"- Confusion matrix: `{final['confusion_matrix']}`",
        "",
        "## Raw model",
        "",
        f"- Cases scored by model: `{raw['count']}`",
        f"- Precision (phishing): `{_render_metric(raw['precision_phishing'])}`",
        f"- Recall (phishing): `{_render_metric(raw['recall_phishing'])}`",
        f"- F1 (phishing): `{_render_metric(raw['f1_phishing'])}`",
        "",
        "## Warnings",
        "",
    ]
    lines.extend(f"- {warning}" for warning in report["warnings"] or ["None."])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], rows: list[dict[str, Any]], output_prefix: Path) -> tuple[Path, Path, Path]:
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = output_prefix.with_suffix(".json")
    markdown_path = output_prefix.with_suffix(".md")
    csv_path = output_prefix.with_name(f"{output_prefix.name}_cases.csv")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    fieldnames = [
        "id", "expected_label", "predicted_label", "raw_score", "final_score",
        "decision_source", "security_adjustments", "elapsed_ms", "category", "correct",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            serialized = dict(row)
            serialized["security_adjustments"] = json.dumps(row["security_adjustments"], ensure_ascii=False, sort_keys=True)
            writer.writerow(serialized)
    return json_path, markdown_path, csv_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "reports" / "classifier_evaluation")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--category")
    parser.add_argument("--label", choices=("phishing", "legitimate"))
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.limit is not None and args.limit <= 0:
        print("Evaluation failed: --limit must be positive", file=sys.stderr)
        return 1
    try:
        records, validation = validate_dataset(args.dataset)
        warnings = list(validation["warnings"]) + _manifest_warnings(args.dataset)
        shortfalls = validation["shortfalls"]
        if shortfalls["phishing"]:
            warnings.append(f"The corpus needs {shortfalls['phishing']} more phishing cases.")
        if shortfalls["legitimate"]:
            warnings.append(f"The corpus needs {shortfalls['legitimate']} more legitimate cases.")
        for category_name, missing_count in shortfalls["used_categories"].items():
            warnings.append(f"Category {category_name} needs {missing_count} more cases.")
        selected = select_records(records, category=args.category, label=args.label, limit=args.limit, seed=args.seed)
        if not selected:
            raise EvaluationError("No records match the requested filters")

        from services import analyzer

        analyzer._load_model(args.model)
        if analyzer.modelo_exportado is None:
            raise EvaluationError("Production analyzer could not load the requested model")
        audit = audit_artifact(analyzer.modelo_exportado, args.model.resolve())
        if (
            audit["class_mapping"]["phishing_probability_index"]
            != PRODUCTION_PHISHING_PROBABILITY_INDEX
        ):
            raise EvaluationError("Production probability index does not match the audited phishing class")
        if audit["feature_dimensions"]["matches"] is False:
            raise EvaluationError("Production feature count does not match the model")

        rows, metrics, evaluation_warnings = evaluate_records(selected, analyzer)
        partial = args.limit is not None or args.category is not None or args.label is not None
        if partial:
            warnings.append("This is a partial evaluation run.")
        report = {
            "dataset": str(args.dataset.resolve()),
            "dataset_sha256": dataset_sha256(args.dataset),
            "model": str(args.model.resolve()),
            "case_count": len(rows),
            "partial": partial,
            "filters": {"limit": args.limit, "category": args.category, "label": args.label},
            "seed": args.seed,
            "model_audit": {
                "classes": audit["class_mapping"]["classes"],
                "phishing_probability_index": audit["class_mapping"]["phishing_probability_index"],
                "threshold": audit["threshold"],
                "feature_dimensions_match": audit["feature_dimensions"]["matches"],
            },
            "metrics": metrics,
            "warnings": sorted(set(warnings + evaluation_warnings)),
        }
        paths = write_outputs(report, rows, args.output)
    except (AuditError, CorpusValidationError, EvaluationError, ImportError, OSError, ValueError) as exc:
        print(f"Evaluation failed: {exc}", file=sys.stderr)
        return 1
    print("Evaluation written to " + ", ".join(str(path) for path in paths))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
