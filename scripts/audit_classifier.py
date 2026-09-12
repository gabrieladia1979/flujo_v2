#!/usr/bin/env python3
"""Audit the current classifier artifact without changing it."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import pickle
import platform
import sys
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.classifier_contract import (  # noqa: E402
    DEFAULT_MODEL_PATH,
    METADATA_FEATURE_COUNT,
    PHISHING_CLASS_VALUE,
    PRODUCTION_PHISHING_PROBABILITY_INDEX,
    READABILITY_FEATURE_COUNT,
    SLOT_FEATURE_COUNT,
    URL_FEATURE_COUNT,
)


REQUIRED_COMPONENTS = ("tfidf", "scaler_meta", "scaler_slots", "calibrated_model", "umbral_critico")
PROVENANCE_KEYS = ("training_dataset", "dataset", "dataset_sha256", "training_code", "training_metadata")


class AuditError(RuntimeError):
    """Raised when the artifact cannot be audited reliably."""


def _json_value(value: Any) -> Any:
    if hasattr(value, "item"):
        return value.item()
    return value


def resolve_phishing_class(classes: Sequence[Any]) -> dict[str, Any]:
    values = [_json_value(value) for value in list(classes)]
    if not values:
        raise AuditError("calibrated_model.classes_ is empty")

    textual_matches = [
        index
        for index, value in enumerate(values)
        if str(value).strip().lower() in {"phishing", "phish", "malicious", "malicioso"}
    ]
    if len(textual_matches) == 1:
        index = textual_matches[0]
        basis = "semantic_class_label"
    elif PHISHING_CLASS_VALUE in values:
        index = values.index(PHISHING_CLASS_VALUE)
        basis = "configured_production_class_convention"
    else:
        raise AuditError(
            "Cannot determine the phishing class from classes_; add explicit artifact provenance before evaluation"
        )

    return {
        "classes": values,
        "phishing_class_value": values[index],
        "phishing_probability_index": index,
        "mapping_basis": basis,
        "matches_production_index": index == PRODUCTION_PHISHING_PROBABILITY_INDEX,
    }


def _feature_count(component: Any) -> int | None:
    value = getattr(component, "n_features_in_", None)
    return int(value) if value is not None else None


def _tfidf_dimension(tfidf: Any) -> int | None:
    vocabulary = getattr(tfidf, "vocabulary_", None)
    if isinstance(vocabulary, dict):
        return len(vocabulary)
    return _feature_count(tfidf)


def _model_feature_count(model: Any) -> int | None:
    direct = _feature_count(model)
    if direct is not None:
        return direct
    for attribute in ("estimator", "base_estimator"):
        nested = getattr(model, attribute, None)
        nested_count = _feature_count(nested) if nested is not None else None
        if nested_count is not None:
            return nested_count
    calibrated = getattr(model, "calibrated_classifiers_", None) or []
    for item in calibrated:
        nested = getattr(item, "estimator", None) or getattr(item, "base_estimator", None)
        nested_count = _feature_count(nested) if nested is not None else None
        if nested_count is not None:
            return nested_count
    return None


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def audit_artifact(artifact: Any, model_path: Path | None = None) -> dict[str, Any]:
    if not isinstance(artifact, dict):
        raise AuditError("Classifier artifact must be a dictionary")
    missing = [name for name in REQUIRED_COMPONENTS if name not in artifact]
    if missing:
        raise AuditError(f"Classifier artifact is missing required components: {', '.join(missing)}")

    classifier = artifact["calibrated_model"]
    if not hasattr(classifier, "classes_"):
        raise AuditError("calibrated_model does not expose classes_")
    class_mapping = resolve_phishing_class(classifier.classes_)

    tfidf_dimension = _tfidf_dimension(artifact["tfidf"])
    meta_dimension = _feature_count(artifact["scaler_meta"])
    slot_dimension = _feature_count(artifact["scaler_slots"])
    readability_scaler = artifact.get("scaler_legibilidad")
    readability_dimension = _feature_count(readability_scaler) if readability_scaler is not None else 1

    dimensions = [tfidf_dimension, meta_dimension, slot_dimension, URL_FEATURE_COUNT, readability_dimension]
    produced_feature_count = sum(dimensions) if all(value is not None for value in dimensions) else None
    model_feature_count = _model_feature_count(classifier)
    feature_match = (
        produced_feature_count == model_feature_count
        if produced_feature_count is not None and model_feature_count is not None
        else None
    )

    provenance = {key: artifact.get(key) for key in PROVENANCE_KEYS if artifact.get(key) is not None}
    mapping_status = (
        "consistent_with_production_contract"
        if class_mapping["matches_production_index"]
        else "suspicious_probability_index"
    )
    warnings: list[str] = []
    if class_mapping["mapping_basis"] == "configured_production_class_convention":
        warnings.append(
            "The numeric phishing label follows the configured production convention and behavioral "
            "regression evidence, but its semantics cannot be independently verified without training provenance."
        )
    if not provenance:
        warnings.append("The artifact does not identify its training dataset or training process.")
    if feature_match is False:
        warnings.append("The production feature count does not match the classifier input dimension.")
    if mapping_status == "suspicious_probability_index":
        warnings.append(
            "Production probability access does not match the resolved phishing class index."
        )

    return {
        "model_path": str(model_path) if model_path else None,
        "loadable": True,
        "artifact_type": type(artifact).__name__,
        "components": sorted(artifact.keys()),
        "required_components_present": True,
        "class_mapping": class_mapping,
        "production_probability_access": (
            f"predict_proba(X)[0][{PRODUCTION_PHISHING_PROBABILITY_INDEX}]"
        ),
        "production_probability_status": mapping_status,
        "threshold": float(artifact["umbral_critico"]),
        "feature_dimensions": {
            "tfidf": tfidf_dimension,
            "metadata": meta_dimension,
            "slots": slot_dimension,
            "url": URL_FEATURE_COUNT,
            "readability": readability_dimension,
            "produced_total": produced_feature_count,
            "model_expected_total": model_feature_count,
            "matches": feature_match,
            "production_contract": {
                "metadata": METADATA_FEATURE_COUNT,
                "slots": SLOT_FEATURE_COUNT,
                "url": URL_FEATURE_COUNT,
                "readability": READABILITY_FEATURE_COUNT,
            },
        },
        "tfidf": {
            "class": type(artifact["tfidf"]).__name__,
            "vocabulary_size": tfidf_dimension,
            "ngram_range": list(getattr(artifact["tfidf"], "ngram_range", [])) or None,
            "max_features": getattr(artifact["tfidf"], "max_features", None),
        },
        "scalers": {
            "metadata": {"class": type(artifact["scaler_meta"]).__name__, "dimension": meta_dimension},
            "slots": {"class": type(artifact["scaler_slots"]).__name__, "dimension": slot_dimension},
            "readability": {
                "class": type(readability_scaler).__name__ if readability_scaler is not None else None,
                "dimension": readability_dimension,
            },
        },
        "official_domains": sorted(str(value) for value in artifact.get("dominios_oficiales", [])),
        "runtime_versions": {
            "python": platform.python_version(),
            "numpy": _package_version("numpy"),
            "scikit-learn": _package_version("scikit-learn"),
            "xgboost": _package_version("xgboost"),
            "spacy": _package_version("spacy"),
        },
        "provenance": {
            "available": bool(provenance),
            "metadata": provenance,
        },
        "warnings": warnings,
    }


def _install_pickle_compatibility_symbol() -> None:
    import __main__

    if not hasattr(__main__, "lematizador_spacy"):
        __main__.lematizador_spacy = lambda text: str(text).lower().split()


def load_and_audit(model_path: Path) -> dict[str, Any]:
    if not model_path.is_file():
        raise AuditError(f"Model not found: {model_path}")
    _install_pickle_compatibility_symbol()
    try:
        with model_path.open("rb") as handle:
            artifact = pickle.load(handle)
    except Exception as exc:
        raise AuditError(f"Could not load model: {exc}") from exc
    return audit_artifact(artifact, model_path.resolve())


def render_markdown(report: dict[str, Any]) -> str:
    mapping = report["class_mapping"]
    features = report["feature_dimensions"]
    provenance = report["provenance"]
    lines = [
        "# Classifier audit",
        "",
        f"- Model: `{report['model_path']}`",
        f"- Loadable: `{str(report['loadable']).lower()}`",
        f"- Classes: `{mapping['classes']}`",
        f"- Phishing class value: `{mapping['phishing_class_value']}`",
        f"- Phishing probability index: `{mapping['phishing_probability_index']}`",
        f"- Mapping basis: `{mapping['mapping_basis']}`",
        f"- Current probability access: `{report['production_probability_access']}`",
        f"- Probability access status: `{report['production_probability_status']}`",
        f"- Production threshold: `{report['threshold']}`",
        "",
        "## Feature dimensions",
        "",
        f"- TF-IDF: `{features['tfidf']}`",
        f"- Metadata: `{features['metadata']}`",
        f"- Slots: `{features['slots']}`",
        f"- URL: `{features['url']}`",
        f"- Readability: `{features['readability']}`",
        f"- Produced total: `{features['produced_total']}`",
        f"- Model expected total: `{features['model_expected_total']}`",
        f"- Dimensions match: `{features['matches']}`",
        "",
        "## Provenance",
        "",
        f"- Training provenance available: `{str(provenance['available']).lower()}`",
        "",
        "## Runtime",
        "",
    ]
    lines.extend(f"- {name}: `{version}`" for name, version in report["runtime_versions"].items())
    lines.extend(["", "## Warnings", ""])
    lines.extend(f"- {warning}" for warning in report["warnings"] or ["None."])
    return "\n".join(lines) + "\n"


def write_report(report: dict[str, Any], output_prefix: Path) -> tuple[Path, Path]:
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = output_prefix.with_suffix(".json")
    markdown_path = output_prefix.with_suffix(".md")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "reports" / "classifier_audit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = load_and_audit(args.model)
        paths = write_report(report, args.output)
    except AuditError as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 1
    print(f"Audit written to {paths[0]} and {paths[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
