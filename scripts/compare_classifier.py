"""Compare probability columns offline, without changing the production contract."""

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from unittest.mock import patch
from contextlib import nullcontext

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.classifier_corpus import validate_dataset, dataset_sha256
from scripts.evaluate_classifier import evaluate_records, _manifest_warnings


def compare(records, analyzer):
    runs = {}
    for index in (0, 1):
        with patch.object(analyzer, "PRODUCTION_PHISHING_PROBABILITY_INDEX", index):
            rows, metrics, warnings = evaluate_records(records, analyzer)
        runs[str(index)] = {"rows": rows, "metrics": metrics, "warnings": warnings}
    return runs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--disable-content-rules", action="store_true",
                        help="Offline ablation only; never changes server configuration")
    args = parser.parse_args()
    records, validation = validate_dataset(args.dataset)
    warnings = _manifest_warnings(args.dataset)
    from services import analyzer
    if analyzer.modelo_exportado is None:
        raise RuntimeError("The real classifier could not be loaded")
    import sklearn
    import xgboost
    import spacy
    with (patch('services.content_rules.detect_content_signals', return_value=[])
          if args.disable_content_rules else nullcontext()):
        runs = compare(records, analyzer)
    report = {
        "dataset_sha256": dataset_sha256(args.dataset),
        "model_sha256": hashlib.sha256(analyzer.DEFAULT_MODEL_PATH.read_bytes()).hexdigest(),
        "threshold": float(analyzer.UMBRAL_CRITICO),
        "production_index": analyzer.PRODUCTION_PHISHING_PROBABILITY_INDEX,
        "content_rules_enabled": not args.disable_content_rules,
        "environment": {"python": platform.python_version(), "sklearn": sklearn.__version__,
                        "xgboost": xgboost.__version__, "spacy": spacy.__version__},
        "validation": validation, "warnings": warnings,
        "runs": runs,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.with_suffix(".json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = ["# Comparación local del clasificador", "",
             "Corpus de diagnóstico incompleto; no mide calidad productiva ni es un holdout verificado.", "",
             f"Modelo SHA256: `{report['model_sha256']}`. Umbral: `{report['threshold']}`.", "",
             "| Índice | Aciertos | Falsos positivos | Falsos negativos |", "|---|---:|---:|---:|"]
    for index, run in report["runs"].items():
        cm = run["metrics"]["final"]["confusion_matrix"]
        lines.append(f"| {index} | {cm['true_positive'] + cm['true_negative']}/{len(records)} | {cm['false_positive']} | {cm['false_negative']} |")
    lines += ["", "| Caso | Categoría | Esperado | Score 0 | Resultado 0 | Score 1 | Resultado 1 |", "|---|---|---|---:|---|---:|---|"]
    for left, right in zip(report["runs"]["0"]["rows"], report["runs"]["1"]["rows"]):
        lines.append(f"| {left['id']} | {left['category']} | {left['expected_label']} | {left['final_score']:.4f} | {left['predicted_label']} | {right['final_score']:.4f} | {right['predicted_label']} |")
    args.output.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:9]))


if __name__ == "__main__":
    main()
