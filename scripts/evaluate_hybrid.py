"""Evaluate a saved hybrid artifact on a JSONL diagnostic corpus, without SLM."""

import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.classifier_corpus import validate_dataset, dataset_sha256
from scripts.evaluate_classifier import evaluate_records, write_outputs, _manifest_warnings
from services.hybrid_classifier import HybridClassifier


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compare-legacy', action='store_true')
    args = parser.parse_args()
    records, validation = validate_dataset(args.dataset)
    warnings = _manifest_warnings(args.dataset) + validation['warnings']
    classifier = HybridClassifier(args.model)

    def classify(payload):
        result = classifier.analyze(payload)
        return dict(raw_score=result.raw_model_score, risk_score=result.risk_score,
                    is_phishing=result.is_phishing, decision_source=result.decision_source,
                    security_adjustments=result.security_adjustments, content_signals=result.content_signals)

    adapter = SimpleNamespace(_classify_payload=classify, UMBRAL_CRITICO=classifier.manifest['threshold'])
    rows, metrics, extra = evaluate_records(records, adapter)
    report = dict(dataset=str(args.dataset), dataset_sha256=dataset_sha256(args.dataset),
                  model=str(args.model), case_count=len(rows), partial=False, seed=42,
                  metrics=metrics, warnings=warnings + extra + ['Diagnostic corpus is not independent validation.'],
                  threshold=classifier.manifest['threshold'])
    write_outputs(report, rows, args.output)
    print(json.dumps(metrics['final']['confusion_matrix']))
    if args.compare_legacy:
        from services import analyzer
        legacy_rows, legacy_metrics, legacy_extra = evaluate_records(records, analyzer)
        legacy_report = dict(report, model=str(analyzer.DEFAULT_MODEL_PATH), metrics=legacy_metrics,
                             threshold=float(analyzer.UMBRAL_CRITICO), warnings=warnings + legacy_extra)
        write_outputs(legacy_report, legacy_rows, args.output.with_name(args.output.name + '_legacy'))
        print('Legacy: ' + json.dumps(legacy_metrics['final']['confusion_matrix']))


if __name__ == '__main__':
    main()
