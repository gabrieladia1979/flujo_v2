"""Focused tests for classifier audit, corpus validation, and evaluation metrics."""

import tempfile
import unittest
from pathlib import Path

from scripts.audit_classifier import AuditError, audit_artifact, resolve_phishing_class
from scripts.classifier_corpus import validate_records
from scripts.evaluate_classifier import calculate_metrics, evaluate_records, select_records, write_outputs


class _Component:
    def __init__(self, feature_count):
        self.n_features_in_ = feature_count


class _Vectorizer(_Component):
    def __init__(self, feature_count):
        super().__init__(feature_count)
        self.vocabulary_ = {f"token-{index}": index for index in range(feature_count)}
        self.ngram_range = (1, 2)
        self.max_features = feature_count


class _Classifier(_Component):
    def __init__(self, classes=(0, 1), feature_count=26):
        super().__init__(feature_count)
        self.classes_ = classes


def _artifact(classifier=None):
    return {
        "tfidf": _Vectorizer(4),
        "scaler_meta": _Component(3),
        "scaler_slots": _Component(7),
        "scaler_legibilidad": _Component(1),
        "calibrated_model": classifier or _Classifier(),
        "umbral_critico": 0.8,
        "dominios_oficiales": {"example.test"},
    }


def _record(record_id="case-1", label="phishing", category="credential_theft"):
    return {
        "id": record_id,
        "subject": "Account validation",
        "body": "Use the inactive URL example.invalid to validate the test account.",
        "label": label,
        "category": category,
        "campaign_id": f"campaign-{record_id}",
        "security_features": {},
        "source": "test_fixture",
    }


class AuditTests(unittest.TestCase):
    def test_resolves_numeric_phishing_class_and_feature_dimensions(self):
        report = audit_artifact(_artifact())

        self.assertEqual(0, report["class_mapping"]["phishing_class_value"])
        self.assertEqual(0, report["class_mapping"]["phishing_probability_index"])
        self.assertEqual(
            "configured_production_class_convention",
            report["class_mapping"]["mapping_basis"],
        )
        self.assertEqual("consistent_with_production_contract", report["production_probability_status"])
        self.assertEqual("predict_proba(X)[0][0]", report["production_probability_access"])
        self.assertEqual(26, report["feature_dimensions"]["produced_total"])
        self.assertTrue(report["feature_dimensions"]["matches"])

    def test_resolves_explicit_textual_phishing_class(self):
        mapping = resolve_phishing_class(["legitimate", "phishing"])
        self.assertEqual(1, mapping["phishing_probability_index"])
        self.assertFalse(mapping["matches_production_index"])

    def test_rejects_classifier_without_classes(self):
        with self.assertRaisesRegex(AuditError, "classes_"):
            audit_artifact(_artifact(classifier=_Component(26)))


class CorpusValidationTests(unittest.TestCase):
    def test_accepts_valid_incomplete_corpus(self):
        validation = validate_records([_record()])
        self.assertTrue(validation["valid"])
        self.assertFalse(validation["complete"])
        self.assertEqual(199, validation["shortfalls"]["phishing"])

    def test_rejects_duplicate_ids(self):
        validation = validate_records([_record(), _record()])
        self.assertFalse(validation["valid"])
        self.assertTrue(any("duplicate id" in error for error in validation["errors"]))

    def test_rejects_invalid_label_and_category_pair(self):
        record = _record(label="legitimate", category="credential_theft")
        validation = validate_records([record])
        self.assertFalse(validation["valid"])
        self.assertTrue(any("inconsistent" in error for error in validation["errors"]))

    def test_rejects_unknown_fields_and_identical_content(self):
        record = _record()
        record["unexpected"] = True
        record["body"] = record["subject"]
        validation = validate_records([record])
        self.assertFalse(validation["valid"])
        self.assertTrue(any("unknown fields" in error for error in validation["errors"]))
        self.assertTrue(any("must not be identical" in error for error in validation["errors"]))

    def test_rejects_unknown_security_fields(self):
        record = _record()
        record["security_features"] = {"invented_signal": True}
        validation = validate_records([record])
        self.assertFalse(validation["valid"])
        self.assertTrue(any("unknown security fields" in error for error in validation["errors"]))

    def test_rejects_invalid_security_field_type(self):
        record = _record()
        record["security_features"] = {"scl": "high"}
        validation = validate_records([record])
        self.assertFalse(validation["valid"])
        self.assertTrue(any("scl must be an integer" in error for error in validation["errors"]))


class MetricsAndOutputTests(unittest.TestCase):
    def test_calculates_confusion_matrix_precision_recall_and_f1(self):
        metrics = calculate_metrics(
            ["phishing", "phishing", "legitimate", "legitimate"],
            ["phishing", "legitimate", "phishing", "legitimate"],
            [0.9, 0.4, 0.8, 0.1],
        )
        self.assertEqual(
            {"true_positive": 1, "true_negative": 1, "false_positive": 1, "false_negative": 1},
            metrics["confusion_matrix"],
        )
        self.assertEqual(0.5, metrics["precision_phishing"])
        self.assertEqual(0.5, metrics["recall_phishing"])
        self.assertEqual(0.5, metrics["f1_phishing"])

    def test_returns_null_for_undefined_single_class_metrics(self):
        metrics = calculate_metrics(["legitimate"], ["legitimate"], [0.1])
        self.assertIsNone(metrics["precision_phishing"])
        self.assertIsNone(metrics["recall_phishing"])
        self.assertIsNone(metrics["roc_auc"])

    def test_returns_zero_f1_when_defined_precision_and_recall_are_zero(self):
        metrics = calculate_metrics(
            ["phishing", "legitimate"],
            ["legitimate", "phishing"],
            [0.1, 0.9],
        )
        self.assertEqual(0.0, metrics["precision_phishing"])
        self.assertEqual(0.0, metrics["recall_phishing"])
        self.assertEqual(0.0, metrics["f1_phishing"])

    def test_seeded_limit_is_deterministic(self):
        records = [_record(f"case-{index}") for index in range(10)]
        first = select_records(records, category=None, label=None, limit=4, seed=42)
        second = select_records(list(reversed(records)), category=None, label=None, limit=4, seed=42)
        self.assertEqual([record["id"] for record in first], [record["id"] for record in second])

    def test_evaluator_excludes_critical_rules_from_raw_model_metrics(self):
        class FakeAnalyzer:
            UMBRAL_CRITICO = 0.8

            @staticmethod
            def _classify_payload(payload):
                if payload.metadata.asunto == "Critical":
                    return {
                        "raw_score": None,
                        "risk_score": 1.0,
                        "is_phishing": True,
                        "decision_source": "critical_security_rule",
                        "security_adjustments": [],
                    }
                return {
                    "raw_score": 0.7,
                    "risk_score": 0.9,
                    "is_phishing": True,
                    "decision_source": "model_and_security_rules",
                    "security_adjustments": [],
                }

        critical = _record("critical")
        critical["subject"] = "Critical"
        adjusted = _record("adjusted")
        adjusted["subject"] = "Adjusted"
        timer_values = iter((1.0, 1.001, 2.0, 2.002))
        rows, metrics, warnings = evaluate_records(
            [critical, adjusted], FakeAnalyzer(), timer=lambda: next(timer_values)
        )

        self.assertIsNone(rows[0]["raw_score"])
        self.assertEqual("critical_security_rule", rows[0]["decision_source"])
        self.assertEqual(0.7, rows[1]["raw_score"])
        self.assertEqual(0.9, rows[1]["final_score"])
        self.assertEqual(1, metrics["raw_model"]["count"])
        self.assertTrue(any("1 critical-rule cases" in warning for warning in warnings))

    def test_report_files_are_deterministic_for_fixed_inputs(self):
        report = {
            "dataset": "fixture.jsonl",
            "model": "fixture.pkl",
            "case_count": 1,
            "partial": True,
            "seed": 42,
            "metrics": {
                "final": calculate_metrics(["phishing"], ["phishing"], [0.9]),
                "raw_model": calculate_metrics(["phishing"], ["phishing"], [0.8]),
            },
            "warnings": ["Fixture report."],
        }
        rows = [{
            "id": "case-1",
            "expected_label": "phishing",
            "predicted_label": "phishing",
            "raw_score": 0.8,
            "final_score": 0.9,
            "decision_source": "model_and_security_rules",
            "security_adjustments": [{"rule": "fixture", "delta": 0.1, "description": "Fixture"}],
            "elapsed_ms": 1.0,
            "category": "credential_theft",
            "correct": True,
        }]
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "report"
            paths = write_outputs(report, rows, prefix)
            first = [path.read_bytes() for path in paths]
            write_outputs(report, rows, prefix)
            second = [path.read_bytes() for path in paths]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
