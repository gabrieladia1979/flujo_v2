"""Training/serving contract and leakage checks for the separate candidate."""
import csv
import pickle

import numpy as np
import pytest
import xgboost as xgb
from sklearn.linear_model import LogisticRegression

from services.calibrated_xgboost import CalibratedXGBoost
from scripts.train_audit_candidate import load_rows


def test_public_column_zero_means_phishing_and_survives_serialization():
    values = np.array([[0.0]] * 20 + [[1.0]] * 20, dtype=np.float32)
    labels = np.array([0] * 20 + [1] * 20)
    matrix = xgb.DMatrix(values, label=labels)
    booster = xgb.train({"objective": "binary:logistic", "max_depth": 1, "eta": 1.0, "nthread": 1}, matrix, num_boost_round=4)
    margins = booster.predict(matrix, output_margin=True).reshape(-1, 1)
    calibration = LogisticRegression().fit(margins, labels)
    classifier = CalibratedXGBoost(booster, calibration)
    original = classifier.predict_proba(np.array([[0.0], [1.0]]))
    restored = pickle.loads(pickle.dumps(classifier)).predict_proba(np.array([[0.0], [1.0]]))
    assert original[0, 0] < 0.1
    assert original[1, 0] > 0.9
    np.testing.assert_allclose(original.sum(axis=1), 1.0)
    np.testing.assert_allclose(original, restored)


def test_training_rejects_a_group_shared_with_test(tmp_path):
    path = tmp_path / "corpus.csv"
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["row_id", "group_id", "particion", "Label"])
        writer.writeheader()
        writer.writerows([{"row_id": "a", "group_id": "campaign", "particion": "train", "Label": "0"},
                         {"row_id": "b", "group_id": "campaign", "particion": "test", "Label": "1"}])
    with pytest.raises(ValueError, match="multiple partitions"):
        load_rows(path)
