"""Stable probability ordering for the retrained audit classifier.

The native booster learns 1=phishing. The public classifier preserves the audit
contract classes [0, 1] with class 0=phishing, so predict_proba column 0 is risk.
"""
import numpy as np
import xgboost as xgb


class CalibratedXGBoost:
    def __init__(self, booster, calibration):
        self.estimator = booster
        self.calibration = calibration
        self.classes_ = np.array([0, 1])
        self.n_features_in_ = booster.num_features()

    def predict_proba(self, values):
        matrix = xgb.DMatrix(np.asarray(values, dtype=np.float32))
        margins = self.estimator.predict(matrix, output_margin=True).reshape(-1, 1)
        positive_index = list(self.calibration.classes_).index(1)
        phishing = self.calibration.predict_proba(margins)[:, positive_index]
        return np.column_stack([phishing, 1.0 - phishing])
