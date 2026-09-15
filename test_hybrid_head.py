"""Regression for native XGBoost intercept compatibility across major versions."""

import json

import numpy as np
import pytest
import xgboost as xgb

from services.hybrid_classifier import load_hybrid_head


@pytest.mark.parametrize('vector_intercept', [False, True])
def test_native_head_preserves_nondefault_intercept(tmp_path, vector_intercept):
    data = xgb.DMatrix(np.arange(24, dtype=np.float32).reshape(12, 2),
                       label=[0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1])
    original = xgb.train({'objective': 'binary:logistic', 'base_score': 0.73,
                          'max_depth': 2, 'nthread': 1}, data, num_boost_round=2)
    path = tmp_path / 'head.json'
    original.save_model(path)
    saved = json.loads(path.read_text())
    saved['learner']['learner_model_param']['base_score'] = '[7.3E-1]' if vector_intercept else '7.3E-1'
    path.write_text(json.dumps(saved))
    restored = load_hybrid_head(path)
    np.testing.assert_allclose(restored.predict(data), original.predict(data), atol=1e-7)


def test_rejects_multitarget_head(tmp_path):
    path = tmp_path / 'head.json'
    path.write_text(json.dumps({'learner': {'objective': {'name': 'binary:logistic'},
                                          'learner_model_param': {'base_score': '[0.2,0.8]'}}}))
    with pytest.raises(ValueError, match='single intercept'):
        load_hybrid_head(path)
