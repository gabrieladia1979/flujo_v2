"""Changes that affect inference must invalidate diagnostic prediction caches."""
import pytest

from scripts.hybrid_lime_cache import inference_fingerprint


@pytest.mark.parametrize('changed_file', ['dataset.csv', 'model/encoder/tokenizer.json',
                                        'model/encoder/model.safetensors', 'services/hybrid_features.py'])
def test_prediction_cache_fingerprint_tracks_inputs(tmp_path, monkeypatch, changed_file):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('scripts.hybrid_lime_cache.importlib.metadata.version', lambda package: 'test-version')
    files = ['dataset.csv', 'services/hybrid_classifier.py', 'services/hybrid_encoder.py',
             'services/hybrid_features.py', 'model/manifest.json',
             'model/finetuned_embeddings_xgboost.json', 'model/encoder/model.safetensors',
             'model/encoder/tokenizer.json']
    for name in files:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'original')
    baseline = inference_fingerprint('model', 'dataset.csv', 'cpu')
    assert baseline == inference_fingerprint('model', 'dataset.csv', 'cpu')
    assert baseline != inference_fingerprint('model', 'dataset.csv', 'cuda:0')
    (tmp_path / changed_file).write_bytes(b'changed')
    assert baseline != inference_fingerprint('model', 'dataset.csv', 'cpu')
