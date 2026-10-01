"""Input fingerprint for local, ignored diagnostic prediction caches."""
import hashlib
import importlib.metadata
import sys
from pathlib import Path


def inference_fingerprint(model_directory, dataset, device):
    model = Path(model_directory)
    paths = [Path(dataset), Path('services/hybrid_classifier.py'), Path('services/hybrid_encoder.py'),
             Path('services/hybrid_features.py'), model / 'manifest.json',
             model / 'finetuned_embeddings_xgboost.json']
    paths += sorted(p for p in (model / 'encoder').rglob('*') if p.is_file())
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path).encode())
        with path.open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
    digest.update((sys.version + str(device)).encode())
    for package in ('numpy', 'torch', 'transformers', 'sentence-transformers', 'xgboost', 'lime'):
        digest.update((package + importlib.metadata.version(package)).encode())
    return digest.hexdigest()
