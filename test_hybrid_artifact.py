"""Explicit opt-in tests of real trained weights; no model downloads.

Set HYBRID_TEST_ARTIFACT and HYBRID_TEST_REPORT after a training run.
"""

import csv
import json
import os
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest
from fastapi.testclient import TestClient

from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema

pytestmark = pytest.mark.skipif(not os.getenv('HYBRID_TEST_ARTIFACT'), reason='Requires explicit local trained artifact')


@pytest.fixture(scope='module')
def trained():
    from services.hybrid_classifier import HybridClassifier
    return HybridClassifier(Path(os.environ['HYBRID_TEST_ARTIFACT']))


def test_short_text_encoding_matches_pretrained_tokenization(trained):
    from services.hybrid_encoder import embed
    texts = ['Nos reunimos mañana en la oficina.', 'Please send your password to verify your account.']
    expected = trained.encoder.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    assert np.allclose(embed(trained.encoder, texts), expected, atol=1e-5)


def test_saved_artifact_reproduces_heldout_raw_score(trained):
    report = json.loads(Path(os.environ['HYBRID_TEST_REPORT']).read_text(encoding='utf-8'))
    split = json.loads((trained.directory / 'splits.json').read_text(encoding='utf-8'))
    first = split['test'][0]['id']
    dataset = Path(report['configuration']['dataset'])
    csv.field_size_limit(10_000_000)
    with dataset.open(encoding='utf-8-sig', newline='') as handle:
        row = next(row for line, row in enumerate(csv.DictReader(handle), 2) if f'row-{line}' == first)
        payload = EmailPayloadSchema(metadata=MetadataSchema(asunto=row['subject']), contenido=row['body'],
                                     security_features=SecurityFeaturesSchema(attachment_count=int(float(row.get('attachments_count') or 0)),
                                                                              received_hop_count=int(float(row.get('hops_count') or 0))))
    actual = trained.raw_score(payload)
    expected = report['results']['finetuned_embeddings_xgboost']['test_scores'][0]
    assert actual == pytest.approx(expected, abs=1e-6)


def test_real_hybrid_http_and_explanation(trained):
    import main
    with patch.dict(os.environ, {'PHISHARG_HYBRID_MODEL_DIR':str(trained.directory)}), \
         patch('services.hybrid_classifier._load', return_value=trained):
        response = TestClient(main.app).post('/api/v1/analyze/hybrid',
            headers={main.API_KEY_NAME:main.API_KEY}, json={
                'metadata':{'asunto':'Verificación pendiente'},
                'contenido':'Responda este correo con su contraseña y código SMS para evitar el bloqueo.',
            })
    assert response.status_code == 200
    result = response.json()
    assert result['is_phishing'] is True and result['risk_score'] >= 0.95
    assert 0 <= result['raw_model_score'] <= 1
    assert result['decision_source'] == 'hybrid_content_security_rule'
    explanation = json.loads(result['slm_explanation'])
    assert explanation['reasons'][0]['evidence_id'] == 'content.credential_disclosure_request'


def test_neural_weights_actually_changed(trained):
    tuning = trained.manifest['fine_tuning']
    assert tuning['steps'] > 0 and tuning['trainable_parameters'] > 0
    assert tuning['before_sha256'] != tuning['after_last_epoch_sha256']
