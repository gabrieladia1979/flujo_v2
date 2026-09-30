"""Leakage, feature parity and opt-in backend contracts without downloading models."""

import csv
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest
from fastapi.testclient import TestClient

from scripts.build_hybrid_corpus import collect_source
from scripts.hybrid_data import group_key, grouped_split, load_training_csv
from scripts.train_hybrid import threshold_on_validation
from services.hybrid_features import FEATURE_NAMES, FEATURE_VERSION, encoder_text, prepare_email, technical_features
from services.hybrid_classifier import validate_manifest


def csv_file(path, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_groups_ignore_subject_and_variable_url_numbers():
    assert group_key('Factura uno', 'Pago 123 en https://uno.invalid/a') == group_key(
        'Factura dos', 'Pago 999 en https://dos.invalid/b')


def test_conflicting_body_labels_quarantined_and_source_untouched(tmp_path):
    source = csv_file(tmp_path / 'source.csv', [
        dict(subject='Uno', body='Mismo mensaje', Label='0'),
        dict(subject='Dos', body='Mismo mensaje', Label='1'),
        dict(subject='Tres', body='Mensaje diferente', Label='0'),
    ])
    before = source.read_bytes()
    rows, audit = load_training_csv(source, '1')
    assert len(rows) == 1
    assert audit['skipped']['conflicting_group_rows'] == 2
    assert source.read_bytes() == before


def test_invalid_label_rejected(tmp_path):
    source = csv_file(tmp_path / 'bad.csv', [dict(subject='A', body='B', Label='unknown')])
    with pytest.raises(ValueError, match='Unknown label'):
        load_training_csv(source, '1')


def test_group_split_disjoint_deterministic_and_has_both_classes():
    rows = [dict(label=i % 2, group=f'g-{i//2}') for i in range(120)]
    first, second = grouped_split(rows), grouped_split(rows)
    sets = []
    for name, ids in first.items():
        assert np.array_equal(ids, second[name])
        assert {rows[i]['label'] for i in ids} == {0, 1}
        sets.append({rows[i]['group'] for i in ids})
    assert not sets[0] & sets[1] and not sets[0] & sets[2] and not sets[1] & sets[2]
    assert sum(map(len, first.values())) == len(rows)


def test_neural_text_preserves_case_words_and_tail():
    text = encoder_text('Asunto', 'inicio ' + 'relleno ' * 1000 + 'CONTRASEÑA AL FINAL')
    assert text.startswith('Asunto inicio') and text.endswith('CONTRASEÑA AL FINAL')
    assert len(text) <= 4010


def test_incremental_corpus_keeps_previous_holdout_groups():
    rows = [dict(label=i % 2, group=f'g-{i//2}') for i in range(120)]
    first = grouped_split(rows)
    previous = {name:[{'group':rows[i]['group']} for i in ids] for name,ids in first.items()}
    expanded = rows + [dict(label=i % 2, group=f'new-{i//2}') for i in range(80)]
    second = grouped_split(expanded, previous=previous)
    for name, ids in first.items():
        assert set(ids).issubset(set(second[name]))


def test_html_hidden_url_and_obfuscated_url_features():
    html = '<p>Verificar</p><a href="http://arca-login.invalid">cuenta</a><script>noise</script>'
    text, urls = prepare_email('Aviso', html)
    assert 'noise' not in text and urls == ['http://arca-login.invalid']
    features = dict(zip(FEATURE_NAMES, technical_features('Aviso', html)))
    assert features['http_count'] == features['url_count'] == features['brand_external_count'] == 1
    assert dict(zip(FEATURE_NAMES, technical_features('', 'hxxp://192.0.2.1/login')))['ip_host_count'] == 1


def test_anonymization_placeholders_are_not_html():
    assert 'TELEFONO' in encoder_text('', 'Contactar <TELEFONO>')


def test_training_serving_metadata_defaults_identical(tmp_path):
    source = csv_file(tmp_path / 'source.csv', [dict(subject='Hola', body='Nos vemos', Label='0')])
    rows, _ = load_training_csv(source, '1')
    row = rows[0]
    assert technical_features(row['subject'], row['body'], **row['metadata']) == technical_features('Hola', 'Nos vemos')
    assert len(technical_features('', '')) == len(FEATURE_NAMES)


def test_threshold_constraint_uses_validation_labels():
    labels = np.array([0, 0, 1, 1])
    scores = np.array([0.1, 0.7, 0.65, 0.9])
    threshold = threshold_on_validation(labels, scores, 0.0)
    assert np.all(scores[labels == 0] < threshold)
    assert (scores[labels == 1] >= threshold).sum() == 1


def test_import_does_not_turn_spam_into_phishing(tmp_path):
    source = csv_file(tmp_path / 'mail.csv', [dict(body=f'Email {i}', label=str(i % 2)) for i in range(30)])
    policy = dict(labels={'0': '0'}, language='en', basis='ham only')
    rows, audit = collect_source(source, policy, 3, 42)
    again, _ = collect_source(source, policy, 3, 42)
    assert rows == again and len(rows) == 3
    assert {row['Label'] for row in rows} == {'0'}
    assert audit['rows'] == 30 and audit['eligible'] == 15


def test_webpage_dataset_not_imported_as_email(tmp_path):
    source = csv_file(tmp_path / 'web.csv', [dict(NumDots=3, UrlLength=44, label='1')])
    rows, audit = collect_source(source, None, 0, 42)
    assert not rows and audit['status'] == 'not_email_text'


def manifest_fixture(directory):
    (directory / 'encoder').mkdir()
    (directory / 'encoder' / 'test.json').write_text('{}')
    head = 'finetuned_embeddings_xgboost.json'
    (directory / head).write_text('{}')
    value = dict(format_version=1, feature_version=FEATURE_VERSION, feature_names=FEATURE_NAMES,
                 class_mapping={'0':'legitimate','1':'phishing'}, phishing_class=1, threshold=0.8,
                 normalization='l2', token_selection='head_tail', encoder_path='encoder', head_path=head,
                 hashes={p:hashlib.sha256((directory / p).read_bytes()).hexdigest() for p in [head, 'encoder/test.json']})
    (directory / 'manifest.json').write_text(json.dumps(value))
    return value


def test_corrupt_artifact_rejected(tmp_path):
    manifest_fixture(tmp_path)
    assert validate_manifest(tmp_path)['phishing_class'] == 1
    (tmp_path / 'encoder/test.json').write_text('changed')
    with pytest.raises(ValueError, match='checksum'):
        validate_manifest(tmp_path)


def test_feature_order_mismatch_rejected(tmp_path):
    manifest = manifest_fixture(tmp_path)
    manifest['feature_names'] = list(reversed(FEATURE_NAMES))
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='feature order'):
        validate_manifest(tmp_path)


def test_hybrid_is_opt_in_and_authentication_is_required():
    import main
    payload = {'metadata': {'asunto': 'Prueba'}, 'contenido': 'Mensaje'}
    client = TestClient(main.app)
    assert client.post('/api/v1/analyze/hybrid', json=payload).status_code == 401
    with patch.dict('os.environ', {}, clear=True):
        response = client.post('/api/v1/analyze/hybrid', json=payload, headers={main.API_KEY_NAME:main.API_KEY})
    assert response.status_code == 503
    assert 'is_phishing' not in response.json()


def test_legacy_route_does_not_invoke_hybrid():
    import main
    from schemas import AnalysisResultSchema
    with patch.object(main, 'analyze_email', return_value=AnalysisResultSchema(is_phishing=False, risk_score=0.1, reason='Legacy')), \
         patch('services.hybrid_classifier._load', side_effect=AssertionError('Hybrid must remain opt-in')):
        response = TestClient(main.app).post('/api/v1/analyze', json={'metadata':{},'contenido':'Mensaje'}, headers={main.API_KEY_NAME:main.API_KEY})
    assert response.status_code == 200 and response.json()['reason'] == 'Legacy'
