"""Opt-in experimental hybrid inference; never replaces the legacy endpoint."""

from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import threading

from schemas import AnalysisResultSchema
from services.hybrid_features import FEATURE_NAMES, FEATURE_VERSION, encoder_text, technical_features


class HybridUnavailableError(RuntimeError):
    pass


def load_hybrid_head(path):
    """Preserve the binary intercept when older XGBoost reads a vector intercept."""
    from xgboost import Booster
    saved = json.loads(Path(path).read_text(encoding='utf-8'))['learner']
    if saved['objective']['name'] != 'binary:logistic':
        raise ValueError('Hybrid head must use binary:logistic')
    raw = json.loads(saved['learner_model_param']['base_score'])
    if isinstance(raw, list):
        if len(raw) != 1:
            raise ValueError('Hybrid head must have a single intercept')
        raw = raw[0]
    intercept = float(raw)
    if not math.isfinite(intercept) or not 0 < intercept < 1:
        raise ValueError('Invalid hybrid intercept')
    head = Booster(params={'nthread': 4})
    head.load_model(path)
    # XGBoost 2.0 silently defaults to 0.5 for the [value] encoding from 3.1+.
    # Reapply the saved value through the public API; keep the artifact intact.
    head.set_param({'nthread': 4, 'base_score': intercept})
    loaded = json.loads(json.loads(head.save_config())['learner']['learner_model_param']['base_score'])
    loaded = loaded[0] if isinstance(loaded, list) else loaded
    if not math.isclose(float(loaded), intercept, rel_tol=1e-6):
        raise ValueError('XGBoost did not preserve the hybrid intercept')
    return head


def validate_manifest(directory):
    directory = Path(directory).resolve()
    manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('format_version') != 1 or manifest.get('feature_version') != FEATURE_VERSION:
        raise ValueError('Unsupported hybrid artifact version')
    if manifest.get('feature_names') != FEATURE_NAMES:
        raise ValueError('Hybrid feature order differs from training')
    if manifest.get('class_mapping') != {'0': 'legitimate', '1': 'phishing'} or manifest.get('phishing_class') != 1:
        raise ValueError('Invalid hybrid label mapping')
    if not isinstance(manifest.get('threshold'), (int, float)) or not math.isfinite(manifest['threshold']) or not 0 <= manifest['threshold'] <= 1:
        raise ValueError('Invalid hybrid threshold')
    if manifest.get('normalization') != 'l2' or manifest.get('token_selection') != 'head_tail':
        raise ValueError('Unsupported encoder preprocessing')
    if manifest.get('encoder_path') != 'encoder' or manifest.get('head_path') != 'finetuned_embeddings_xgboost.json':
        raise ValueError('Unexpected hybrid component paths')
    hashes = manifest.get('hashes', {})
    if manifest['head_path'] not in hashes or not any(k.startswith('encoder/') for k in hashes):
        raise ValueError('Missing artifact hashes')
    for name, expected in hashes.items():
        target = (directory / name).resolve()
        if not target.is_relative_to(directory) or not target.is_file():
            raise ValueError('Invalid artifact file path')
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise ValueError('Hybrid artifact checksum mismatch')
    return manifest


class HybridClassifier:
    def __init__(self, directory):
        from sentence_transformers import SentenceTransformer
        import torch
        self.directory = Path(directory).resolve()
        self.manifest = validate_manifest(self.directory)
        torch.set_num_threads(4)
        self.encoder = SentenceTransformer(str(self.directory / self.manifest['encoder_path']),
                                           device='cpu', local_files_only=True, trust_remote_code=False)
        self.encoder.max_seq_length = self.manifest['max_tokens']
        self.head = load_hybrid_head(self.directory / self.manifest['head_path'])
        expected = self.encoder.get_sentence_embedding_dimension() + len(FEATURE_NAMES)
        if expected != self.head.num_features() or expected != self.manifest['total_features']:
            raise ValueError('Hybrid feature dimensions do not match')
        self.lock = threading.Lock()

    def raw_score(self, payload):
        import numpy as np
        from xgboost import DMatrix
        from services.hybrid_encoder import embed
        subject, body = payload.metadata.asunto or '', payload.contenido or ''
        security = payload.security_features
        features = technical_features(subject, body,
                                      security.attachment_count if security else 0,
                                      security.received_hop_count if security else 0)
        with self.lock:
            vectors = embed(self.encoder, [encoder_text(subject, body)])
            values = np.hstack([vectors, np.asarray([features], dtype=np.float32)])
            score = float(self.head.predict(DMatrix(values))[0])
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError('Invalid hybrid score')
        return score

    def analyze(self, payload):
        from services.content_rules import detect_content_signals
        from services.security_rules import check_critical_threats, apply_security_rules
        from services.slm_explanation import build_analyzer_evidence, build_explanation_context, build_safe_fallback
        security = payload.security_features
        critical, reason = check_critical_threats(security) if security else (False, '')
        signals = detect_content_signals(payload.contenido or '', payload.metadata.asunto or '')
        adjustments = []
        raw = None
        if critical:
            score, phishing, source = 1.0, True, 'hybrid_critical_security_rule'
        else:
            raw = self.raw_score(payload)
            adjustments = apply_security_rules(security) if security else []
            delta = max(-0.25, min(0.35, sum(a.delta for a in adjustments)))
            score = max(0.0, min(1.0, raw + delta))
            source = 'hybrid_model_and_security_rules' if security else 'hybrid_model'
            if signals:
                score = max(score, self.manifest['threshold'], 0.95)
                source = 'hybrid_content_security_rule'
            phishing = score >= self.manifest['threshold']
        intent = 'phishing_sin_intencion_determinada' if phishing else 'comunicacion_operativa'
        if critical:
            intent = 'suplantacion_o_malware'
        elif any(s.rule == 'credential_disclosure_request' for s in signals):
            intent = 'solicitar_credenciales'
        elif any(s.rule == 'payment_redirection_no_verification' for s in signals):
            intent = 'desviar_pago'
        elif any(s.rule == 'mfa_push_fatigue' for s in signals):
            intent = 'robo_de_sesion'
        elif any(s.rule == 'qr_phishing' for s in signals):
            intent = 'solicitar_credenciales'
        evidence = build_analyzer_evidence({}, adjustments, is_phishing=phishing,
                                           critical_reason=reason if critical else None, content_signals=signals)
        context = build_explanation_context(is_phishing=bool(phishing), risk_score=float(score), intent=intent, evidence=evidence)
        summary = 'PHISHING DETECTADO' if phishing else 'LEGÍTIMO'
        return AnalysisResultSchema(is_phishing=bool(phishing), risk_score=round(score, 4),
                                    reason=summary + (': ' + reason if critical else '') +
                                    (': ' + ' '.join(s.description for s in signals) if signals else ''),
                                    intent=intent, security_adjustments=adjustments, content_signals=signals,
                                    raw_model_score=raw, decision_source=source,
                                    slm_explanation=build_safe_fallback(context).model_dump_json())


@lru_cache(maxsize=1)
def _load(directory):
    return HybridClassifier(directory)


def analyze_hybrid_email(payload):
    directory = os.getenv('PHISHARG_HYBRID_MODEL_DIR')
    if not directory:
        raise HybridUnavailableError('El clasificador híbrido experimental no está configurado.')
    try:
        classifier = _load(str(Path(directory).resolve()))
        return classifier.analyze(payload)
    except (ImportError, OSError, ValueError, RuntimeError, KeyError) as exc:
        raise HybridUnavailableError('No se pudo utilizar el clasificador híbrido experimental.') from exc
