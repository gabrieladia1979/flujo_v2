"""Hybrid V3 inference with bounded model attribution and SLM explanations."""

from functools import lru_cache
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import re
import threading

from schemas import AnalysisResultSchema, HybridXAIResult
from services.hybrid_features import FEATURE_NAMES, FEATURE_VERSION, encoder_text, technical_features


logger = logging.getLogger(__name__)

_FEATURE_EVIDENCE = {
    'http_count': 'enlaces HTTP sin cifrar',
    'ip_host_count': 'enlaces con una dirección IP como dominio',
    'brand_external_count': 'dominios que mencionan una marca fuera de sus dominios oficiales',
    'punycode_count': 'dominios codificados con Punycode',
    'urgency_count': 'expresiones de urgencia',
    'secret_count': 'menciones de credenciales o datos sensibles',
    'payment_count': 'expresiones relacionadas con pagos',
    'threat_count': 'expresiones de amenaza o bloqueo',
    'action_count': 'solicitudes de acción',
}


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

    def technical_attributions(self, payload, raw_score):
        """XGBoost TreeSHAP contributions to the raw log-odds, not to rule-adjusted risk."""
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
            contributions = np.asarray(self.head.predict(DMatrix(values), pred_contribs=True))[0]
        if contributions.shape != (values.shape[1] + 1,) or not np.all(np.isfinite(contributions)):
            raise ValueError('Invalid hybrid SHAP contributions')
        margin = float(contributions.sum())
        reconstructed = 1 / (1 + math.exp(-margin)) if margin >= 0 else math.exp(margin) / (1 + math.exp(margin))
        if not math.isclose(reconstructed, raw_score, abs_tol=1e-5):
            raise ValueError('Hybrid SHAP contributions do not reconstruct the raw score')
        start = vectors.shape[1]
        attributions = [
            {'feature': name, 'value': float(features[index]),
             'contribution_log_odds': float(contributions[start + index])}
            for index, name in enumerate(FEATURE_NAMES)
        ]
        attributions.sort(key=lambda item: abs(item['contribution_log_odds']), reverse=True)
        return attributions, float(contributions[:start].sum()), float(contributions[-1])

    def explain(self, payload, raw_score, *, include_lime=True, lime_samples=128):
        """Return bounded diagnostics; rejected LIME weights never enter the main response."""
        details = dict(technical_status='skipped', lime_status='disabled' if not include_lime else 'skipped')
        if raw_score is None:
            return HybridXAIResult(**details)
        try:
            attributions, embedding, baseline = self.technical_attributions(payload, raw_score)
            details.update(technical_status='available', technical_attributions=attributions,
                           embedding_contribution_log_odds=embedding, baseline_log_odds=baseline)
        except Exception:
            logger.exception('Hybrid technical attribution failed')
            details['technical_status'] = 'error'
        body = (payload.contenido or '').strip()
        if include_lime and 1 <= len(body) <= 4000 and len(body.split()) >= 2:
            try:
                from services.hybrid_lime import explain_hybrid_text
                lime = explain_hybrid_text(self, payload, num_samples=lime_samples)
                if not math.isclose(lime['phishing_probability'], raw_score, abs_tol=1e-5):
                    raise ValueError('LIME explained a different hybrid score')
                reliable = bool(lime['reliable_local_fit'])
                details.update(lime_status='reliable' if reliable else 'unreliable',
                               lime_word_attributions=lime['word_weights'] if reliable else [],
                               lime_fit_r2=lime['local_fidelity_r2'],
                               lime_heldout_r2=lime['heldout_fidelity_r2'],
                               lime_original_prediction_error=lime['original_prediction_error'],
                               lime_reliability_failures=lime.get('reliability_failures', []),
                               lime_heldout_mae=lime.get('heldout_mae'),
                               lime_elapsed_seconds=lime.get('elapsed_seconds'))
            except Exception:
                logger.exception('Hybrid LIME explanation failed')
                details['lime_status'] = 'error'
        return HybridXAIResult(**details)

    def analyze(self, payload, *, include_lime=True, lime_samples=128):
        from services.content_rules import detect_content_signals
        from services.security_rules import check_critical_threats, apply_security_rules
        from services.slm_explanation import (ExplanationEvidence, EvidenceSource,
                                               build_analyzer_evidence, build_explanation_context,
                                               build_safe_fallback, validate_or_fallback_slm_output)
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
        # A critical rule bypasses the model. For other alerts, keep model evidence
        # separate from the rules that may have raised the final risk score.
        xai = self.explain(payload, raw, include_lime=include_lime and phishing,
                           lime_samples=lime_samples)
        if include_lime and not phishing:
            xai.lime_status = 'skipped'
        xai.supports_final_verdict = (raw is not None and
                                      (raw >= self.manifest['threshold']) == bool(phishing))
        if (phishing and raw is not None and raw >= self.manifest['threshold']
                and source in {'hybrid_model', 'hybrid_model_and_security_rules'}):
            model_evidence = []
            if xai.technical_status == 'available':
                for item in xai.technical_attributions:
                    label = _FEATURE_EVIDENCE.get(item.feature)
                    if label and item.value > 0 and item.contribution_log_odds > 0:
                        model_evidence.append(ExplanationEvidence(
                            evidence_id=f'model.{item.feature}',
                            text=f'En la puntuación del modelo, la señal de {label} aportó a favor de phishing.',
                            source=EvidenceSource.CLASSIFIER))
                        break
            if xai.lime_status == 'reliable':
                words = [item.word for item in xai.lime_word_attributions
                         if item.weight > 0 and re.fullmatch(r'[\wáéíóúñÁÉÍÓÚÑ]{2,30}', item.word)]
                if words:
                    model_evidence.append(ExplanationEvidence(
                        evidence_id='model.lime_words',
                        text='La aproximación local LIME vinculó con mayor puntaje de phishing: ' +
                             ', '.join(words[:3]) + '.',
                        source=EvidenceSource.CLASSIFIER))
            evidence = model_evidence + evidence
        context = build_explanation_context(is_phishing=bool(phishing), risk_score=float(score), intent=intent, evidence=evidence)
        summary = 'PHISHING DETECTADO' if phishing else 'LEGÍTIMO'
        explanation_source = 'fallback'
        if phishing:
            try:
                from services.slm_client import generate_slm_explanation
                generated = generate_slm_explanation(context)
                validated = validate_or_fallback_slm_output(generated, context)
                slm_explanation = validated.explanation.model_dump_json()
                if not validated.used_fallback:
                    explanation_source = 'qwen'
            except Exception:
                logger.exception('Hybrid SLM explanation failed')
                slm_explanation = build_safe_fallback(context).model_dump_json()
        else:
            slm_explanation = build_safe_fallback(context).model_dump_json()
        return AnalysisResultSchema(is_phishing=bool(phishing), risk_score=round(score, 4),
                                    reason=summary + (': ' + reason if critical else '') +
                                    (': ' + ' '.join(s.description for s in signals) if signals else ''),
                                    intent=intent, security_adjustments=adjustments, content_signals=signals,
                                    raw_model_score=raw, decision_source=source,
                                    slm_explanation=slm_explanation, explanation_source=explanation_source,
                                    hybrid_xai=xai)


@lru_cache(maxsize=1)
def _load(directory):
    return HybridClassifier(directory)


def analyze_hybrid_email(payload, *, include_lime=True, lime_samples=128):
    directory = os.getenv('PHISHARG_HYBRID_MODEL_DIR')
    if not directory:
        raise HybridUnavailableError('El clasificador Hybrid no está configurado.')
    try:
        classifier = _load(str(Path(directory).resolve()))
        return classifier.analyze(payload, include_lime=include_lime, lime_samples=lime_samples)
    except (ImportError, OSError, ValueError, RuntimeError, KeyError) as exc:
        raise HybridUnavailableError('No se pudo utilizar el clasificador Hybrid.') from exc
