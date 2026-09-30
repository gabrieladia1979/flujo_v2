"""Optional local word attribution for the raw hybrid classifier score."""

from __future__ import annotations

import math
import time

MAX_BODY_CHARS = 4000
MIN_SAMPLES = 64
MAX_SAMPLES = 256


def explain_hybrid_text(classifier, payload, *, num_samples: int = 128) -> dict:
    """Perturb only the body; hold subject and header-derived features fixed."""
    if not MIN_SAMPLES <= num_samples <= MAX_SAMPLES:
        raise ValueError(f"num_samples must be between {MIN_SAMPLES} and {MAX_SAMPLES}")
    body = (payload.contenido or "").strip()
    if not body or len(body) > MAX_BODY_CHARS:
        raise ValueError(f"Email body must contain 1 to {MAX_BODY_CHARS} characters")

    import numpy as np
    from lime.lime_text import LimeTextExplainer
    from xgboost import DMatrix

    from services.hybrid_encoder import embed
    from services.hybrid_features import encoder_text, technical_features

    subject = payload.metadata.asunto or ""
    security = payload.security_features
    attachments = security.attachment_count if security else 0
    hops = security.received_hop_count if security else 0

    def predict_proba(bodies):
        texts = [encoder_text(subject, text) for text in bodies]
        features = np.asarray(
            [technical_features(subject, text, attachments, hops) for text in bodies],
            dtype=np.float32,
        )
        with classifier.lock:
            vectors = embed(classifier.encoder, texts)
            scores = np.asarray(
                classifier.head.predict(DMatrix(np.hstack([vectors, features]))),
                dtype=np.float64,
            )
        if not np.all(np.isfinite(scores)) or np.any((scores < 0) | (scores > 1)):
            raise ValueError("Hybrid model returned invalid probabilities")
        return np.column_stack((1 - scores, scores))

    start = time.perf_counter()
    explainer = LimeTextExplainer(class_names=["legitimate", "phishing"], random_state=42)
    explanation = explainer.explain_instance(
        body,
        predict_proba,
        labels=(1,),
        num_features=8,
        num_samples=num_samples,
    )
    score = float(explanation.predict_proba[1])
    fidelity = float(explanation.score)
    if not math.isfinite(score) or not math.isfinite(fidelity):
        raise ValueError("LIME returned non-finite explanation values")
    return {
        "method": "LIME text",
        "scope": "raw_hybrid_model_score; body words perturbed; subject and header features fixed; body-derived features recalculated",
        "phishing_probability": score,
        "local_fidelity_r2": fidelity,
        "reliable_local_fit": fidelity >= 0.7,
        "interpretation_warning": (
            "Low local fidelity: do not treat these word weights as an explanation of the model."
            if fidelity < 0.7 else
            "Local approximation only; security rules can change the final decision."
        ),
        "word_weights": [
            {"word": word, "weight": float(weight)}
            for word, weight in explanation.as_list(label=1)
        ],
        "num_samples": num_samples,
        "elapsed_seconds": round(time.perf_counter() - start, 3),
    }
