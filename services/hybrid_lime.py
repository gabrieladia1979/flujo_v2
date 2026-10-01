"""Optional local word attribution for the raw hybrid classifier score."""

from __future__ import annotations

import math
import time

MAX_BODY_CHARS = 4000
MIN_SAMPLES = 64
MAX_SAMPLES = 256
VALIDATION_SAMPLES = 32
MAX_ORIGINAL_SCORE_ERROR = 0.01


def explain_hybrid_text(classifier, payload, *, num_samples: int = 128) -> dict:
    """Perturb only the body; hold subject and header-derived features fixed."""
    if not MIN_SAMPLES <= num_samples <= MAX_SAMPLES:
        raise ValueError(f"num_samples must be between {MIN_SAMPLES} and {MAX_SAMPLES}")
    body = (payload.contenido or "").strip()
    if not body or len(body) > MAX_BODY_CHARS:
        raise ValueError(f"Email body must contain 1 to {MAX_BODY_CHARS} characters")

    import numpy as np
    from lime.lime_text import IndexedString, LimeTextExplainer
    from xgboost import DMatrix

    from services.hybrid_encoder import embed
    from services.hybrid_features import encoder_text, technical_features

    subject = payload.metadata.asunto or ""
    if IndexedString(body).num_words() < 2:
        raise ValueError("Email body needs at least two words for LIME")
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

    # LIME's score is measured on the perturbations used to fit the surrogate.
    # Check the same surrogate against fresh perturbations before calling it reliable.
    indexed = explanation.domain_mapper.indexed_string
    word_count = indexed.num_words()
    rng = np.random.default_rng(43)
    removed = [set(rng.choice(word_count, size=int(rng.integers(1, word_count + 1)),
                              replace=False).tolist()) for _ in range(VALIDATION_SAMPLES)]
    heldout_bodies = [indexed.inverse_removing(sorted(indices)) for indices in removed]
    heldout_actual = predict_proba(heldout_bodies)[:, 1]
    coefficients = dict(explanation.local_exp[1])
    intercept = float(explanation.intercept[1])
    heldout_estimated = np.asarray([
        intercept + sum(weight for index, weight in coefficients.items() if index not in indices)
        for indices in removed
    ])
    squared_error = float(np.square(heldout_actual - heldout_estimated).sum())
    total_variance = float(np.square(heldout_actual - heldout_actual.mean()).sum())
    heldout_r2 = 1 - squared_error / total_variance if total_variance > 1e-10 else None
    heldout_mae = float(np.mean(np.abs(heldout_actual - heldout_estimated)))
    original_estimated = intercept + sum(coefficients.values())
    original_error = abs(original_estimated - score)
    reliable = (fidelity >= 0.7 and heldout_r2 is not None and heldout_r2 >= 0.7
                and original_error <= MAX_ORIGINAL_SCORE_ERROR)
    return {
        "method": "LIME text",
        "scope": "raw_hybrid_model_score; body words perturbed; subject and header features fixed; body-derived features recalculated",
        "phishing_probability": score,
        "local_fidelity_r2": fidelity,
        "heldout_fidelity_r2": heldout_r2,
        "heldout_mae": heldout_mae,
        "original_surrogate_probability": original_estimated,
        "original_prediction_error": original_error,
        "max_original_prediction_error": MAX_ORIGINAL_SCORE_ERROR,
        "reliable_local_fit": reliable,
        "interpretation_warning": (
            "Local explanation failed the fit, fresh-perturbation or original-score check; do not show word weights to end users."
            if not reliable else
            "Local approximation only; security rules can change the final decision."
        ),
        "word_weights": [
            {"word": word, "weight": float(weight)}
            for word, weight in explanation.as_list(label=1)
        ],
        "num_samples": num_samples,
        "elapsed_seconds": round(time.perf_counter() - start, 3),
    }
