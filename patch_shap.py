import re

with open("services/analyzer.py", "r", encoding="utf-8") as f:
    content = f.read()

target = """    explanation_evidence = build_analyzer_evidence(
        slots_text,
        security_adjustments,
        is_phishing=is_phishing,
        content_signals=content_signals,
    )"""

replacement = """    explanation_evidence = build_analyzer_evidence(
        slots_text,
        security_adjustments,
        is_phishing=is_phishing,
        content_signals=content_signals,
    )
    
    if is_phishing:
        try:
            from services.explainer import extract_shap_insights
            # Extraemos las palabras exactas que dispararon la alerta
            shap_words = extract_shap_insights(calibrated_model, X_input, tfidf_vectorizer)
            if shap_words:
                from services.slm_explanation import ExplanationEvidence, EvidenceSource
                for w in shap_words:
                    if w and not w.startswith("Tiene_") and not w.startswith("URL_"):
                        explanation_evidence.append(ExplanationEvidence(
                            evidence_id="shap.keyword",
                            text=f"El modelo detectó esta palabra como sospechosa: '{w}'",
                            source=EvidenceSource.OBSERVED_SIGNAL
                        ))
        except Exception as e:
            pass"""

content = content.replace(target, replacement)

target2 = """    try:
        from services.slm_client import generate_slm_explanation
        slm_explanation = generate_slm_explanation(explanation_context)
    except Exception:
        # Evita que un fallo del SLM impida devolver el veredicto
        slm_explanation = render_server_fallback(explanation_context)"""

replacement2 = """    if not is_phishing:
        # Fast-path: Si es legítimo, no consumimos recursos del SLM ni SHAP
        slm_explanation = render_server_fallback(explanation_context)
    else:
        try:
            from services.slm_client import generate_slm_explanation
            slm_explanation = generate_slm_explanation(explanation_context)
        except Exception:
            # Evita que un fallo del SLM impida devolver el veredicto
            slm_explanation = render_server_fallback(explanation_context)"""

content = content.replace(target2, replacement2)

with open("services/analyzer.py", "w", encoding="utf-8") as f:
    f.write(content)
print("Patched.")
