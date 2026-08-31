import sys

with open('services/analyzer.py', 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Add Cache logic and imports
code = code.replace(
    'def analyze_email(payload: EmailPayloadSchema) -> AnalysisResultSchema:',
    'import hashlib\n\n_ANALYSIS_CACHE = {}\n\ndef analyze_email(payload: EmailPayloadSchema) -> AnalysisResultSchema:'
)

code = code.replace(
    '# 1. Extracción de variables del payload\n    asunto = payload.metadata.asunto or ""',
    '# 1. Extracción de variables del payload\n    content_hash = hashlib.sha256(f"{payload.metadata.asunto}|{payload.contenido}".encode("utf-8")).hexdigest()\n    if content_hash in _ANALYSIS_CACHE:\n        print(f"[Cache] Hit para {content_hash[:8]}")\n        return _ANALYSIS_CACHE[content_hash]\n\n    asunto = payload.metadata.asunto or ""'
)

# 2. Add SLM integration at the end
old_return = '''    # 10. Respuesta final
    return AnalysisResultSchema(
        is_phishing=is_phishing,
        risk_score=round(float(risk_score), 4),
        reason=reason,
        intent=intent,
        slots_detectados=slots,
        security_adjustments=security_adjustments
    )'''

new_return = '''    # 10. Respuesta final
    from services.explainer import generate_safe_email_response, extract_shap_insights, generate_slm_prompt
    
    slm_explanation = None
    if is_phishing:
        try:
            insights = extract_shap_insights(calibrated_model, X_input, tfidf)
            slm_prompt = generate_slm_prompt(insights, slots, security_adjustments)
            slm_explanation = f"[Borrador del SLM]: Analicé este correo y encontré riesgos. {', '.join(insights)}."
        except Exception as e:
            print(f"Error en explicabilidad: {e}")
            slm_explanation = "Este correo contiene elementos maliciosos detectados por nuestra IA."
    else:
        slm_explanation = generate_safe_email_response(security_adjustments)

    final_result = AnalysisResultSchema(
        is_phishing=is_phishing,
        risk_score=round(float(risk_score), 4),
        reason=reason,
        intent=intent,
        slots_detectados=slots,
        security_adjustments=security_adjustments,
        slm_explanation=slm_explanation
    )
    _ANALYSIS_CACHE[content_hash] = final_result
    return final_result'''

code = code.replace(old_return, new_return)

with open('services/analyzer.py', 'w', encoding='utf-8') as f:
    f.write(code)
