import re
import numpy as np
import spacy
from spacy.matcher import Matcher
from urllib.parse import urlparse
import hashlib
import pickle
import os

from schemas import EmailPayloadSchema, AnalysisResultSchema, SecurityFeaturesSchema
from services.classifier_contract import (
    DEFAULT_MODEL_PATH,
    PRODUCTION_PHISHING_PROBABILITY_INDEX,
)

# 1. CARGA DE SPACY Y DEFINICIÓN DEL TOKENIZER (DEBE ESTAR ANTES DEL PICKLE LOAD)
try:
    nlp = spacy.load("es_core_news_sm")
    nlp.max_length = 50000
except OSError:
    pass

import __main__
def lematizador_spacy(texto):
    doc = nlp(texto.lower())
    return [token.lemma_ for token in doc if not token.is_punct and not token.is_space and not token.is_stop]
__main__.lematizador_spacy = lematizador_spacy

# 2. CARGA DEL PICKLE V4
modelo_exportado = None
tfidf = None
scaler_meta = None
scaler_slots = None
scaler_legibilidad = None
calibrated_model = None
UMBRAL_CRITICO = 0.91
DOMINIOS_OFICIALES = []


class ClassifierUnavailableError(RuntimeError):
    """Raised when normal model inference is requested without a loaded model."""

def _load_model(model_path=None):
    global modelo_exportado, tfidf, scaler_meta, scaler_slots, scaler_legibilidad
    global calibrated_model, UMBRAL_CRITICO, DOMINIOS_OFICIALES

    selected_path = os.fspath(model_path or DEFAULT_MODEL_PATH)
    try:
        with open(selected_path, 'rb') as f:
            modelo_exportado = pickle.load(f)
        
        tfidf = modelo_exportado['tfidf']
        scaler_meta = modelo_exportado['scaler_meta']
        scaler_slots = modelo_exportado['scaler_slots']
        scaler_legibilidad = modelo_exportado.get('scaler_legibilidad', None)
        calibrated_model = modelo_exportado['calibrated_model']
        UMBRAL_CRITICO = modelo_exportado['umbral_critico']
        DOMINIOS_OFICIALES = modelo_exportado.get('dominios_oficiales', [])
        print("[Analyzer] Modelo XGBoost V4 cargado exitosamente.")
    except Exception as e:
        modelo_exportado = None
        tfidf = None
        scaler_meta = None
        scaler_slots = None
        scaler_legibilidad = None
        calibrated_model = None
        print(f"[!] Error crítico cargando el modelo real: {e}")

_load_model()

# 3. REGLAS NLU (6 CATEGORÍAS)
def _crear_matcher():
    matcher = Matcher(nlp.vocab)
    matcher.add("URGENCIA", [[{"LOWER": {"IN": ["inmediatamente", "asap", "suspensión", "suspendida", "bloqueada", "bloqueado"]}}], [{"LOWER": "acción"}, {"LOWER": "requerida"}], [{"LOWER": "último"}, {"LOWER": "aviso"}], [{"LOWER": "evitar"}, {"LOWER": "la"}, {"LOWER": "suspensión"}]])
    matcher.add("AUTORIDAD", [[{"LOWER": {"IN": ["afip", "arca", "anses", "bcra", "mastercard", "mercadopago", "netflix"]}}], [{"LOWER": "red"}, {"LOWER": "link"}], [{"LOWER": "cajero"}, {"LOWER": "link"}], [{"LOWER": "banco"}, {"IS_TITLE": True}], [{"LOWER": "agencia"}, {"LOWER": "de"}, {"LOWER": "recaudación"}]])
    matcher.add("FINANCIERO", [[{"LOWER": {"IN": ["cbu", "alias", "deuda", "token", "cvv", "embargo"]}}], [{"LOWER": "código"}, {"LOWER": "de"}, {"LOWER": "seguridad"}], [{"LOWER": "código"}, {"LOWER": "pin"}], [{"LOWER": "código"}, {"LOWER": "sms"}], [{"LOWER": "clave"}, {"LOWER": "fiscal"}], [{"LOWER": "actualizar"}, {"LOWER": "datos"}]])
    matcher.add("AMENAZA", [[{"LOWER": "acciones"}, {"LOWER": "legales"}], [{"LOWER": "embargo"}, {"LOWER": "preventivo"}], [{"LOWER": "embargo"}, {"LOWER": "de"}, {"LOWER": {"IN": ["bienes", "cuentas"]}}], [{"LOWER": {"IN": ["infracción", "sanción", "sanciones", "penalidad"]}}], [{"LOWER": "será"}, {"LOWER": {"IN": ["bloqueada", "bloqueado", "suspendida", "suspendido", "embargada", "embargado"]}}]])
    matcher.add("CALL_TO_ACTION", [[{"LOWER": "haciendo"}, {"LOWER": "clic"}], [{"LOWER": "haga"}, {"LOWER": "clic"}], [{"LOWER": "ingrese"}, {"LOWER": {"IN": ["al", "a", "en"]}}], [{"LOWER": "acceda"}, {"LOWER": {"IN": ["al", "a"]}}], [{"LOWER": "verifique"}, {"LOWER": "su"}], [{"LOWER": "verificá"}, {"LOWER": "tu"}], [{"LOWER": "actualizá"}, {"LOWER": "tu"}], [{"LOWER": "complete"}, {"LOWER": "la"}, {"LOWER": "verificación"}]])
    matcher.add("TEMPORAL", [[{"LIKE_NUM": True}, {"LOWER": {"IN": ["horas", "días", "minutos"]}}], [{"LOWER": "plazo"}, {"LOWER": {"IN": ["máximo", "de"]}}], [{"LOWER": "días"}, {"LOWER": "hábiles"}]])
    return matcher

matcher_global = _crear_matcher()

# 4. FUNCIONES DE UTILIDAD (URL, TYPOSQUATTING, LEGIBILIDAD)
def extraer_urls(texto): 
    return re.findall(r'https?://[^\s<>"\'\)\]]+|www\.[^\s<>"\'\)\]]+', str(texto), re.IGNORECASE)

def extraer_dominio(url):
    try: 
        return urlparse(url if url.startswith('http') else f'http://{url}').hostname.lower().lstrip('www.')
    except: 
        return ''

def dominio_es_oficial(dominio): 
    return bool(dominio) and any(dominio == o or dominio.endswith('.' + o) for o in DOMINIOS_OFICIALES)

def damerau_levenshtein(s1, s2):
    len_s1, len_s2 = len(s1), len(s2)
    d = [[0] * (len_s2 + 1) for _ in range(len_s1 + 1)]
    for i in range(len_s1 + 1): d[i][0] = i
    for j in range(len_s2 + 1): d[0][j] = j
    for i in range(1, len_s1 + 1):
        for j in range(1, len_s2 + 1):
            cost = 0 if s1[i-1] == s2[j-1] else 1
            d[i][j] = min(d[i-1][j] + 1, d[i][j-1] + 1, d[i-1][j-1] + cost)
            if i > 1 and j > 1 and s1[i-1] == s2[j-2] and s1[i-2] == s2[j-1]: d[i][j] = min(d[i][j], d[i-2][j-2] + cost)
    return d[len_s1][len_s2]

def indice_fernandez_huerta(texto):
    palabras = re.findall(r'\b[a-záéíóúüñ]+\b', str(texto).lower())
    if len(palabras) < 5: return 50.0
    silabas = sum(max(sum(1 for char in p if char in "aeiouáéíóúü" and (p.index(char)==0 or p[p.index(char)-1] not in "aeiouáéíóúü")), 1) for p in palabras)
    frases = max(len([f for f in re.split(r'[.!?]+', str(texto)) if f.strip()]), 1)
    return round(206.84 - (0.60 * (silabas/len(palabras)*100)) - (1.02 * (frases/len(palabras)*100)), 2)

def _apply_security_adjustments(risk_score, is_phishing, security_features):
    from services.security_rules import apply_security_rules
    adjustments = apply_security_rules(security_features)
    total_delta = sum(adj.delta for adj in adjustments)
    # Limitar el delta acumulado para evitar que múltiples señales leves
    # empujen un correo legítimo por encima del umbral de phishing.
    total_delta = max(min(total_delta, 0.35), -0.25)
    adjusted_score = min(max(risk_score + total_delta, 0.0), 1.0)
    adjusted_is_phishing = adjusted_score >= UMBRAL_CRITICO
    return adjusted_score, adjusted_is_phishing, adjustments

_ANALYSIS_CACHE = {}

def _classify_payload(payload: EmailPayloadSchema) -> dict:
    """Run the authoritative classifier and expose internal evaluation diagnostics."""
    from services.security_rules import check_critical_threats

    if payload.security_features:
        es_critico, razon_critica = check_critical_threats(payload.security_features)
        if es_critico:
            return {
                "raw_score": None,
                "risk_score": 1.0,
                "is_phishing": True,
                "intent": "suplantacion_o_malware",
                "slots_detectados": {},
                "security_adjustments": [],
                "decision_source": "critical_security_rule",
                "critical_reason": razon_critica,
            }

    asunto = payload.metadata.asunto or ""
    remitente_email = payload.metadata.remitente_email or ""

    contenido_raw = payload.contenido or ""
    contenido = re.sub(r'<[^>]+>', ' ', contenido_raw)
    contenido = re.sub(r'\s+', ' ', contenido).strip()

    attachments_count = payload.security_features.attachment_count if payload.security_features else 0
    hops_count = payload.security_features.received_hop_count if payload.security_features else 3

    if calibrated_model is None or tfidf is None or nlp is None:
        raise ClassifierUnavailableError("El modelo de IA no se encuentra cargado.")

    urls = extraer_urls(contenido)
    url_count = len(urls)

    doc = nlp(f"{asunto} {contenido}")
    slots_count = {"URGENCIA": 0, "AUTORIDAD": 0, "FINANCIERO": 0, "AMENAZA": 0, "CALL_TO_ACTION": 0, "TEMPORAL": 0}
    slots_text = {"URGENCIA": [], "AUTORIDAD": [], "FINANCIERO": [], "AMENAZA": [], "CALL_TO_ACTION": [], "TEMPORAL": []}

    for match_id, start, end in matcher_global(doc):
        cat = nlp.vocab.strings[match_id]
        slots_count[cat] += 1
        slots_text[cat].append(doc[start:end].text)

    tiene_url = 1 if urls else 0
    url_usa_http = 0; url_oficial_val = 0; url_suplantada_val = 0; url_tiene_ip_val = 0; typosquatting_val = 0
    entidades_suplantables = ["afip", "arca", "bcra", "anses", "mercadopago", "galicia", "santander", "macro", "nacion", "redlink", "netflix", "correo", "pami"]

    for u in urls:
        if u.startswith('http://'): url_usa_http = 1
        dom = extraer_dominio(u)
        if dominio_es_oficial(dom): url_oficial_val = 1
        for ent in entidades_suplantables:
            if ent in dom and not dominio_es_oficial(dom): url_suplantada_val = 1; break
        if re.match(r'\d+\.\d+\.\d+\.\d+', dom or ''): url_tiene_ip_val = 1
        if not dominio_es_oficial(dom) and any(1 <= damerau_levenshtein(dom, o) <= 2 for o in DOMINIOS_OFICIALES): typosquatting_val = 1

    ifh = indice_fernandez_huerta(f"{asunto} {contenido}")

    vec_text = tfidf.transform([f"{asunto} {contenido}"]).toarray()
    vec_meta = scaler_meta.transform([[url_count, attachments_count, hops_count]])
    vec_slots = scaler_slots.transform([[slots_count['URGENCIA'], slots_count['AUTORIDAD'], slots_count['FINANCIERO'], slots_count['AMENAZA'], slots_count['CALL_TO_ACTION'], slots_count['TEMPORAL'], url_count]])
    vec_url = np.array([[tiene_url, tiene_url, url_usa_http, url_usa_http, url_oficial_val, url_oficial_val, url_suplantada_val, url_suplantada_val, url_tiene_ip_val, url_tiene_ip_val, typosquatting_val]])

    if scaler_legibilidad:
        vec_legibilidad = scaler_legibilidad.transform([[ifh]])
        X_input = np.hstack([vec_text, vec_meta, vec_slots, vec_url, vec_legibilidad])
    else:
        X_input = np.hstack([vec_text, vec_meta, vec_slots, vec_url, np.array([[ifh]])])

    if remitente_email and "@" in remitente_email:
        sender_dom = remitente_email.split("@")[-1].lower()
        if payload.security_features:
            payload.security_features.is_trusted_domain = dominio_es_oficial(sender_dom)

    raw_score = float(
        calibrated_model.predict_proba(X_input)[0][PRODUCTION_PHISHING_PROBABILITY_INDEX]
    )
    risk_score = raw_score
    is_phishing = raw_score >= UMBRAL_CRITICO

    security_adjustments = None
    decision_source = "model_only"
    if payload.security_features is not None:
        risk_score, is_phishing, security_adjustments = _apply_security_adjustments(
            risk_score, is_phishing, payload.security_features
        )
        decision_source = "model_and_security_rules"

    if not is_phishing:
        intent = "comunicacion_operativa"
    elif slots_count['FINANCIERO'] > 0:
        intent = "coaccionar_pago"
    else:
        intent = "solicitar_credenciales"

    return {
        "raw_score": raw_score,
        "risk_score": risk_score,
        "is_phishing": is_phishing,
        "intent": intent,
        "slots_detectados": slots_text,
        "security_adjustments": security_adjustments,
        "decision_source": decision_source,
        "critical_reason": None,
        "feature_count": int(X_input.shape[1]),
    }


def analyze_email(payload: EmailPayloadSchema) -> AnalysisResultSchema:
    from services.slm_explanation import (
        build_analyzer_evidence,
        build_explanation_context,
        render_server_fallback,
    )

    sec_str = str(payload.security_features.model_dump()) if payload.security_features else ""
    content_hash = hashlib.sha256(
        f"{payload.metadata.asunto}|{payload.contenido}|{sec_str}".encode("utf-8")
    ).hexdigest()
    if content_hash in _ANALYSIS_CACHE:
        return _ANALYSIS_CACHE[content_hash]

    try:
        diagnostics = _classify_payload(payload)
    except ClassifierUnavailableError:
        return AnalysisResultSchema(
            is_phishing=False, risk_score=0.0, reason="Error interno: El modelo de IA no se encuentra cargado."
        )

    if diagnostics["decision_source"] == "critical_security_rule":
            razon_critica = diagnostics["critical_reason"]
            critical_intent = "suplantacion_o_malware"
            critical_evidence = build_analyzer_evidence(
                {}, [], is_phishing=True, critical_reason=razon_critica
            )
            critical_context = build_explanation_context(
                is_phishing=True,
                risk_score=1.0,
                intent=critical_intent,
                evidence=critical_evidence,
            )
            try:
                from services.slm_client import generate_slm_explanation
                express_explanation = generate_slm_explanation(critical_context)
            except Exception:
                express_explanation = render_server_fallback(critical_context)

            resultado_express = AnalysisResultSchema(
                is_phishing=True,
                risk_score=1.0,
                reason="🛑 PHISHING COMPROBADO POR METADATOS",
                intent=critical_intent,
                slots_detectados={},
                security_adjustments=[],
                slm_explanation=express_explanation,
            )
            _ANALYSIS_CACHE[content_hash] = resultado_express
            return resultado_express

    risk_score = diagnostics["risk_score"]
    is_phishing = diagnostics["is_phishing"]
    intent = diagnostics["intent"]
    slots_text = diagnostics["slots_detectados"]
    security_adjustments = diagnostics["security_adjustments"]

    # 9. Veredicto
    reason = "🔴 PHISHING DETECTADO" if is_phishing else "🟢 LEGÍTIMO"

    # 10. Explicación Segura usando SLM Local (Fallback automático en caso de error)
    # Se integra el componente del servidor dedicado a generar explicaciones,
    # desacoplando la generación del veredicto.
    explanation_evidence = build_analyzer_evidence(
        slots_text,
        security_adjustments,
        is_phishing=is_phishing,
    )
    explanation_context = build_explanation_context(
        is_phishing=is_phishing,
        risk_score=round(float(risk_score), 4),
        intent=intent,
        evidence=explanation_evidence,
    )
    
    try:
        from services.slm_client import generate_slm_explanation
        slm_explanation = generate_slm_explanation(explanation_context)
    except Exception:
        # Evita que un fallo del SLM impida devolver el veredicto
        slm_explanation = render_server_fallback(explanation_context)

    final_result = AnalysisResultSchema(
        is_phishing=is_phishing,
        risk_score=round(float(risk_score), 4),
        reason=reason,
        intent=intent,
        slots_detectados=slots_text,
        security_adjustments=security_adjustments,
        slm_explanation=slm_explanation
    )
    _ANALYSIS_CACHE[content_hash] = final_result
    return final_result
