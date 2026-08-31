import sys
import re

with open('services/analyzer.py', 'r', encoding='utf-8') as f:
    code = f.read()

new_load_model = '''def _load_model():
    """Carga el pipeline NLP y el modelo XGBoost desde el archivo .pkl."""
    global nlp, matcher_global, modelo_exportado
    global tfidf, scaler_meta, scaler_slots, calibrated_model, UMBRAL_CRITICO
    
    import spacy
    try:
        nlp = spacy.load("es_core_news_sm")
        nlp.max_length = 50000
    except OSError:
        print("[!] Advertencia: No se pudo cargar es_core_news_sm. Intentando fallback.")
        pass
        
    matcher_global = _crear_matcher()
    
    # Inyectar el tokenizador en __main__ para que pickle lo encuentre si es necesario
    import __main__
    def lematizador_spacy(texto):
        doc = nlp(texto.lower())
        return [token.lemma_ for token in doc if not token.is_stop and not token.is_punct]
    __main__.lematizador_spacy = lematizador_spacy

    import pickle
    import os
    model_path = os.path.join(os.path.dirname(__file__), "..", "model", "phisharg_xgboost.pkl")
    
    try:
        with open(model_path, 'rb') as f:
            modelo_exportado = pickle.load(f)
            
        tfidf = modelo_exportado.get('tfidf')
        scaler_meta = modelo_exportado.get('scaler_meta')
        scaler_slots = modelo_exportado.get('scaler_slots')
        calibrated_model = modelo_exportado.get('calibrated_model')
        UMBRAL_CRITICO = modelo_exportado.get('umbral_critico', 0.91)
        print("[Analyzer] Modelo XGBoost cargado exitosamente.")
    except Exception as e:
        print(f"[!] Error crítico cargando el modelo real: {e}")
        tfidf = None
        scaler_meta = None
        scaler_slots = None
        calibrated_model = None
        UMBRAL_CRITICO = 0.91
'''

code = re.sub(r'def _load_model\(\):.*?(?=\n_load_model\(\))', new_load_model, code, flags=re.DOTALL)

with open('services/analyzer.py', 'w', encoding='utf-8') as f:
    f.write(code)
