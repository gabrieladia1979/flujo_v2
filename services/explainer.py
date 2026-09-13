import numpy as np

def extract_shap_insights(calibrated_model, X_input, tfidf_vectorizer) -> list:
    import shap
    
    try:
        xgb_base = calibrated_model.estimator
        explainer = shap.TreeExplainer(xgb_base)
        shap_values = explainer.shap_values(X_input)
        
        if isinstance(shap_values, list):
            shap_phishing = shap_values[1][0]
        elif len(shap_values.shape) == 3:
            shap_phishing = shap_values[0, :, 1]
        else:
            shap_phishing = shap_values[0]

        feature_names_text = tfidf_vectorizer.get_feature_names_out().tolist()
        cols_meta = ['Cantidad de URLs', 'Cantidad de Adjuntos', 'Saltos de Red (Hops)']
        cols_slots = ['Uso de Urgencia', 'Suplantacion de Autoridad', 'Contexto Financiero', 'Amenaza', 'Call To Action', 'Temporal', 'URLs en el Cuerpo']
        cols_urls = ['Tiene_URL_1', 'Tiene_URL_2', 'URL_Usa_HTTP_1', 'URL_Usa_HTTP_2', 'URL_Oficial_1', 'URL_Oficial_2', 'URL_Suplantada_1', 'URL_Suplantada_2', 'URL_Tiene_IP_1', 'URL_Tiene_IP_2', 'Typosquatting']
        cols_leg = ['Indice de Legibilidad']
        all_feature_names = feature_names_text + cols_meta + cols_slots + cols_urls + cols_leg
        
        if len(all_feature_names) < X_input.shape[1]:
            all_feature_names += [f"Feature_{i}" for i in range(X_input.shape[1] - len(all_feature_names))]
        
        top_indices = np.argsort(shap_phishing)[::-1]
        
        insights = []
        for idx in top_indices:
            if shap_phishing[idx] > 0 and len(insights) < 5:
                if idx < len(all_feature_names):
                    insights.append(all_feature_names[idx])
                
        return insights
    
    except Exception as e:
        print(f"[Explainer] Error calculando SHAP: {e}")
        return ["Presencia de enlaces sospechosos", "Tono de urgencia o manipulacion"]
