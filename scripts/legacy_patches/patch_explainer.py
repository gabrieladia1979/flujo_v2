import re

with open('services/explainer.py', 'r', encoding='utf-8') as f:
    code = f.read()

old_code = r"""        feature_names_text = tfidf_vectorizer.get_feature_names_out().tolist()
        cols_meta = \['Cantidad de URLs', 'Cantidad de Adjuntos', 'Saltos de Red \(Hops\)'\]
        cols_slots = \['Uso de Urgencia', '.*?Autoridad', 'Contexto Financiero', 'URLs en el Cuerpo'\]
        all_feature_names = feature_names_text \+ cols_meta \+ cols_slots"""

new_code = """        feature_names_text = tfidf_vectorizer.get_feature_names_out().tolist()
        cols_meta = ['Cantidad de URLs', 'Cantidad de Adjuntos', 'Saltos de Red (Hops)']
        cols_slots = ['Uso de Urgencia', 'Suplantacion de Autoridad', 'Contexto Financiero', 'Amenaza', 'Call To Action', 'Temporal', 'URLs en el Cuerpo']
        cols_urls = ['Tiene_URL_1', 'Tiene_URL_2', 'URL_Usa_HTTP_1', 'URL_Usa_HTTP_2', 'URL_Oficial_1', 'URL_Oficial_2', 'URL_Suplantada_1', 'URL_Suplantada_2', 'URL_Tiene_IP_1', 'URL_Tiene_IP_2', 'Typosquatting']
        cols_leg = ['Indice de Legibilidad']
        all_feature_names = feature_names_text + cols_meta + cols_slots + cols_urls + cols_leg"""

code = re.sub(old_code, new_code, code, flags=re.DOTALL)

with open('services/explainer.py', 'w', encoding='utf-8') as f:
    f.write(code)
