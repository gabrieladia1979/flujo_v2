import re

with open('services/explainer.py', 'r', encoding='utf-8') as f:
    code = f.read()

old_code = r"""        all_feature_names = feature_names_text \+ cols_meta \+ cols_slots \+ cols_urls \+ cols_leg
        
        # Buscar el Top 5 de cosas que m.*?s sumaron probabilidad de Phishing"""

new_code = """        all_feature_names = feature_names_text + cols_meta + cols_slots + cols_urls + cols_leg
        
        # DEBUGGING lengths
        if len(all_feature_names) != X_input.shape[1]:
            print(f"[Explainer DEBUG] len(all_feature_names) = {len(all_feature_names)}, X_input.shape[1] = {X_input.shape[1]}")
            # Pad with unknowns if shorter
            if len(all_feature_names) < X_input.shape[1]:
                all_feature_names += [f"Desconocido_{i}" for i in range(X_input.shape[1] - len(all_feature_names))]
        
        # Buscar el Top 5 de cosas que más sumaron probabilidad de Phishing"""

code = re.sub(old_code, new_code, code, flags=re.DOTALL)

with open('services/explainer.py', 'w', encoding='utf-8') as f:
    f.write(code)
