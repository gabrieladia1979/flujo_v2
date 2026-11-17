import re

with open('services/security_rules.py', 'r', encoding='utf-8') as f:
    code = f.read()

new_func = '''def check_critical_threats(features: SecurityFeaturesSchema) -> Tuple[bool, str]:
    if not features: return False, ""
    
    # 1. Spoofing y Autenticación Criptográfica (Identidad Falsificada)
    if features.dmarc_result == 'fail':
        return True, "🛑 ALERTA MÁXIMA: DMARC falló. El dominio origen prohíbe explícitamente a este remitente enviar correos. Es una suplantación comprobada."
    if features.spf_result == 'fail' and not features.sender_vs_from_match:
        return True, "⚠️ Suplantación: El servidor desde donde se envió este correo no está autorizado por el dominio (SPF Fail) y el remitente está enmascarado."
    
    # 2. Análisis de Cabeceras (Reply-To Mismatch)
    if not features.from_reply_to_match:
        return True, "⚠️ Fraude BEC: La dirección a la que vas a responder (Reply-To) es distinta a la del remitente original. Si haces clic en 'Responder', el correo irá a un atacante."
    
    # 3. Amenazas Microsoft 365 (Filtro Antispam)
    if features.scl >= 9:
        return True, f"🚨 Microsoft 365 catalogó silenciosamente este correo como Alta Probabilidad de Phishing (Nivel SCL: {features.scl})."
    if features.bcl >= 7:
        return True, f"⚠️ Este correo proviene de un enviador masivo reportado frecuentemente por spam y abusos (Nivel BCL: {features.bcl})."
    
    # 4. Análisis de Carga Útil (Payload)
    if features.has_executable_attachment:
        return True, "🛑 PELIGRO: Se detectó un archivo adjunto con formato ejecutable oculto. Podría instalar Malware o Ransomware en tu equipo."
    
    # 5. Anomalías de Origen y Red
    if features.auth_as == 'Anonymous' and features.scl >= 5:
        return True, "⚠️ Remitente anónimo desde un servidor externo combinado con sospecha de Spam. Tratar con extrema precaución."

    return False, ""
'''

code = re.sub(r'def check_critical_threats.*?return False, ""\n', new_func, code, flags=re.DOTALL)

with open('services/security_rules.py', 'w', encoding='utf-8') as f:
    f.write(code)
