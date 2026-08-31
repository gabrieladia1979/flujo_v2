"""
Motor de reglas heurísticas para ajustar el risk_score de phishing
basado en las security_features extraídas de las cabeceras del correo.

Cada regla es una tupla (nombre, condición, delta, descripción).
Las reglas se evalúan secuencialmente y los deltas se acumulan.
"""

from typing import List, Tuple
from schemas import SecurityFeaturesSchema, SecurityAdjustment


def check_critical_threats(features: SecurityFeaturesSchema) -> Tuple[bool, str]:
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
        
    # 1. Spoofing Directo (Suplantación de Identidad)
    falla_auth = features.spf_result == 'fail' or features.dkim_result == 'fail'
    if falla_auth and not features.sender_vs_from_match:
        return True, "Suplantación de identidad comprobada (Falla criptográfica + Dominio falsificado)."
        
    # 2. Veredicto del Servidor (Microsoft 365)
    if features.scl >= 9 or features.threat_category.upper() in ['MALWARE', 'PHISH', 'HIGHPHISH']:
        return True, f"Bloqueado por el servidor de correo corporativo (Nivel de Spam: {features.scl})."
        
    # 3. Adjuntos Peligrosos
    if features.has_executable_attachment:
        return True, "Contiene un archivo adjunto ejecutable (posible Malware/Ransomware)."
        
    return False, ""


def _check_auth_failures(features: SecurityFeaturesSchema) -> List[SecurityAdjustment]:
    """Evalúa fallos de autenticación SPF, DKIM, DMARC, CompAuth."""
    adjustments = []

    if features.spf_result in ("fail", "softfail"):
        adjustments.append(SecurityAdjustment(
            rule="spf_fail",
            delta=0.15,
            description=f"SPF {features.spf_result}: el remitente no está autorizado por el dominio"
        ))

    if features.dkim_result == "fail":
        adjustments.append(SecurityAdjustment(
            rule="dkim_fail",
            delta=0.10,
            description="DKIM fail: la firma digital del correo es inválida"
        ))

    if features.dmarc_result == "fail":
        adjustments.append(SecurityAdjustment(
            rule="dmarc_fail",
            delta=0.15,
            description="DMARC fail: la política de autenticación del dominio no se cumplió"
        ))

    if features.compauth_result == "fail":
        adjustments.append(SecurityAdjustment(
            rule="compauth_fail",
            delta=0.10,
            description="Autenticación compuesta de Microsoft 365 fallida"
        ))

    return adjustments


def _check_spoofing(features: SecurityFeaturesSchema) -> List[SecurityAdjustment]:
    """Evalúa indicadores de spoofing (discrepancias en cabeceras)."""
    adjustments = []

    if not features.from_return_path_match:
        adjustments.append(SecurityAdjustment(
            rule="return_path_mismatch",
            delta=0.10,
            description="Discrepancia entre From y Return-Path: posible spoofing"
        ))

    if not features.from_reply_to_match:
        adjustments.append(SecurityAdjustment(
            rule="reply_to_mismatch",
            delta=0.05,
            description="Reply-To apunta a un dominio diferente al remitente"
        ))

    if not features.sender_vs_from_match:
        adjustments.append(SecurityAdjustment(
            rule="sender_from_mismatch",
            delta=0.08,
            description="Discrepancia entre Sender y From: posible suplantación"
        ))

    return adjustments


def _check_antispam(features: SecurityFeaturesSchema) -> List[SecurityAdjustment]:
    """Evalúa indicadores anti-spam de Microsoft 365 (SCL, BCL)."""
    adjustments = []

    # SCL (Spam Confidence Level): 0-4 = no spam, 5-6 = spam, 7-9 = high confidence spam
    if features.scl >= 9:
        adjustments.append(SecurityAdjustment(
            rule="scl_high",
            delta=0.20,
            description=f"SCL={features.scl}: Microsoft lo clasifica como spam de alta confianza"
        ))
    elif features.scl >= 5:
        adjustments.append(SecurityAdjustment(
            rule="scl_medium",
            delta=0.12,
            description=f"SCL={features.scl}: Microsoft lo clasifica como spam probable"
        ))

    # BCL (Bulk Complaint Level): 0-3 = legítimo, 4-7 = mixto, 8-9 = alto volumen
    if features.bcl >= 5:
        adjustments.append(SecurityAdjustment(
            rule="bcl_high",
            delta=0.05,
            description=f"BCL={features.bcl}: alto nivel de envío masivo"
        ))

    return adjustments


def _check_attachments(features: SecurityFeaturesSchema) -> List[SecurityAdjustment]:
    """Evalúa adjuntos peligrosos."""
    adjustments = []

    if features.has_executable_attachment:
        adjustments.append(SecurityAdjustment(
            rule="executable_attachment",
            delta=0.15,
            description="El correo contiene un adjunto ejecutable potencialmente peligroso"
        ))

    return adjustments


def _check_positive_signals(features: SecurityFeaturesSchema) -> List[SecurityAdjustment]:
    """Evalúa señales positivas que reducen el riesgo."""
    adjustments = []

    # Email autenticado internamente en la organización
    if features.auth_as == "Internal":
        adjustments.append(SecurityAdjustment(
            rule="internal_auth",
            delta=-0.10,
            description="Correo autenticado como interno de la organización"
        ))

    # Todas las verificaciones de autenticación pasaron Y no hay spoofing
    all_auth_pass = (
        features.spf_result == "pass"
        and features.dkim_result == "pass"
        and features.dmarc_result == "pass"
    )
    no_spoofing = (
        features.from_return_path_match
        and features.from_reply_to_match
        and features.sender_vs_from_match
    )
    if all_auth_pass and no_spoofing:
        adjustments.append(SecurityAdjustment(
            rule="all_checks_pass",
            delta=-0.05,
            description="Todas las verificaciones de autenticación y spoofing pasaron correctamente"
        ))

    return adjustments


def apply_security_rules(features: SecurityFeaturesSchema) -> List[SecurityAdjustment]:
    """
    Evalúa todas las reglas heurísticas contra las security_features
    y retorna la lista de ajustes a aplicar al risk_score.

    Args:
        features: Características de seguridad del correo.

    Returns:
        Lista de SecurityAdjustment con los ajustes aplicables.
    """
    adjustments = []

    adjustments.extend(_check_auth_failures(features))
    adjustments.extend(_check_spoofing(features))
    adjustments.extend(_check_antispam(features))
    adjustments.extend(_check_attachments(features))
    adjustments.extend(_check_positive_signals(features))

    return adjustments
