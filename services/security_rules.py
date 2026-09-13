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
    
    # 1. Spoofing Directo (SPF Fail + Sender Enmascarado)
    #    SPF fail + sender mismatch es evidencia fuerte de suplantación activa.
    if features.spf_result == 'fail' and not features.sender_vs_from_match:
        return True, "⚠️ Suplantación: El servidor desde donde se envió este correo no está autorizado por el dominio (SPF Fail) y el remitente está enmascarado."
    
    # 2. Amenazas Microsoft 365 (Alta confianza de phishing)
    if features.scl >= 9:
        return True, f"🚨 Microsoft 365 catalogó silenciosamente este correo como Alta Probabilidad de Phishing (Nivel SCL: {features.scl})."
    # BCL alone describes bulk mail complaints, not proof of phishing.
    # Keep its noncritical contribution in _check_antispam.
    
    # 3. Análisis de Carga Útil (Payload)
    if features.has_executable_attachment:
        return True, "🛑 PELIGRO: Se detectó un archivo adjunto con formato ejecutable oculto. Podría instalar Malware o Ransomware en tu equipo."
    
    # 4. Anomalías de Origen y Red (umbral SCL subido a 7 para evitar FP con newsletters)
    if features.auth_as == 'Anonymous' and features.scl >= 7:
        return True, "⚠️ Remitente anónimo desde un servidor externo combinado con sospecha alta de Spam. Tratar con extrema precaución."

    return False, ""


def _check_auth_failures(features: SecurityFeaturesSchema) -> List[SecurityAdjustment]:
    """Evalúa fallos de autenticación SPF, DKIM, DMARC, CompAuth."""
    adjustments = []

    if features.spf_result == "fail":
        adjustments.append(SecurityAdjustment(
            rule="spf_fail",
            delta=0.15,
            description="SPF fail: el remitente no está autorizado por el dominio"
        ))
    elif features.spf_result == "softfail":
        adjustments.append(SecurityAdjustment(
            rule="spf_softfail",
            delta=0.05,
            description="SPF softfail: el dominio no prohíbe explícitamente este remitente (común en reenvíos)"
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
            delta=-0.15,
            description="Todas las verificaciones de autenticación y spoofing pasaron correctamente"
        ))
        if features.is_trusted_domain:
            adjustments.append(SecurityAdjustment(
                rule="trusted_official_domain",
                delta=-0.40,
                description="Remitente es un dominio oficial verificado con autenticación perfecta"
            ))
    elif features.spf_result == "pass" and features.dkim_result == "pass":
        # SPF+DKIM pasan pero DMARC no está o falla (común en dominios sin DMARC configurado)
        adjustments.append(SecurityAdjustment(
            rule="spf_dkim_pass",
            delta=-0.08,
            description="SPF y DKIM pasaron correctamente (autenticación parcial positiva)"
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
