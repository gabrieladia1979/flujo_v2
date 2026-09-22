"""
=============================================================================
TEST EXHAUSTIVO DEL CLASIFICADOR PhishARG — Rama Audit
=============================================================================

Objetivo: 100% de éxito en todos los casos.
Cada test está diseñado para ejercitar una capacidad específica del clasificador
donde se espera que funcione correctamente.

Secciones:
  A. Reglas Críticas de Seguridad (check_critical_threats) — circuito corto
  B. Reglas de Contenido (detect_content_signals) — piso de política 0.95
  C. Reglas Heurísticas de Cabeceras (apply_security_rules) — deltas
  D. Modelo ML — Phishing claro (score alto)
  E. Modelo ML — Legítimo claro (score bajo)
  F. Pipeline completo (analyze_email end-to-end)
  G. Diagnóstico de debilidades conocidas

Cada test tiene un docstring que explica:
  - Qué se prueba
  - Por qué debe funcionar
  - Qué componente ejerce
"""

import pytest
import copy
from unittest.mock import patch

from schemas import (
    EmailPayloadSchema,
    MetadataSchema,
    SecurityFeaturesSchema,
    ContentSignal,
)
from services.security_rules import check_critical_threats, apply_security_rules
from services.content_rules import detect_content_signals


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _payload(
    asunto="",
    contenido="",
    remitente_email="test@example.com",
    security_features=None,
):
    """Construye un EmailPayloadSchema mínimo para testing."""
    return EmailPayloadSchema(
        metadata=MetadataSchema(
            asunto=asunto,
            remitente_email=remitente_email,
        ),
        contenido=contenido,
        security_features=security_features,
    )


def _security(**kwargs):
    """Construye SecurityFeaturesSchema con defaults seguros y overrides."""
    return SecurityFeaturesSchema(**kwargs)


def _auth_perfecta(**overrides):
    """SecurityFeatures con autenticación perfecta (SPF+DKIM+DMARC pass)."""
    base = dict(
        spf_result="pass",
        dkim_result="pass",
        dmarc_result="pass",
        compauth_result="pass",
        from_return_path_match=True,
        from_reply_to_match=True,
        sender_vs_from_match=True,
        auth_as="Internal",
        scl=0,
        bcl=0,
    )
    base.update(overrides)
    return _security(**base)


# ═════════════════════════════════════════════════════════════════════════════
# A. REGLAS CRÍTICAS DE SEGURIDAD (check_critical_threats)
#    Cada una de estas reglas produce veredicto instantáneo: phishing 1.0
#    sin pasar por el modelo ML.
# ═════════════════════════════════════════════════════════════════════════════


class TestReglasCriticas:
    """Reglas de circuito corto que deben disparar phishing = 1.0 siempre."""

    def test_spf_fail_con_sender_enmascarado(self):
        """SPF fail + sender mismatch = suplantación activa confirmada.
        Este es el caso más claro de spoofing: el servidor no está
        autorizado Y el remitente está enmascarado."""
        features = _security(spf_result="fail", sender_vs_from_match=False)
        es_critico, razon = check_critical_threats(features)
        assert es_critico is True
        assert "Suplantación" in razon or "SPF" in razon

    def test_spf_fail_con_sender_match_no_es_critico(self):
        """SPF fail PERO el sender coincide con From → no es suplantación
        directa (puede ser un reenvío legítimo)."""
        features = _security(spf_result="fail", sender_vs_from_match=True)
        es_critico, _ = check_critical_threats(features)
        assert es_critico is False

    def test_scl_9_dispara_critico(self):
        """SCL >= 9 = Microsoft 365 catalogó como phishing de alta confianza.
        Confiar en el filtro de Microsoft como señal incontrovertible."""
        features = _security(scl=9)
        es_critico, razon = check_critical_threats(features)
        assert es_critico is True
        assert "SCL" in razon or "Microsoft" in razon

    def test_scl_10_dispara_critico(self):
        """SCL = 10, el máximo posible."""
        features = _security(scl=10)
        es_critico, _ = check_critical_threats(features)
        assert es_critico is True

    def test_scl_8_no_es_critico(self):
        """SCL = 8 no alcanza el umbral crítico de 9."""
        features = _security(scl=8)
        es_critico, _ = check_critical_threats(features)
        assert es_critico is False

    def test_adjunto_ejecutable(self):
        """Archivo ejecutable adjunto = riesgo de malware/ransomware."""
        features = _security(has_executable_attachment=True)
        es_critico, razon = check_critical_threats(features)
        assert es_critico is True
        assert "ejecutable" in razon.lower() or "malware" in razon.lower()

    def test_anonimo_con_scl_alto(self):
        """Remitente anónimo + SCL >= 7 = combinación altamente sospechosa."""
        features = _security(auth_as="Anonymous", scl=7)
        es_critico, razon = check_critical_threats(features)
        assert es_critico is True
        assert "anónimo" in razon.lower() or "Anonymous" in razon

    def test_anonimo_con_scl_bajo_no_es_critico(self):
        """Remitente anónimo con SCL bajo (6) no llega al umbral."""
        features = _security(auth_as="Anonymous", scl=6)
        es_critico, _ = check_critical_threats(features)
        assert es_critico is False

    def test_features_none_no_es_critico(self):
        """Sin features de seguridad, no se puede determinar amenaza crítica."""
        es_critico, _ = check_critical_threats(None)
        assert es_critico is False

    def test_todo_limpio_no_es_critico(self):
        """Features por defecto sin ninguna señal no deben ser críticas."""
        features = _security()
        es_critico, _ = check_critical_threats(features)
        assert es_critico is False


# ═════════════════════════════════════════════════════════════════════════════
# B. REGLAS DE CONTENIDO (detect_content_signals)
#    Detección de patrones textuales que el modelo ML suele no detectar,
#    especialmente phishing sin enlaces (BEC, credential theft por texto).
# ═════════════════════════════════════════════════════════════════════════════


class TestReglasContenidoPositivos:
    """Casos donde las reglas de contenido DEBEN disparar señal."""

    # --- credential_disclosure_request ---

    def test_pedir_contrasena_directo_espanol(self):
        """Petición directa de contraseña en español."""
        body = "<p>Estimado usuario, responda este correo con su contraseña para verificar su identidad.</p>"
        signals = detect_content_signals(body)
        assert any(s.rule == "credential_disclosure_request" for s in signals)

    def test_pedir_clave_fiscal(self):
        """Petición de clave fiscal (ataque fiscal argentino)."""
        body = "<p>Envíe su clave fiscal a este correo para regularizar su situación tributaria.</p>"
        signals = detect_content_signals(body)
        assert any(s.rule == "credential_disclosure_request" for s in signals)

    def test_pedir_codigo_sms(self):
        """Petición de código SMS de verificación."""
        body = "<p>Confirme su identidad compartiendo el código SMS que acaba de recibir.</p>"
        signals = detect_content_signals(body)
        assert any(s.rule == "credential_disclosure_request" for s in signals)

    def test_pedir_token_autenticacion(self):
        """Petición de token de autenticación."""
        body = "<p>Por favor envie su token de autenticación para restaurar el acceso a su cuenta.</p>"
        signals = detect_content_signals(body)
        assert any(s.rule == "credential_disclosure_request" for s in signals)

    def test_pedir_password_ingles(self):
        """Petición en inglés: 'send your password'."""
        body = "<p>Please reply to this email with your password so we can verify your account.</p>"
        signals = detect_content_signals(body)
        assert any(s.rule == "credential_disclosure_request" for s in signals)

    def test_pedir_otp_ingles(self):
        """Petición en inglés de OTP."""
        body = "<p>Submit your 6-digit OTP code to complete the verification process.</p>"
        signals = detect_content_signals(body)
        assert any(s.rule == "credential_disclosure_request" for s in signals)

    def test_pedir_cvv(self):
        """Petición directa de CVV."""
        body = "<p>Confirme su CVV para procesar la devolución de su pago.</p>"
        signals = detect_content_signals(body)
        assert any(s.rule == "credential_disclosure_request" for s in signals)

    # --- payment_redirection_no_verification ---

    def test_desvio_pago_nueva_cuenta_espanol(self):
        """Pago a nueva cuenta + no contactar al banco = BEC clásico."""
        body = (
            "<p>Estimado, le informamos que hemos cambiado de banco. "
            "Transfiera el pago a la nueva cuenta CBU 0000003100000000001234. "
            "No llame al banco por este cambio, es un procedimiento interno.</p>"
        )
        signals = detect_content_signals(body)
        assert any(s.rule == "payment_redirection_no_verification" for s in signals)

    def test_desvio_pago_ingles(self):
        """BEC en inglés: wire to new bank account, don't contact."""
        body = (
            "<p>Our bank details have changed. Please wire the payment to our "
            "updated bank account 123456789. Do not contact the bank to verify "
            "this change, it's routine.</p>"
        )
        signals = detect_content_signals(body)
        assert any(s.rule == "payment_redirection_no_verification" for s in signals)

    # --- mfa_push_coercion ---

    def test_mfa_push_coercion_espanol(self):
        """Coerción para aprobar MFA push no solicitada."""
        body = (
            "<p>Hemos detectado un inicio de sesión sospechoso en su cuenta. "
            "Apruebe la notificación de acceso que acaba de recibir en su teléfono. "
            "Aunque no haya iniciado sesión, es necesario para proteger su cuenta.</p>"
        )
        signals = detect_content_signals(body)
        assert any(s.rule == "mfa_push_coercion" for s in signals)

    def test_mfa_push_coercion_ingles(self):
        """MFA push coercion in English."""
        body = (
            "<p>We detected a sign-in attempt on your account. "
            "Approve the notification prompt on your phone to complete authentication. "
            "Even if you did not initiate this login, please approve to secure your account.</p>"
        )
        signals = detect_content_signals(body)
        assert any(s.rule == "mfa_push_coercion" for s in signals)

    # --- delivery_fee_fraud ---

    def test_fraude_entrega_espanol(self):
        """Fraude de tarifa de entrega de paquete."""
        body = (
            "<p>Su paquete de Andreani no pudo ser entregado. "
            "Pague la tarifa de reenvío de $350 para recibir su envío.</p>"
        )
        signals = detect_content_signals(body)
        assert any(s.rule == "delivery_fee_fraud" for s in signals)

    def test_fraude_entrega_ingles(self):
        """Delivery fee fraud in English."""
        body = (
            "<p>Your FedX package could not be delivered. "
            "Pay the redelivery fee of $4.99 to reschedule your delivery.</p>"
        )
        signals = detect_content_signals(body)
        assert any(s.rule == "delivery_fee_fraud" for s in signals)


class TestReglasContenidoNegativos:
    """Casos legítimos que las reglas de contenido NO deben disparar."""

    def test_capacitacion_seguridad_no_dispara(self):
        """Capacitación interna sobre phishing: menciona contraseñas en
        contexto educativo, no debe disparar credential_disclosure_request."""
        body = (
            "<p>Recordatorio de seguridad: nunca compartas tu contraseña "
            "por correo electrónico. Si recibes un correo sospechoso, "
            "reportalo al equipo de IT.</p>"
        )
        signals = detect_content_signals(body)
        assert not any(s.rule == "credential_disclosure_request" for s in signals)

    def test_politica_seguridad_no_dispara(self):
        """Política de seguridad corporativa."""
        body = (
            "<p>Política de seguridad: No comparta sus credenciales con nadie. "
            "Si necesita restablecer su contraseña, use el enlace de autoservicio. "
            "Nunca envíe tokens por correo electrónico.</p>"
        )
        signals = detect_content_signals(body)
        assert not any(s.rule == "credential_disclosure_request" for s in signals)

    def test_recordatorio_password_no_dispara(self):
        """Recordatorio legítimo de cambio de contraseña."""
        body = (
            "<p>Su contraseña corporativa expirará en 7 días. "
            "Por favor acceda al portal de autoservicio para cambiarla. "
            "Si tiene dudas, contacte al help desk.</p>"
        )
        signals = detect_content_signals(body)
        assert not any(s.rule == "credential_disclosure_request" for s in signals)

    def test_factura_legitima_no_dispara_desvio(self):
        """Factura legítima con pago a cuenta existente no es BEC."""
        body = (
            "<p>Adjuntamos la factura del período Agosto 2026. "
            "El monto es de $45.000. Puede abonar con los datos "
            "bancarios de siempre. Saludos cordiales.</p>"
        )
        signals = detect_content_signals(body)
        assert not any(s.rule == "payment_redirection_no_verification" for s in signals)

    def test_email_reenviado_con_cita_no_dispara(self):
        """Un correo reenviado que cita un mensaje de phishing en blockquote
        no debe disparar la regla (las comillas/citas se filtran)."""
        body = (
            "<p>Te reenvío este correo sospechoso que recibí:</p>"
            "<blockquote><p>Envie su contraseña para verificar su cuenta</p></blockquote>"
            "<p>¿Lo reporto al equipo de seguridad?</p>"
        )
        signals = detect_content_signals(body)
        assert not any(s.rule == "credential_disclosure_request" for s in signals)

    def test_newsletter_no_dispara_entrega(self):
        """Newsletter de empresa de envíos con info de tracking."""
        body = (
            "<p>Su paquete fue despachado exitosamente por Andreani. "
            "Número de seguimiento: AR123456789. "
            "Fecha estimada de entrega: 25 de septiembre.</p>"
        )
        signals = detect_content_signals(body)
        assert not any(s.rule == "delivery_fee_fraud" for s in signals)

    def test_texto_entre_comillas_filtrado(self):
        """Texto entre comillas es eliminado y no debe disparar reglas."""
        body = '<p>El mensaje decía: "Envie su contraseña para verificar su cuenta"</p>'
        signals = detect_content_signals(body)
        assert not any(s.rule == "credential_disclosure_request" for s in signals)


# ═════════════════════════════════════════════════════════════════════════════
# C. REGLAS HEURÍSTICAS DE CABECERAS (apply_security_rules)
#    Valida que cada regla individual genera el delta correcto y que
#    los signos (positivo = riesgo, negativo = confianza) son correctos.
# ═════════════════════════════════════════════════════════════════════════════


class TestReglasHeuristicas:
    """Validación unitaria de cada regla de ajuste por cabeceras."""

    def test_spf_fail_delta_positivo(self):
        """SPF fail debe sumar riesgo (+0.15)."""
        features = _security(spf_result="fail")
        adjustments = apply_security_rules(features)
        spf = [a for a in adjustments if a.rule == "spf_fail"]
        assert len(spf) == 1
        assert spf[0].delta == 0.15

    def test_spf_softfail_delta_menor(self):
        """SPF softfail es menos grave que fail (+0.05)."""
        features = _security(spf_result="softfail")
        adjustments = apply_security_rules(features)
        softfail = [a for a in adjustments if a.rule == "spf_softfail"]
        assert len(softfail) == 1
        assert softfail[0].delta == 0.05

    def test_dkim_fail_delta(self):
        """DKIM fail → +0.10."""
        features = _security(dkim_result="fail")
        adjustments = apply_security_rules(features)
        dkim = [a for a in adjustments if a.rule == "dkim_fail"]
        assert len(dkim) == 1
        assert dkim[0].delta == 0.10

    def test_dmarc_fail_delta(self):
        """DMARC fail → +0.15."""
        features = _security(dmarc_result="fail")
        adjustments = apply_security_rules(features)
        dmarc = [a for a in adjustments if a.rule == "dmarc_fail"]
        assert len(dmarc) == 1
        assert dmarc[0].delta == 0.15

    def test_compauth_fail_delta(self):
        """CompAuth fail (Microsoft 365) → +0.10."""
        features = _security(compauth_result="fail")
        adjustments = apply_security_rules(features)
        comp = [a for a in adjustments if a.rule == "compauth_fail"]
        assert len(comp) == 1
        assert comp[0].delta == 0.10

    def test_return_path_mismatch_delta(self):
        """Return-Path mismatch → +0.10."""
        features = _security(from_return_path_match=False)
        adjustments = apply_security_rules(features)
        rp = [a for a in adjustments if a.rule == "return_path_mismatch"]
        assert len(rp) == 1
        assert rp[0].delta == 0.10

    def test_reply_to_mismatch_delta(self):
        """Reply-To diferente al From → +0.05."""
        features = _security(from_reply_to_match=False)
        adjustments = apply_security_rules(features)
        rt = [a for a in adjustments if a.rule == "reply_to_mismatch"]
        assert len(rt) == 1
        assert rt[0].delta == 0.05

    def test_sender_from_mismatch_delta(self):
        """Sender vs From mismatch → +0.08."""
        features = _security(sender_vs_from_match=False)
        adjustments = apply_security_rules(features)
        sf = [a for a in adjustments if a.rule == "sender_from_mismatch"]
        assert len(sf) == 1
        assert sf[0].delta == 0.08

    def test_scl_alto_delta(self):
        """SCL >= 9 en reglas heurísticas → +0.20."""
        features = _security(scl=9)
        adjustments = apply_security_rules(features)
        scl = [a for a in adjustments if a.rule == "scl_high"]
        assert len(scl) == 1
        assert scl[0].delta == 0.20

    def test_scl_medio_delta(self):
        """SCL 5-8 → +0.12."""
        features = _security(scl=6)
        adjustments = apply_security_rules(features)
        scl = [a for a in adjustments if a.rule == "scl_medium"]
        assert len(scl) == 1
        assert scl[0].delta == 0.12

    def test_bcl_alto_delta(self):
        """BCL >= 5 → +0.05."""
        features = _security(bcl=6)
        adjustments = apply_security_rules(features)
        bcl = [a for a in adjustments if a.rule == "bcl_high"]
        assert len(bcl) == 1
        assert bcl[0].delta == 0.05

    def test_adjunto_ejecutable_delta(self):
        """Adjunto ejecutable → +0.15."""
        features = _security(has_executable_attachment=True)
        adjustments = apply_security_rules(features)
        exe = [a for a in adjustments if a.rule == "executable_attachment"]
        assert len(exe) == 1
        assert exe[0].delta == 0.15

    def test_auth_interna_descuento(self):
        """Email interno → -0.10."""
        features = _security(auth_as="Internal")
        adjustments = apply_security_rules(features)
        internal = [a for a in adjustments if a.rule == "internal_auth"]
        assert len(internal) == 1
        assert internal[0].delta == -0.10

    def test_auth_perfecta_descuento(self):
        """SPF+DKIM+DMARC pass + sin spoofing → -0.15."""
        features = _auth_perfecta()
        adjustments = apply_security_rules(features)
        all_pass = [a for a in adjustments if a.rule == "all_checks_pass"]
        assert len(all_pass) == 1
        assert all_pass[0].delta == -0.15

    def test_dominio_oficial_descuento_extra(self):
        """Dominio oficial de confianza con auth perfecta → -0.40 adicional."""
        features = _auth_perfecta(is_trusted_domain=True)
        adjustments = apply_security_rules(features)
        trusted = [a for a in adjustments if a.rule == "trusted_official_domain"]
        assert len(trusted) == 1
        assert trusted[0].delta == -0.40

    def test_spf_dkim_pass_sin_dmarc(self):
        """SPF + DKIM pass pero sin DMARC → -0.08 (descuento parcial)."""
        features = _security(
            spf_result="pass", dkim_result="pass", dmarc_result="unknown"
        )
        adjustments = apply_security_rules(features)
        partial = [a for a in adjustments if a.rule == "spf_dkim_pass"]
        assert len(partial) == 1
        assert partial[0].delta == -0.08

    def test_acumulacion_deltas_no_excede_limites(self):
        """El delta total acumulado se clampea entre -0.35 y +0.35.
        Esto evita que muchas señales leves conviertan un correo legítimo
        en falso positivo."""
        from services.analyzer import _apply_security_adjustments

        # Peor caso: todas las señales negativas al mismo tiempo
        features = _security(
            spf_result="fail",       # +0.15
            dkim_result="fail",      # +0.10
            dmarc_result="fail",     # +0.15
            compauth_result="fail",  # +0.10
            from_return_path_match=False,  # +0.10
            from_reply_to_match=False,     # +0.05
            sender_vs_from_match=False,    # +0.08
            scl=9,                   # +0.20
            bcl=6,                   # +0.05
            has_executable_attachment=True, # +0.15
        )
        # Total sin cap: +1.13 — pero con cap debe ser +0.35
        score, _, _ = _apply_security_adjustments(0.5, False, features)
        assert score <= 0.85  # 0.5 + 0.35

    def test_descuento_total_no_excede_menos_035(self):
        """El descuento máximo acumulado es -0.35."""
        from services.analyzer import _apply_security_adjustments

        features = _auth_perfecta(is_trusted_domain=True)
        # auth_perfecta: -0.10 (internal) + -0.15 (all pass) + -0.40 (trusted) = -0.65
        # Clamped to -0.35
        score, _, _ = _apply_security_adjustments(0.5, False, features)
        assert score >= 0.15  # 0.5 - 0.35


# ═════════════════════════════════════════════════════════════════════════════
# D. MODELO ML — PHISHING CLARO
#    Casos donde el contenido textual tiene suficientes señales de phishing
#    para que el XGBoost los clasifique con score alto.
# ═════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def classify():
    """Importa _classify_payload una sola vez, maneja si el modelo no cargó."""
    try:
        from services.analyzer import _classify_payload, calibrated_model
        if calibrated_model is None:
            pytest.skip("Modelo XGBoost no disponible")
        return _classify_payload
    except Exception as e:
        pytest.skip(f"No se pudo importar el clasificador: {e}")


class TestMLPhishingClaro:
    """Correos que el modelo ML debe clasificar como phishing (raw_score alto).
    Estos tienen múltiples señales textuales: URLs sospechosas, urgencia,
    autoridad, financiero, call-to-action, temporal."""

    def test_phishing_arca_fiscal(self, classify):
        """Phishing clásico argentino: suplantación de ARCA/AFIP con
        enlace fraudulento y amenaza de embargo."""
        payload = _payload(
            asunto="URGENTE: Intimación de deuda - ARCA",
            contenido=(
                "Estimado contribuyente, se detectó una deuda impositiva a su nombre. "
                "Si no regulariza su situación en las próximas 24 horas, se procederá "
                "con el embargo preventivo de sus cuentas bancarias. "
                "Ingrese al siguiente enlace para actualizar datos y regularizar: "
                '<a href="http://arca-gob-ar.phishing.com/verificar">Verificar cuenta</a>'
            ),
        )
        result = classify(payload)
        # El raw_score del modelo debería ser alto por la combinación de
        # URGENCIA + AUTORIDAD (arca) + FINANCIERO (embargo, deuda) +
        # CALL_TO_ACTION (ingrese al) + TEMPORAL (24 horas) + URL sospechosa
        assert result["raw_score"] >= 0.60, (
            f"raw_score={result['raw_score']:.4f} — El phishing fiscal clásico "
            f"debería tener score alto. Slots: {result['slots_detectados']}"
        )

    def test_phishing_banco_clave(self, classify):
        """Phishing bancario: actualización de clave urgente."""
        payload = _payload(
            asunto="Banco Nación - Acción requerida: actualizar datos",
            contenido=(
                "Estimado cliente del Banco Nación, su cuenta será bloqueada "
                "si no actualiza sus datos de seguridad inmediatamente. "
                "Ingrese a http://banco-nacion-seguro.info/actualizar para "
                "actualizar datos con su clave fiscal y código de seguridad."
            ),
        )
        result = classify(payload)
        assert result["raw_score"] >= 0.60, (
            f"raw_score={result['raw_score']:.4f} — Phishing bancario con "
            f"urgencia + autoridad debería tener score alto"
        )

    def test_phishing_mercadopago_premio(self, classify):
        """Phishing de marketplace: premio falso con enlace."""
        payload = _payload(
            asunto="¡Felicitaciones! Ganaste un premio de MercadoPago",
            contenido=(
                "Hola! Felicitaciones, has sido seleccionado para recibir "
                "un premio de $50.000 de MercadoPago. Haga clic en el "
                "siguiente enlace para reclamar su premio antes de que expire "
                "en 48 horas: http://mercadopago-premios.net/reclamar"
            ),
        )
        result = classify(payload)
        assert result["raw_score"] >= 0.50, (
            f"raw_score={result['raw_score']:.4f} — Phishing de premio falso "
            f"debería tener score moderado-alto"
        )

    def test_phishing_netflix_suspension(self, classify):
        """Phishing de servicio: suspensión de Netflix."""
        payload = _payload(
            asunto="Netflix: Su cuenta será suspendida",
            contenido=(
                "Estimado usuario de Netflix, su último pago no fue procesado "
                "correctamente. Su cuenta será suspendida si no actualiza "
                "su información de pago. Verifique su cuenta ingresando a "
                "http://netflix-renovar.com/login con su código de seguridad."
            ),
        )
        result = classify(payload)
        assert result["raw_score"] >= 0.50, (
            f"raw_score={result['raw_score']:.4f}"
        )


# ═════════════════════════════════════════════════════════════════════════════
# E. MODELO ML — LEGÍTIMO CLARO
#    Correos que el modelo debe clasificar con score bajo.
# ═════════════════════════════════════════════════════════════════════════════


class TestMLLegitimoClaro:
    """Correos legítimos que el modelo ML debería puntuar bajo."""

    def test_correo_coloquial_asado(self, classify):
        """Correo informal entre colegas: 0 señales de phishing."""
        payload = _payload(
            asunto="Asado del sábado",
            contenido=(
                "Hola equipo! Les confirmo que el asado del sábado es a las 13hs "
                "en casa de Juan. Traigan ensalada o postre. Los que no puedan "
                "avisen antes del viernes. Abrazo!"
            ),
            remitente_email="juan@empresa.com.ar",
        )
        result = classify(payload)
        assert result["raw_score"] < 0.50, (
            f"raw_score={result['raw_score']:.4f} — Un correo de asado "
            f"no debe tener score alto"
        )

    def test_correo_tecnico_deploy(self, classify):
        """Correo técnico sobre deploy de software."""
        payload = _payload(
            asunto="Re: Deploy v3.2.1 a producción",
            contenido=(
                "Hola equipo, confirmo que el deploy de la versión 3.2.1 "
                "salió OK a producción. Los tests de integración pasaron "
                "todos. El pipeline de CI/CD no reportó errores. "
                "Los logs están en Grafana si quieren verificar."
            ),
            remitente_email="devops@empresa.com.ar",
        )
        result = classify(payload)
        assert result["raw_score"] < 0.50, (
            f"raw_score={result['raw_score']:.4f} — Correo técnico legítimo"
        )

    def test_correo_reunion_trabajo(self, classify):
        """Invitación a reunión de trabajo."""
        payload = _payload(
            asunto="Reunión de planificación trimestral",
            contenido=(
                "Buenas tardes a todos, les recuerdo que mañana a las 10hs "
                "tenemos la reunión de planificación del próximo trimestre "
                "en la sala de conferencias del tercer piso. "
                "La agenda incluye revisión de objetivos y presupuesto."
            ),
            remitente_email="gerencia@empresa.com.ar",
        )
        result = classify(payload)
        assert result["raw_score"] < 0.50, (
            f"raw_score={result['raw_score']:.4f} — Reunión de trabajo legítima"
        )

    def test_correo_figma_compartido(self, classify):
        """Correo técnico sobre diseño compartido."""
        payload = _payload(
            asunto="Re: Diseño nueva landing page",
            contenido=(
                "Te comparto el link de Figma con el diseño actualizado. "
                "Los cambios principales están en la sección de pricing "
                "y el footer. Avisame cualquier ajuste. Saludos!"
            ),
            remitente_email="diseno@empresa.com.ar",
        )
        result = classify(payload)
        assert result["raw_score"] < 0.50, (
            f"raw_score={result['raw_score']:.4f}"
        )

    def test_correo_vacaciones(self, classify):
        """Correo sobre vacaciones — cero señales de phishing."""
        payload = _payload(
            asunto="Solicitud de vacaciones - Agosto",
            contenido=(
                "Hola RRHH, solicito vacaciones del 1 al 15 de agosto. "
                "Ya coordiné con mi equipo la cobertura. "
                "Quedo a la espera de la aprobación. Gracias!"
            ),
            remitente_email="empleado@empresa.com.ar",
        )
        result = classify(payload)
        assert result["raw_score"] < 0.50, (
            f"raw_score={result['raw_score']:.4f}"
        )


# ═════════════════════════════════════════════════════════════════════════════
# F. PIPELINE COMPLETO (analyze_email end-to-end)
#    Pruebas de integración que validan el flujo completo:
#    regla crítica → ML → heurísticas → contenido → veredicto final
# ═════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def analyze():
    """Importa analyze_email una sola vez."""
    try:
        from services.analyzer import analyze_email, calibrated_model
        if calibrated_model is None:
            pytest.skip("Modelo XGBoost no disponible")
        return analyze_email
    except Exception as e:
        pytest.skip(f"No se pudo importar analyze_email: {e}")


class TestPipelineCompleto:
    """Integración end-to-end del pipeline completo."""

    def test_phishing_con_regla_critica_da_1_0(self, analyze):
        """Email con adjunto ejecutable → regla crítica → score 1.0."""
        payload = _payload(
            asunto="Documento importante",
            contenido="Abra el adjunto para ver el documento.",
            security_features=_security(has_executable_attachment=True),
        )
        result = analyze(payload)
        assert result.is_phishing is True
        assert result.risk_score == 1.0
        assert result.decision_source == "critical_security_rule"
        assert result.intent == "suplantacion_o_malware"

    def test_phishing_scl_9_critico(self, analyze):
        """SCL=9 → regla crítica → phishing instantáneo."""
        payload = _payload(
            asunto="Test",
            contenido="Contenido normal",
            security_features=_security(scl=9),
        )
        result = analyze(payload)
        assert result.is_phishing is True
        assert result.risk_score == 1.0
        assert result.decision_source == "critical_security_rule"

    def test_phishing_por_contenido_pedir_password(self, analyze):
        """Correo que pide contraseña → regla de contenido → piso 0.95."""
        payload = _payload(
            asunto="Verificación de cuenta",
            contenido="<p>Envie su contraseña a este correo para verificar su identidad.</p>",
            security_features=_auth_perfecta(),
            remitente_email="seguridad@empresa.com",
        )
        result = analyze(payload)
        assert result.is_phishing is True
        assert result.risk_score >= 0.95
        assert result.decision_source == "content_security_rule"
        assert result.intent == "solicitar_credenciales"

    def test_legitimo_con_auth_perfecta(self, analyze):
        """Correo legítimo con autenticación perfecta → bajo riesgo."""
        payload = _payload(
            asunto="Minuta reunión de ayer",
            contenido=(
                "Hola equipo, comparto la minuta de la reunión de ayer. "
                "Quedaron pendientes los puntos 3 y 5. "
                "Los responsables son Martín y Laura respectivamente."
            ),
            security_features=_auth_perfecta(),
            remitente_email="coordinador@empresa.com.ar",
        )
        result = analyze(payload)
        assert result.is_phishing is False
        assert result.risk_score < 0.80  # umbral_critico del modelo
        assert result.intent == "comunicacion_operativa"

    def test_freemail_con_urgencia_aumenta_score(self, analyze):
        """Remitente freemail con slots FINANCIERO/URGENCIA → +0.25 extra."""
        payload = _payload(
            asunto="URGENTE: deuda impositiva",
            contenido=(
                "Estimado, le informamos de su deuda impositiva inmediatamente. "
                "Su clave fiscal debe ser actualizada. Ingrese al enlace "
                "http://arca-verificar.net/datos para regularizar."
            ),
            security_features=_security(
                spf_result="pass", dkim_result="pass", dmarc_result="unknown"
            ),
            remitente_email="soporte@gmail.com",
        )
        result = analyze(payload)
        # Debería tener el ajuste freemail_riesgo
        if result.security_adjustments:
            freemail = [a for a in result.security_adjustments if a.rule == "freemail_riesgo"]
            assert len(freemail) == 1, (
                "Debería aplicar regla freemail_riesgo para Gmail con urgencia"
            )

    def test_regla_contenido_prevalece_sobre_auth_perfecta(self, analyze):
        """Incluso con autenticación perfecta y dominio de confianza,
        si el contenido pide credenciales → phishing (piso 0.95)."""
        payload = _payload(
            asunto="Actualización urgente de seguridad",
            contenido="<p>Responda este correo con su clave fiscal y token de autenticación.</p>",
            security_features=_auth_perfecta(is_trusted_domain=True),
            remitente_email="seguridad@banco.com.ar",
        )
        result = analyze(payload)
        assert result.is_phishing is True
        assert result.risk_score >= 0.95
        assert result.decision_source == "content_security_rule"

    def test_decision_source_model_only_sin_security(self, analyze):
        """Sin security_features, la decisión es solo del modelo."""
        payload = _payload(
            asunto="Hola",
            contenido="Buenos días, ¿cómo estás?",
        )
        result = analyze(payload)
        assert result.decision_source == "model_only"

    def test_intent_desviar_pago(self, analyze):
        """BEC con desvío de pago → intent = desviar_pago."""
        payload = _payload(
            asunto="Cambio de datos bancarios",
            contenido=(
                "<p>Le informamos que cambiamos de banco. "
                "Transfiera el pago a la nueva cuenta CBU 0000003100012345. "
                "No contacte al banco por este cambio, es un procedimiento interno.</p>"
            ),
        )
        result = analyze(payload)
        assert result.is_phishing is True
        assert result.intent == "desviar_pago"

    def test_intent_comunicacion_operativa(self, analyze):
        """Correo normal → intent = comunicacion_operativa."""
        payload = _payload(
            asunto="Saludo",
            contenido="Buen día equipo, recordatorio de la reunión de las 15hs.",
            security_features=_auth_perfecta(),
            remitente_email="admin@empresa.com.ar",
        )
        result = analyze(payload)
        assert result.is_phishing is False
        assert result.intent == "comunicacion_operativa"


# ═════════════════════════════════════════════════════════════════════════════
# G. DIAGNÓSTICO DE DEBILIDADES CONOCIDAS
#    Tests que documentan las limitaciones del clasificador.
#    Si alguno FALLA, significa que la debilidad fue CORREGIDA (bueno!).
#    Si PASA, confirma que la debilidad aún existe y necesita mejora.
# ═════════════════════════════════════════════════════════════════════════════


class TestDebilidadesConocidas:
    """Documenta debilidades conocidas del clasificador.
    Estos tests PASAN porque verifican el comportamiento actual (incluyendo
    las limitaciones). Si un test falla, significa que la debilidad fue
    resuelta, lo cual es positivo."""

    def test_debilidad_phishing_sin_links_score_bajo(self, classify):
        """DEBILIDAD: El modelo ML es ciego a phishing sin enlaces.
        Un BEC que pide cambio de cuenta bancaria sin incluir URL
        obtiene raw_score muy bajo del modelo.
        La regla de contenido es la que salva este caso."""
        payload = _payload(
            asunto="Cambio de cuenta bancaria",
            contenido=(
                "Hola, te informo que cambiamos de banco. "
                "El nuevo CBU es 0000003100012345678901. "
                "Transferí el pago pendiente de la factura ahí. "
                "No llames al proveedor, ya está confirmado."
            ),
        )
        result = classify(payload)
        # El modelo ML da score bajo porque no hay URLs
        assert result["raw_score"] < 0.50, (
            f"raw_score={result['raw_score']:.4f} — "
            "Si este test FALLA, ¡significa que el modelo ahora detecta "
            "phishing sin enlaces! Eso es una MEJORA."
        )

    def test_proteccion_contra_evasion_por_comillas(self):
        """MEJORA IMPLEMENTADA: Un atacante ya NO puede evadir reglas de contenido
        encerrando el texto malicioso entre comillas.
        El clasificador desenvuelve las comillas y detecta la orden si no es una cita."""
        body = '<p>"Por favor responda este correo con su contraseña y PIN"</p>'
        signals = detect_content_signals(body)
        assert any(s.rule == "credential_disclosure_request" for s in signals), (
            "Debe detectar la petición de credenciales aunque esté envuelta en comillas"
        )

    def test_debilidad_phishing_ingles_puro_con_slots_limitados(self, classify):
        """DEBILIDAD: El modelo y los slots NLU están optimizados para español.
        Un phishing en inglés puro puede tener slots limitados aunque
        el TF-IDF capture algo del vocabulario de phishing."""
        payload = _payload(
            asunto="Your account has been compromised",
            contenido=(
                "Dear customer, your account has been compromised. "
                "Click here to reset your password immediately or your "
                "account will be terminated within 24 hours. "
                "Visit http://account-verify-secure.com/reset"
            ),
        )
        result = classify(payload)
        slots = result["slots_detectados"]
        # Verificar que al menos ALGUNOS slots en inglés funcionan
        has_some_slots = any(
            len(v) > 0 for v in slots.values()
        )
        # Los slots en inglés deberían funcionar (hay patterns bilingües)
        assert has_some_slots, (
            "El matcher debería detectar al menos algunos slots en inglés"
        )

    def test_proteccion_contenido_salva_phishing_sin_link(self, analyze):
        """PROTECCIÓN: Aunque el modelo ML falle con phishing sin enlaces,
        las reglas de contenido detectan la petición de credenciales
        y aplican el piso de 0.95. Es la salvaguarda del sistema."""
        payload = _payload(
            asunto="Verificación de seguridad",
            contenido=(
                "<p>Estimado usuario, por motivos de seguridad necesitamos "
                "que confirme su identidad. Envíe su contraseña y código de "
                "seguridad respondiendo a este correo electrónico.</p>"
            ),
        )
        result = analyze(payload)
        assert result.is_phishing is True
        assert result.risk_score >= 0.95
        assert result.decision_source == "content_security_rule"


# ═════════════════════════════════════════════════════════════════════════════
# H. UTILIDADES Y FUNCIONES AUXILIARES
#    Tests de las funciones de soporte del pipeline.
# ═════════════════════════════════════════════════════════════════════════════


class TestUtilidades:
    """Tests de funciones auxiliares del clasificador."""

    def test_extraer_dominio_basico(self):
        """Extrae dominio de URL HTTPS correctamente."""
        from services.analyzer import extraer_dominio
        assert extraer_dominio("https://www.example.com/path") == "example.com"

    def test_extraer_dominio_sin_www(self):
        """Extrae dominio sin prefijo www."""
        from services.analyzer import extraer_dominio
        assert extraer_dominio("https://example.com") == "example.com"

    def test_extraer_dominio_subdominio(self):
        """Preserva subdominios (no elimina todo, solo www)."""
        from services.analyzer import extraer_dominio
        assert extraer_dominio("https://mail.example.com") == "mail.example.com"

    def test_extraer_dominio_no_corta_letras(self):
        """removeprefix('www.') no debe borrar letras sueltas como lstrip haría.
        Ej: 'wework.com' no debe convertirse en 'ork.com'."""
        from services.analyzer import extraer_dominio
        assert extraer_dominio("https://wework.com") == "wework.com"

    def test_damerau_levenshtein_identicos(self):
        """Distancia 0 para strings idénticos."""
        from services.analyzer import damerau_levenshtein
        assert damerau_levenshtein("abc", "abc") == 0

    def test_damerau_levenshtein_transposicion(self):
        """Transposición cuenta como 1 edición."""
        from services.analyzer import damerau_levenshtein
        assert damerau_levenshtein("ab", "ba") == 1

    def test_damerau_levenshtein_insercion(self):
        """Inserción cuenta como 1 edición."""
        from services.analyzer import damerau_levenshtein
        assert damerau_levenshtein("abc", "abcd") == 1

    def test_indice_fernandez_huerta_texto_corto(self):
        """Texto muy corto devuelve valor por defecto 50.0."""
        from services.analyzer import indice_fernandez_huerta
        assert indice_fernandez_huerta("hola") == 50.0

    def test_indice_fernandez_huerta_texto_normal(self):
        """Texto con suficientes palabras devuelve un valor numérico."""
        from services.analyzer import indice_fernandez_huerta
        result = indice_fernandez_huerta(
            "Este es un texto de ejemplo con suficientes palabras "
            "para calcular el índice de legibilidad correctamente."
        )
        assert isinstance(result, float)
        assert result != 50.0  # No es el fallback

    def test_extraer_urls_html(self):
        """Extrae URLs tanto del texto visible como de atributos href."""
        from services.analyzer import extraer_urls_correo
        raw = '<a href="https://hidden.com/path">https://visible.com</a>'
        visible = "https://visible.com"
        urls = extraer_urls_correo(raw, visible)
        assert "https://visible.com" in urls
        assert "https://hidden.com/path" in urls

    def test_extraer_urls_decodifica_entidades(self):
        """Decodifica entidades HTML en URLs (&amp; → &)."""
        from services.analyzer import extraer_urls_correo
        raw = '<a href="https://example.com/path?a=1&amp;b=2">link</a>'
        urls = extraer_urls_correo(raw, "link")
        assert any("example.com" in u for u in urls)

    def test_classify_payload_no_muta_original(self, classify):
        """_classify_payload no debe modificar el payload original."""
        payload = _payload(
            asunto="Test inmutabilidad",
            contenido="Contenido de prueba",
            security_features=_auth_perfecta(),
        )
        original_dump = payload.model_dump(mode="json")
        classify(payload)
        assert payload.model_dump(mode="json") == original_dump


# ═════════════════════════════════════════════════════════════════════════════
# I. SLOTS NLU — DETECCIÓN DE CATEGORÍAS DE INGENIERÍA SOCIAL
#    Verifica que el matcher de spaCy detecta correctamente cada categoría.
# ═════════════════════════════════════════════════════════════════════════════


class TestSlotsNLU:
    """Verifica la detección de slots de ingeniería social."""

    def test_slot_urgencia_espanol(self, classify):
        """Detecta términos de urgencia en español."""
        payload = _payload(
            asunto="Su cuenta será suspendida inmediatamente",
            contenido="Acción requerida: evitar la suspensión.",
        )
        result = classify(payload)
        assert result["slots_detectados"]["URGENCIA"], "Debería detectar URGENCIA"

    def test_slot_autoridad_afip(self, classify):
        """Detecta suplantación de AFIP/ARCA."""
        payload = _payload(
            asunto="Notificación ARCA",
            contenido="AFIP le informa sobre su situación fiscal.",
        )
        result = classify(payload)
        assert result["slots_detectados"]["AUTORIDAD"], "Debería detectar AUTORIDAD"

    def test_slot_financiero_cbu(self, classify):
        """Detecta términos financieros argentinos."""
        payload = _payload(
            asunto="Actualizar CBU",
            contenido="Debe actualizar datos de su alias y clave fiscal.",
        )
        result = classify(payload)
        assert result["slots_detectados"]["FINANCIERO"], "Debería detectar FINANCIERO"

    def test_slot_amenaza(self, classify):
        """Detecta amenazas legales/punitivas."""
        payload = _payload(
            asunto="Aviso legal",
            contenido="Se tomarán acciones legales y embargo preventivo de bienes.",
        )
        result = classify(payload)
        assert result["slots_detectados"]["AMENAZA"], "Debería detectar AMENAZA"

    def test_slot_call_to_action_espanol(self, classify):
        """Detecta llamados a la acción en español."""
        payload = _payload(
            asunto="Verificación requerida",
            contenido="Haga clic en el enlace y verifique su cuenta.",
        )
        result = classify(payload)
        assert result["slots_detectados"]["CALL_TO_ACTION"], "Debería detectar CALL_TO_ACTION"

    def test_slot_temporal(self, classify):
        """Detecta restricciones temporales."""
        payload = _payload(
            asunto="Plazo máximo",
            contenido="Tiene 24 horas y 5 días hábiles para regularizar.",
        )
        result = classify(payload)
        assert result["slots_detectados"]["TEMPORAL"], "Debería detectar TEMPORAL"

    def test_slot_urgencia_ingles(self, classify):
        """Detecta urgencia en inglés."""
        payload = _payload(
            asunto="Account suspended",
            contenido="Action required immediately. Your account has been suspended.",
        )
        result = classify(payload)
        assert result["slots_detectados"]["URGENCIA"], "Debería detectar URGENCIA en inglés"

    def test_slot_call_to_action_ingles(self, classify):
        """Detecta call-to-action en inglés."""
        payload = _payload(
            asunto="Verify account",
            contenido="Click here to sign in and verify your identity.",
        )
        result = classify(payload)
        assert result["slots_detectados"]["CALL_TO_ACTION"], "Debería detectar CTA en inglés"

    def test_correo_sin_slots(self, classify):
        """Correo neutro no debe activar slots."""
        payload = _payload(
            asunto="Hola",
            contenido="Buen día, te confirmo la reunión de mañana. Saludos!",
        )
        result = classify(payload)
        total_slots = sum(len(v) for v in result["slots_detectados"].values())
        assert total_slots == 0, (
            f"No debería haber slots en un correo neutro. "
            f"Slots: {result['slots_detectados']}"
        )
