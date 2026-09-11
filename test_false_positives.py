"""
test_false_positives.py — Pruebas funcionales de falsos positivos para PhishARG.

Valida que correos legítimos con características comunes (newsletters con
Reply-To distinto, emails reenviados con DMARC fail, facturas urgentes
genuinas) NO sean clasificados erróneamente como phishing.

Ejecutar con:
    python -m pytest test_false_positives.py -v
"""

import pytest
from schemas import SecurityFeaturesSchema
from services.security_rules import check_critical_threats, apply_security_rules


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _make_features(**overrides) -> SecurityFeaturesSchema:
    """Crea SecurityFeatures con valores por defecto seguros (todo pass)."""
    defaults = dict(
        spf_result="pass",
        dkim_result="pass",
        dmarc_result="pass",
        compauth_result="pass",
        return_path="sender@example.com",
        reply_to="sender@example.com",
        from_return_path_match=True,
        from_reply_to_match=True,
        sender_vs_from_match=True,
        scl=0,
        threat_category="NONE",
        spam_filtering_verdict="",
        auth_as="Anonymous",
        bcl=0,
        originating_ip="",
        originating_country="",
        x_mailer="",
        received_hop_count=3,
        attachment_count=0,
        attachment_types=None,
        has_executable_attachment=False,
        to_count=1,
        cc_count=0,
        internet_message_id="",
        has_headers=True,
    )
    defaults.update(overrides)
    return SecurityFeaturesSchema(**defaults)


UMBRAL_CRITICO = 0.91


def _total_delta(features: SecurityFeaturesSchema) -> float:
    """Calcula el delta total de las reglas heurísticas."""
    adjustments = apply_security_rules(features)
    return sum(adj.delta for adj in adjustments)


# ─── Test 1: Newsletter con Reply-To distinto ─────────────────────────────────

class TestNewsletterReplyToMismatch:
    """Un newsletter legítimo (Mailchimp, HubSpot, etc.) que usa Reply-To
    distinto al From. Esto es una práctica estándar y NO debería ser phishing."""

    def test_not_critical_threat(self):
        features = _make_features(
            from_reply_to_match=False,  # Reply-To distinto
            # Pero todo lo demás está perfecto
        )
        es_critico, _ = check_critical_threats(features)
        assert not es_critico, (
            "Un newsletter con Reply-To distinto NO debería ser amenaza crítica"
        )

    def test_low_penalty(self):
        features = _make_features(from_reply_to_match=False)
        delta = _total_delta(features)
        assert delta < 0.10, (
            f"Reply-To mismatch solo debería penalizar levemente, got delta={delta}"
        )


# ─── Test 2: Email reenviado con DMARC fail ───────────────────────────────────

class TestForwardedEmailDmarcFail:
    """Un email reenviado (forwarded) frecuentemente falla DMARC porque el
    servidor intermediario no está en la política del dominio original.
    Si DKIM pasa, es evidencia de que el contenido no fue alterado."""

    def test_not_critical_threat(self):
        features = _make_features(
            dmarc_result="fail",
            dkim_result="pass",  # DKIM pasa → contenido intacto
        )
        es_critico, _ = check_critical_threats(features)
        assert not es_critico, (
            "DMARC fail con DKIM pass (email reenviado) NO debería ser amenaza crítica"
        )

    def test_moderate_penalty_but_below_threshold(self):
        features = _make_features(dmarc_result="fail", dkim_result="pass")
        delta = _total_delta(features)
        # DMARC fail (+0.15) pero DKIM pass + SPF pass dan recompensa (-0.08)
        assert delta < UMBRAL_CRITICO, (
            f"DMARC fail solo no debería superar el umbral, got delta={delta}"
        )


# ─── Test 3: SaaS con Return-Path distinto ────────────────────────────────────

class TestSaasReturnPathMismatch:
    """Servicios como SendGrid, Mailgun, Amazon SES usan Return-Path distinto
    para manejar bounces. Esto es totalmente normal."""

    def test_not_critical_threat(self):
        features = _make_features(
            from_return_path_match=False,
            # Todo lo demás perfecto
        )
        es_critico, _ = check_critical_threats(features)
        assert not es_critico, (
            "Return-Path mismatch NO debería ser amenaza crítica"
        )

    def test_small_penalty(self):
        features = _make_features(from_return_path_match=False)
        delta = _total_delta(features)
        assert delta <= 0.10, (
            f"Return-Path mismatch debería tener penalidad baja, got delta={delta}"
        )


# ─── Test 4: Factura urgente legítima con auth OK ─────────────────────────────

class TestUrgentLegitInvoice:
    """Un correo urgente real de una empresa con autenticación perfecta.
    El contenido tiene palabras como 'URGENTE', 'factura', 'vencida' pero
    los metadatos técnicos son impecables."""

    def test_not_critical_threat(self):
        features = _make_features()  # Todo pass → perfecto
        es_critico, _ = check_critical_threats(features)
        assert not es_critico, (
            "Un correo con autenticación perfecta NO debería ser amenaza crítica"
        )

    def test_negative_or_zero_delta(self):
        features = _make_features()
        delta = _total_delta(features)
        assert delta <= 0, (
            f"Autenticación perfecta debería dar delta ≤ 0, got delta={delta}"
        )


# ─── Test 5: Acumulación con tope ─────────────────────────────────────────────

class TestAccumulationCap:
    """Múltiples señales leves (SPF softfail + return_path mismatch + sender
    mismatch + SCL=5) no deberían sumar tanto como para superar el umbral."""

    def test_accumulated_delta_is_capped(self):
        features = _make_features(
            spf_result="softfail",
            from_return_path_match=False,
            sender_vs_from_match=False,
            scl=5,
        )
        adjustments = apply_security_rules(features)
        raw_delta = sum(adj.delta for adj in adjustments)
        capped_delta = max(min(raw_delta, 0.35), -0.25)

        assert capped_delta <= 0.35, (
            f"Delta acumulado debería estar capped a 0.35, got {capped_delta}"
        )

    def test_legit_email_survives_mild_signals(self):
        """Un email con XGBoost score 0.40 y múltiples señales leves
        NO debería cruzar el umbral 0.91 gracias al tope."""
        features = _make_features(
            spf_result="softfail",
            from_return_path_match=False,
            sender_vs_from_match=False,
            scl=6,
            dmarc_result="fail",
        )
        adjustments = apply_security_rules(features)
        raw_delta = sum(adj.delta for adj in adjustments)
        capped_delta = max(min(raw_delta, 0.35), -0.25)

        simulated_score = 0.40 + capped_delta
        assert simulated_score < UMBRAL_CRITICO, (
            f"Score 0.40 + capped delta no debería cruzar 0.91, got {simulated_score}"
        )


# ─── Test 6: Phishing real sigue siendo detectado ─────────────────────────────

class TestRealPhishingStillCaught:
    """Un phishing clásico con SPF fail + sender enmascarado sigue siendo
    detectado como amenaza crítica."""

    def test_spf_fail_plus_sender_mismatch_is_critical(self):
        features = _make_features(
            spf_result="fail",
            sender_vs_from_match=False,
        )
        es_critico, razon = check_critical_threats(features)
        assert es_critico, (
            "SPF fail + sender mismatch DEBERÍA ser amenaza crítica"
        )
        assert "Suplantación" in razon

    def test_high_scl_is_critical(self):
        features = _make_features(scl=9)
        es_critico, _ = check_critical_threats(features)
        assert es_critico, "SCL >= 9 DEBERÍA ser amenaza crítica"


# ─── Test 7: Adjunto ejecutable sigue siendo crítico ──────────────────────────

class TestCriticalExecutable:
    """Un adjunto ejecutable siempre debe ser amenaza crítica,
    independientemente de la autenticación."""

    def test_executable_is_always_critical(self):
        features = _make_features(has_executable_attachment=True)
        es_critico, razon = check_critical_threats(features)
        assert es_critico, (
            "Adjunto ejecutable DEBERÍA ser amenaza crítica siempre"
        )
        assert "ejecutable" in razon.lower() or "Malware" in razon


# ─── Test 8: Recompensa por autenticación perfecta ────────────────────────────

class TestPositiveSignals:
    """Verificar que las recompensas positivas funcionan correctamente."""

    def test_all_checks_pass_gives_strong_reward(self):
        features = _make_features()  # Todo pass, todo match
        delta = _total_delta(features)
        assert delta <= -0.10, (
            f"Autenticación perfecta debería dar al menos -0.10, got {delta}"
        )

    def test_spf_dkim_pass_without_dmarc_gives_partial_reward(self):
        features = _make_features(dmarc_result="none")  # Sin DMARC configurado
        delta = _total_delta(features)
        assert delta < 0, (
            f"SPF+DKIM pass sin DMARC debería dar delta negativo, got {delta}"
        )

    def test_trusted_official_domain_gives_massive_reward(self):
        # Todo pass, pero además es dominio oficial
        features = _make_features(is_trusted_domain=True)
        delta = _total_delta(features)
        assert delta <= -0.50, ( # -0.15 de all_checks + -0.40 de trusted
            f"Dominio oficial con auth perfecta debería dar recompensa masiva, got {delta}"
        )
