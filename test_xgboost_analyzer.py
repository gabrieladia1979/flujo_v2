"""
Tests de validación para el pipeline XGBoost + NLP del analyzer.
Ejecutar con: python test_xgboost_analyzer.py

Requiere:
  - spaCy es_core_news_sm instalado
  - model/phisharg_xgboost.pkl presente
"""

import sys
import os

# Asegurar que el directorio raíz está en el path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema


def test_model_loads():
    """El modelo, spaCy y el Matcher deben cargarse al importar analyzer."""
    from services.analyzer import calibrated_model, tfidf, scaler_meta, scaler_slots, nlp, matcher_global

    assert nlp is not None, "spaCy no se cargo"
    assert matcher_global is not None, "Matcher no se creo"
    assert calibrated_model is not None, "calibrated_model no se cargo del .pkl"
    assert tfidf is not None, "tfidf no se cargo del .pkl"
    assert scaler_meta is not None, "scaler_meta no se cargo del .pkl"
    assert scaler_slots is not None, "scaler_slots no se cargo del .pkl"
    print("[PASS] test_model_loads")


def test_legitimate_email():
    """Un email casual/interno debe tener score bajo."""
    from services.analyzer import analyze_email

    payload = EmailPayloadSchema(
        metadata=MetadataSchema(
            asunto="Asado del sabado",
            remitente_email="juan@empresa.com"
        ),
        contenido="Chicos a las 21 en casa, avisen quienes vienen asi calculo. Abrazo!"
    )
    result = analyze_email(payload)

    assert result.risk_score < 0.5, (
        f"Email legitimo deberia tener score < 0.5, got {result.risk_score}"
    )
    assert result.intent == "comunicacion_operativa", (
        f"Expected intent 'comunicacion_operativa', got '{result.intent}'"
    )
    print(f"[PASS] test_legitimate_email (score: {result.risk_score:.4f}, intent: {result.intent})")


def test_phishing_email():
    """Un email con patrones claros de phishing (urgencia + autoridad + financiero) debe tener score alto."""
    from services.analyzer import analyze_email

    payload = EmailPayloadSchema(
        metadata=MetadataSchema(
            asunto="ARCA - Intimacion de pago por deuda fiscal VENCIDA",
            remitente_email="notificaciones@arca-gov.net"
        ),
        contenido=(
            "Para evitar la suspension de su CUIT y el embargo, "
            "proceda al pago inmediatamente ingresando su clave fiscal "
            "en http://arca-verificacion.com/login. "
            "Actualizar datos antes de las 48hs."
        )
    )
    result = analyze_email(payload)

    assert result.risk_score > 0.5, (
        f"Email phishing deberia tener score > 0.5, got {result.risk_score}"
    )
    # Verificar que se detectaron slots
    assert result.slots_detectados is not None, "slots_detectados should not be None"
    total_slots = (
        len(result.slots_detectados.get('URGENCIA', []))
        + len(result.slots_detectados.get('AUTORIDAD', []))
        + len(result.slots_detectados.get('FINANCIERO', []))
    )
    assert total_slots > 0, "Deberia detectar al menos un slot psicologico"
    print(
        f"[PASS] test_phishing_email (score: {result.risk_score:.4f}, "
        f"intent: {result.intent}, "
        f"slots: U={len(result.slots_detectados.get('URGENCIA', []))} "
        f"A={len(result.slots_detectados.get('AUTORIDAD', []))} "
        f"F={len(result.slots_detectados.get('FINANCIERO', []))})"
    )


def test_no_security_features():
    """Payload sin security_features debe funcionar correctamente."""
    from services.analyzer import analyze_email

    payload = EmailPayloadSchema(
        metadata=MetadataSchema(
            asunto="Test",
            remitente_email="test@test.com"
        ),
        contenido="Este es un mensaje de prueba.",
        security_features=None
    )
    result = analyze_email(payload)

    assert result.security_adjustments is None, (
        f"Sin security_features, adjustments deberia ser None, got {result.security_adjustments}"
    )
    assert result.reason is not None and len(result.reason) > 0, "reason no debe estar vacio"
    print(f"[PASS] test_no_security_features (score: {result.risk_score:.4f})")


def test_with_security_features_suspicious():
    """Payload con security_features sospechosas debe aumentar el score."""
    from services.analyzer import analyze_email

    # Primero sin security_features
    payload_base = EmailPayloadSchema(
        metadata=MetadataSchema(
            asunto="Actualiza tu cuenta bancaria",
            remitente_email="seguridad@banco-falso.com"
        ),
        contenido="Ingresa a http://banco-falso.com y actualizar datos de tu CBU.",
    )
    result_base = analyze_email(payload_base)

    # Luego con features sospechosas
    payload_sus = EmailPayloadSchema(
        metadata=MetadataSchema(
            asunto="Actualiza tu cuenta bancaria",
            remitente_email="seguridad@banco-falso.com"
        ),
        contenido="Ingresa a http://banco-falso.com y actualizar datos de tu CBU.",
        security_features=SecurityFeaturesSchema(
            spf_result="fail",
            dkim_result="fail",
            dmarc_result="fail",
            from_return_path_match=False,
            has_executable_attachment=True,
            attachment_count=1,
            received_hop_count=5,
        )
    )
    result_sus = analyze_email(payload_sus)

    assert result_sus.risk_score > result_base.risk_score, (
        f"Score con features sospechosas ({result_sus.risk_score}) "
        f"deberia ser mayor que sin features ({result_base.risk_score})"
    )
    assert result_sus.security_adjustments is not None, "Deberia tener adjustments"
    assert len(result_sus.security_adjustments) > 0, "Deberia tener al menos un adjustment"
    print(
        f"[PASS] test_with_security_features_suspicious "
        f"(base: {result_base.risk_score:.4f} -> adjusted: {result_sus.risk_score:.4f}, "
        f"{len(result_sus.security_adjustments)} adjustments)"
    )


def test_with_security_features_internal():
    """Payload con auth interna debe reducir el score."""
    from services.analyzer import analyze_email

    payload = EmailPayloadSchema(
        metadata=MetadataSchema(
            asunto="Reunion de equipo",
            remitente_email="gerente@empresa.com"
        ),
        contenido="Manana a las 10 nos juntamos en la sala de reuniones. Saludos.",
        security_features=SecurityFeaturesSchema(
            spf_result="pass",
            dkim_result="pass",
            dmarc_result="pass",
            auth_as="Internal",
            from_return_path_match=True,
            from_reply_to_match=True,
            sender_vs_from_match=True,
        )
    )
    result = analyze_email(payload)

    assert result.risk_score < 0.3, (
        f"Email interno con auth pass deberia tener score muy bajo, got {result.risk_score}"
    )
    assert result.security_adjustments is not None, "Deberia tener adjustments"
    # Verificar que hay ajustes negativos (reducen riesgo)
    negative_adj = [a for a in result.security_adjustments if a.delta < 0]
    assert len(negative_adj) > 0, "Deberia tener al menos un ajuste negativo (reduce riesgo)"
    print(
        f"[PASS] test_with_security_features_internal "
        f"(score: {result.risk_score:.4f}, "
        f"{len(negative_adj)} ajustes positivos)"
    )


def test_response_has_all_fields():
    """La respuesta debe incluir todos los campos del schema."""
    from services.analyzer import analyze_email

    payload = EmailPayloadSchema(
        metadata=MetadataSchema(asunto="Test", remitente_email="a@b.com"),
        contenido="Hola mundo"
    )
    result = analyze_email(payload)

    assert hasattr(result, 'is_phishing'), "Falta campo is_phishing"
    assert hasattr(result, 'risk_score'), "Falta campo risk_score"
    assert hasattr(result, 'reason'), "Falta campo reason"
    assert hasattr(result, 'intent'), "Falta campo intent"
    assert hasattr(result, 'slots_detectados'), "Falta campo slots_detectados"
    assert hasattr(result, 'security_adjustments'), "Falta campo security_adjustments"

    assert isinstance(result.is_phishing, bool), "is_phishing debe ser bool"
    assert isinstance(result.risk_score, float), "risk_score debe ser float"
    assert 0.0 <= result.risk_score <= 1.0, f"risk_score debe estar en [0,1], got {result.risk_score}"
    assert result.intent in ("comunicacion_operativa", "coaccionar_pago", "solicitar_credenciales"), (
        f"intent invalido: {result.intent}"
    )
    print(f"[PASS] test_response_has_all_fields")


def test_technical_email_not_phishing():
    """Un email tecnico con palabras que podrian confundir no debe ser phishing."""
    from services.analyzer import analyze_email

    payload = EmailPayloadSchema(
        metadata=MetadataSchema(
            asunto="Revision de la app movil",
            remitente_email="dev@empresa.com"
        ),
        contenido="Les dejo el link de Figma. Revisen el codigo fuente. Saludos"
    )
    result = analyze_email(payload)

    assert result.risk_score < 0.5, (
        f"Email tecnico no deberia ser phishing, got score {result.risk_score}"
    )
    print(f"[PASS] test_technical_email_not_phishing (score: {result.risk_score:.4f})")


if __name__ == "__main__":
    tests = [
        test_model_loads,
        test_legitimate_email,
        test_phishing_email,
        test_no_security_features,
        test_with_security_features_suspicious,
        test_with_security_features_internal,
        test_response_has_all_fields,
        test_technical_email_not_phishing,
    ]

    passed = 0
    failed = 0

    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_fn.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test_fn.__name__}: UNEXPECTED ERROR: {e}")
            failed += 1

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    print(f"{'='*50}")

    sys.exit(0 if failed == 0 else 1)
