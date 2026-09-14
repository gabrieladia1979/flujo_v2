"""
Prueba completa del SLM: 3 escenarios distintos
1. Phishing de premio falso
2. Phishing de suplantación AFIP
3. Correo legítimo
"""
import json
import time
from services.slm_explanation import (
    build_explanation_context, EvidenceSource, ExplanationEvidence
)
from services.slm_client import generate_slm_explanation

def test_caso(nombre, is_phishing, risk_score, intent, evidencias):
    print(f"\n{'='*60}")
    print(f"🧪 CASO: {nombre}")
    print(f"   Veredicto XGBoost: {'PHISHING' if is_phishing else 'LEGÍTIMO'} | Score: {risk_score*100:.0f}% | Intent: {intent}")
    print(f"{'='*60}")
    
    context = build_explanation_context(
        is_phishing=is_phishing,
        risk_score=risk_score,
        intent=intent,
        evidence=evidencias
    )
    
    start = time.time()
    resultado = generate_slm_explanation(context)
    elapsed = time.time() - start
    
    print(f"⏱️  Tiempo de respuesta: {elapsed:.1f}s")
    
    try:
        parsed = json.loads(resultado)
        print(f"✅ JSON válido")
        print(f"   Summary: {parsed.get('summary')}")
        print(f"   Reasons ({len(parsed.get('reasons', []))}):")
        for r in parsed.get("reasons", []):
            print(f"     - [{r.get('evidence_id')}] {r.get('text')}")
        print(f"   Actions ({len(parsed.get('recommended_actions', []))}):")
        for a in parsed.get("recommended_actions", []):
            print(f"     - [{a.get('code')}] {a.get('text')}")
    except json.JSONDecodeError:
        print(f"❌ NO es JSON válido. Respuesta cruda:")
        print(resultado[:500])


# ===================== CASO 1: Premio Falso =====================
test_caso(
    nombre="Phishing - Premio Falso (Sorteo iPhone)",
    is_phishing=True,
    risk_score=0.98,
    intent="premio_falso",
    evidencias=[
        ExplanationEvidence(
            evidence_id="slot.urgencia",
            text="El correo exige una acción inmediata antes de 24 horas.",
            source=EvidenceSource.OBSERVED_SIGNAL
        ),
        ExplanationEvidence(
            evidence_id="slot.premio_falso",
            text="Se detectó la mención de un sorteo de un iPhone 15 Pro.",
            source=EvidenceSource.OBSERVED_SIGNAL
        ),
        ExplanationEvidence(
            evidence_id="security.url_check",
            text="El enlace apunta a 'apple-rewards-login.xyz' que es sospechoso.",
            source=EvidenceSource.SECURITY_RULE
        ),
    ]
)

# ===================== CASO 2: Suplantación AFIP =====================
test_caso(
    nombre="Phishing - Suplantación AFIP (Clave Fiscal)",
    is_phishing=True,
    risk_score=0.95,
    intent="solicitar_credenciales",
    evidencias=[
        ExplanationEvidence(
            evidence_id="slot.autoridad",
            text="Se detectó una referencia de autoridad: AFIP, Agencia de Recaudación.",
            source=EvidenceSource.OBSERVED_SIGNAL
        ),
        ExplanationEvidence(
            evidence_id="slot.urgencia",
            text="El correo exige actualizar datos de forma inmediata.",
            source=EvidenceSource.OBSERVED_SIGNAL
        ),
        ExplanationEvidence(
            evidence_id="slot.solicitud_datos",
            text="Se solicita clave fiscal y datos personales.",
            source=EvidenceSource.OBSERVED_SIGNAL
        ),
        ExplanationEvidence(
            evidence_id="security.spf_fail",
            text="La verificación SPF del remitente falló.",
            source=EvidenceSource.SECURITY_RULE
        ),
    ]
)

# ===================== CASO 3: Correo Legítimo =====================
test_caso(
    nombre="Legítimo - Notificación de MercadoLibre",
    is_phishing=False,
    risk_score=0.12,
    intent="comunicacion_operativa",
    evidencias=[
        ExplanationEvidence(
            evidence_id="security.all_checks_pass",
            text="Todas las verificaciones de seguridad (SPF, DKIM, DMARC) pasaron correctamente.",
            source=EvidenceSource.SECURITY_RULE
        ),
        ExplanationEvidence(
            evidence_id="security.ml_classifier",
            text="El clasificador estadístico determinó que el correo es legítimo con alta confianza.",
            source=EvidenceSource.SECURITY_RULE
        ),
    ]
)

print(f"\n{'='*60}")
print("🏁 PRUEBAS COMPLETADAS")
print(f"{'='*60}")
