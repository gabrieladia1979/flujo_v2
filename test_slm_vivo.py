import sys
import json
from services.slm_explanation import build_explanation_context, EvidenceSource, ExplanationEvidence
from services.slm_client import generate_slm_explanation

print("="*60)
print("INICIANDO PRUEBA DEL SLM ENTRENADO (llama-cpp-python)")
print("="*60)

# Simulamos que el XGBoost detectó un Phishing de premio falso
context = build_explanation_context(
    is_phishing=True,
    risk_score=0.98,
    intent="premio_falso",
    evidence=[
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
        )
    ]
)

print(f"\n[!] Enviando contexto al modelo...\nIntent: premio_falso | Score: 98%\n")

try:
    resultado = generate_slm_explanation(context)
    print("="*60)
    print("RESPUESTA DEL MODELO (JSON crudo):")
    print("="*60)
    print(resultado)
    
    # Validar si es JSON
    try:
        parsed = json.loads(resultado)
        print("\n✅ El modelo devolvió un JSON válido.")
        print(f"✅ Summary: {parsed.get('summary')}")
        print(f"✅ Reasons: {len(parsed.get('reasons', []))} motivos detectados.")
        print(f"✅ Actions: {[a.get('code') for a in parsed.get('recommended_actions', [])]}")
    except Exception as e:
        print(f"\n❌ Error parseando JSON: {e}")
        
except Exception as e:
    print(f"\n❌ Error ejecutando el modelo: {e}")
