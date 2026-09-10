"""
Prueba TRANSPARENTE del SLM: muestra TODO el proceso interno.
- Qué contexto recibe del XGBoost
- Qué prompt exacto se le arma (system + user)
- Qué JSON devuelve crudo
"""
import json
import time
from services.slm_explanation import (
    build_explanation_context, build_slm_prompt_messages,
    EvidenceSource, ExplanationEvidence
)
from services.slm_client import get_slm_instance

print("="*70)
print("🔍 PRUEBA TRANSPARENTE: VER TODO LO QUE HACE EL SLM POR DENTRO")
print("="*70)

# ---- PASO 1: Simulamos que el XGBoost ya analizó un correo ----
print("\n" + "="*70)
print("📧 PASO 1: EL CORREO QUE LLEGÓ (ejemplo nuevo)")
print("="*70)
print("""
  De: soporte@banco-nacion-argentina.com.br
  Asunto: ⚠️ Movimiento no reconocido en tu cuenta - Verificá tu identidad

  Estimado cliente del Banco Nación,
  Detectamos un movimiento sospechoso de $45.000 desde tu cuenta.
  Si no fuiste vos, verificá tu identidad haciendo clic acá:
  https://banco-nacion-seguridad.com.br/verificar
  Tenés 12 horas para responder o tu cuenta será bloqueada.
""")

# ---- PASO 2: El XGBoost ya decidió ----
print("="*70)
print("🧮 PASO 2: DECISIÓN DEL XGBOOST (ya tomada, inmutable)")
print("="*70)
print("  → Veredicto: PHISHING")
print("  → Confianza: 96%")
print("  → Intención detectada: solicitar_credenciales")
print("  → Evidencias encontradas:")
print("    1. [slot.autoridad] Suplanta al Banco Nación")
print("    2. [slot.urgencia] Plazo de 12 horas")
print("    3. [slot.financiero] Menciona movimiento de $45.000")
print("    4. [security.url_check] URL .com.br no es del Banco Nación real")
print("    5. [security.spf_fail] SPF del remitente falló")

# ---- PASO 3: Se arma el contexto para el SLM ----
evidencias = [
    ExplanationEvidence(
        evidence_id="slot.autoridad",
        text="Se detectó suplantación del Banco de la Nación Argentina.",
        source=EvidenceSource.OBSERVED_SIGNAL
    ),
    ExplanationEvidence(
        evidence_id="slot.urgencia",
        text="El correo impone un plazo de 12 horas para actuar.",
        source=EvidenceSource.OBSERVED_SIGNAL
    ),
    ExplanationEvidence(
        evidence_id="slot.financiero",
        text="Se menciona un movimiento bancario de $45.000 no reconocido.",
        source=EvidenceSource.OBSERVED_SIGNAL
    ),
    ExplanationEvidence(
        evidence_id="security.url_check",
        text="El dominio del enlace no corresponde al sitio oficial del Banco Nación.",
        source=EvidenceSource.SECURITY_RULE
    ),
    ExplanationEvidence(
        evidence_id="security.spf_fail",
        text="La verificación SPF del remitente falló.",
        source=EvidenceSource.SECURITY_RULE
    ),
]

context = build_explanation_context(
    is_phishing=True,
    risk_score=0.96,
    intent="solicitar_credenciales",
    evidence=evidencias
)

# ---- PASO 4: Mostrar el PROMPT EXACTO que recibe el SLM ----
messages = build_slm_prompt_messages(context)

print("\n" + "="*70)
print("📨 PASO 3: PROMPT QUE RECIBE EL SLM (armado por slm_explanation.py)")
print("="*70)

print("\n--- ROL: SYSTEM (las reglas que debe seguir) ---")
print(messages[0]["content"][:800])
print("... [continúa con ejemplos y acciones permitidas]")

print("\n--- ROL: USER (el contexto estructurado del XGBoost) ---")
user_content = messages[1]["content"]
# Parseamos el JSON para mostrarlo bonito
json_part = user_content.replace("Contexto estructurado de solo lectura:\n", "")
try:
    parsed_context = json.loads(json_part)
    print("Contexto estructurado de solo lectura:")
    print(json.dumps(parsed_context, indent=2, ensure_ascii=False))
except:
    print(user_content)

# ---- PASO 5: Ejecutar el SLM y ver la respuesta ----
print("\n" + "="*70)
print("🧠 PASO 4: EL SLM PROCESA Y RESPONDE...")
print("="*70)
print("   Cargando modelo GGUF en memoria (CPU)...")

llm = get_slm_instance()

print("   Generando respuesta...")
start = time.time()

response = llm.create_chat_completion(
    messages=messages,
    temperature=0.1,
    max_tokens=400,
    response_format={"type": "json_object"}
)

elapsed = time.time() - start
raw = response['choices'][0]['message']['content'].strip()

print(f"   ⏱️ Tiempo de inferencia: {elapsed:.1f}s")

print("\n" + "="*70)
print("📤 PASO 5: RESPUESTA CRUDA DEL SLM (esto es lo que devuelve)")
print("="*70)
print(raw)

# ---- PASO 6: Parsear y explicar ----
print("\n" + "="*70)
print("✅ PASO 6: ANÁLISIS DE LA RESPUESTA")
print("="*70)
try:
    parsed = json.loads(raw)
    print(json.dumps(parsed, indent=2, ensure_ascii=False))
    
    print(f"\n📊 Resumen de lo que hizo el SLM:")
    print(f"   → Copió el summary: {'✅ Correcto' if 'phishing' in parsed.get('summary','').lower() else '❌ Incorrecto'}")
    print(f"   → Seleccionó {len(parsed.get('reasons',[]))} razones de las 5 disponibles")
    print(f"   → Recomendó {len(parsed.get('recommended_actions',[]))} acciones:")
    for a in parsed.get("recommended_actions", []):
        print(f"      • {a.get('code')}: {a.get('text')}")
except json.JSONDecodeError as e:
    print(f"   ❌ Error: no devolvió JSON válido: {e}")

print("\n" + "="*70)
print("🏁 FIN DE LA PRUEBA TRANSPARENTE")
print("="*70)
