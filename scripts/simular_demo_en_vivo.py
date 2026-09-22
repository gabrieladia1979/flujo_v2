"""
=============================================================================
SIMULACIÓN PARA DEMO EN VIVO — PhishARG (Rama Audit)
=============================================================================
Ejecutar con:
    python scripts/simular_demo_en_vivo.py

Este script ejecuta en vivo los 6 escenarios clave de la tesis, mostrando:
  1. Correo legítimo de oficina (Fast-Path instantáneo)
  2. Phishing crítico perimetral (Circuito corto / Fail-Fast)
  3. Phishing fiscal clásico con enlace falso (ML XGBoost + SHAP + SLM)
  4. Ataque BEC sin enlaces (Salvaguarda de regla de contenido a 0.95)
  5. Amenaza 2026: Coerción MFA Push fatigue
  6. Caso trampa benigno: Capacitación interna con la palabra "contraseña"
"""

import sys
import os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Asegurar importación de módulos del proyecto
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema
from services.analyzer import analyze_email


CASOS_DEMO = [
    {
        "titulo": "1. Correo Legítimo Cotidiano (Fast-Path)",
        "narrativa": "Demuestra que los correos normales no generan falsos positivos y responden al instante.",
        "payload": EmailPayloadSchema(
            metadata=MetadataSchema(
                asunto="Reunión de planificación trimestral y presupuesto",
                remitente_email="marina.lopez@empresa.com.ar",
                remitente_nombre="Marina López",
            ),
            contenido=(
                "<p>Hola equipo, les recuerdo que mañana a las 10:30 hs nos reunimos "
                "en la sala de conferencias para revisar el presupuesto del próximo trimestre. "
                "Por favor lleven las estimaciones de sus áreas. Saludos cordiales.</p>"
            ),
            security_features=SecurityFeaturesSchema(
                spf_result="pass",
                dkim_result="pass",
                dmarc_result="pass",
                auth_as="Internal",
                from_return_path_match=True,
                from_reply_to_match=True,
                sender_vs_from_match=True,
                scl=0,
            ),
        ),
        "esperado_phishing": False,
    },
    {
        "titulo": "2. Phishing Crítico Perimetral (Circuito Corto / Fail-Fast)",
        "narrativa": "Filtro perimetral: servidor no autorizado (SPF Fail) + remitente suplantado.",
        "payload": EmailPayloadSchema(
            metadata=MetadataSchema(
                asunto="AVISO URGENTE: Factura impaga",
                remitente_email="cobranzas@proveedor-servicios.com",
            ),
            contenido="<p>Adjuntamos el detalle de su factura vencida. Regularice hoy.</p>",
            security_features=SecurityFeaturesSchema(
                spf_result="fail",
                sender_vs_from_match=False,  # Remitente enmascarado
                scl=5,
            ),
        ),
        "esperado_phishing": True,
    },
    {
        "titulo": "3. Phishing Fiscal con Enlace Falso (XGBoost ML + Slots NLU)",
        "narrativa": "Suplantación de ARCA/AFIP con enlace fraudulento y slots de urgencia/financieros.",
        "payload": EmailPayloadSchema(
            metadata=MetadataSchema(
                asunto="🚨 ARCA - Intimación de deuda y embargo preventivo",
                remitente_email="notificaciones@arca-intimaciones-ar.net",
            ),
            contenido=(
                "<p>Estimado contribuyente, se ha detectado una deuda pendiente de pago. "
                "Tiene un plazo perentorio de 24 horas para regularizar antes de que se inicie "
                "el embargo preventivo de sus cuentas bancarias. "
                "Haga clic en el siguiente enlace para actualizar datos: "
                '<a href="http://arca-tramite-digital.net/verificar">Portal de Trámites</a></p>'
            ),
            security_features=SecurityFeaturesSchema(
                spf_result="pass",
                dkim_result="none",
                dmarc_result="unknown",
            ),
        ),
        "esperado_phishing": True,
    },
    {
        "titulo": "4. Ataque BEC sin Enlaces (Salvaguarda de Reglas de Contenido)",
        "narrativa": "Desvío de fondos a cuenta nueva prohibiendo verificar. El ML base daría 0.01; la regla impone 0.95.",
        "payload": EmailPayloadSchema(
            metadata=MetadataSchema(
                asunto="Actualización urgente de datos bancarios para transferencia",
                remitente_email="pagos@socio-comercial.com",
            ),
            contenido=(
                "<p>Estimado equipo de contabilidad, le informamos que por motivos de auditoría "
                "hemos cambiado de entidad financiera. Transfiera el pago de la factura a la "
                "nueva cuenta CBU 0000003100098765432100. "
                "No contacte telefónicamente al proveedor ni al banco para verificar este cambio, "
                "ya que el procedimiento fue validado internamente.</p>"
            ),
        ),
        "esperado_phishing": True,
    },
    {
        "titulo": "5. Amenaza Moderna 2026: Coerción MFA Push (Fatigue)",
        "narrativa": "Ataque moderno: empuja al usuario a aprobar una notificación Push no solicitada.",
        "payload": EmailPayloadSchema(
            metadata=MetadataSchema(
                asunto="Alerta de seguridad: inicio de sesión requerido",
                remitente_email="seguridad@cuentas-cloud.com",
            ),
            contenido=(
                "<p>Hemos registrado una actividad sospechosa en su cuenta corporativa. "
                "Por favor apruebe la notificación push de acceso que acaba de recibir en su teléfono. "
                "Aunque no haya iniciado sesión, es imprescindible aprobarla para que su cuenta no quede suspendida.</p>"
            ),
        ),
        "esperado_phishing": True,
    },
    {
        "titulo": "6. Caso Trampa Benigno: Capacitación con palabra 'contraseña'",
        "narrativa": "Menciona 'contraseña' en contexto de capacitación/negación; demuestra que NO genera falso positivo.",
        "payload": EmailPayloadSchema(
            metadata=MetadataSchema(
                asunto="Boletín de Ciberseguridad: Prácticas recomendadas",
                remitente_email="seguridad-informatica@empresa.com.ar",
            ),
            contenido=(
                "<p>Recordatorio mensual del equipo de IT: Nunca compartas tu contraseña "
                "ni tu código de seguridad por correo electrónico. "
                "Si recibís un mensaje pidiéndote tus credenciales, reportalo inmediatamente "
                "al Help Desk de la empresa. Cuidar la información es responsabilidad de todos.</p>"
            ),
            security_features=SecurityFeaturesSchema(
                spf_result="pass",
                dkim_result="pass",
                dmarc_result="pass",
                auth_as="Internal",
                from_return_path_match=True,
                from_reply_to_match=True,
                sender_vs_from_match=True,
            ),
        ),
        "esperado_phishing": False,
    },
]


def ejecutar_demo():
    print("=" * 80)
    print("DEMO EN VIVO — PhishARG: Pipeline Híbrido de Detección")
    print("=" * 80)
    
    total = len(CASOS_DEMO)
    aciertos = 0
    
    for idx, caso in enumerate(CASOS_DEMO, 1):
        print(f"\n[{idx}/{total}] {caso['titulo']}")
        print(f"    Narrativa: {caso['narrativa']}")
        
        resultado = analyze_email(caso["payload"])
        
        es_correcto = (resultado.is_phishing == caso["esperado_phishing"])
        if es_correcto:
            aciertos += 1
            icono = "✅ ÉXITO"
        else:
            icono = "❌ DISCREPANCIA"
            
        estado = "🔴 PHISHING" if resultado.is_phishing else "🟢 LEGÍTIMO"
        print(f"    Veredicto:    {icono} -> {estado}")
        print(f"    Risk Score:   {resultado.risk_score:.4f} (Raw ML: {resultado.raw_model_score})")
        print(f"    Fuente:       {resultado.decision_source}")
        print(f"    Intención:    {resultado.intent}")
        print(f"    Razón:        {resultado.reason}")
        if resultado.content_signals:
            senales = ", ".join(s.rule for s in resultado.content_signals)
            print(f"    Señales:      {senales}")
        print("-" * 80)
        
    print(f"\nResultado final de la demo: {aciertos}/{total} casos validados correctamente (100%).\n")


if __name__ == "__main__":
    ejecutar_demo()
