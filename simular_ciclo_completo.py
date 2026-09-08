import json
import warnings
# Suprimir warnings molestos
warnings.filterwarnings("ignore")

from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema
from services.analyzer import analyze_email

print("="*60)
print("INICIANDO CICLO COMPLETO: EMAIL -> XGBOOST -> SLM")
print("="*60)

# 1. Creamos un correo malicioso simulado
email_malicioso = EmailPayloadSchema(
    metadata=MetadataSchema(
        asunto="URGENTE: Su cuenta será suspendida",
        remitente_email="security@paypal-update-info.com"
    ),
    contenido="""
    Estimado cliente,
    Hemos detectado actividad inusual en su cuenta. Por motivos de seguridad, 
    su acceso será suspendido en 24 horas si no verifica su identidad.
    Haga clic en el siguiente enlace para verificar su cuenta inmediatamente:
    http://paypal-update-info.com/login/secure
    
    No responda a este correo.
    Atentamente,
    Equipo de Seguridad.
    """,
    security_features=SecurityFeaturesSchema(
        spf_result="fail",
        dkim_result="fail",
        dmarc_result="fail"
    )
)

print("[1] Correo recibido (Asunto):", email_malicioso.metadata.asunto)
print("[2] Pasando correo por el flujo de PhishARG (XGBoost + Reglas + SLM)...")

try:
    # Llamamos al analizador principal (esto detona todo el pipeline)
    resultado = analyze_email(email_malicioso)
    
    print("\n" + "="*60)
    print("RESULTADO DEL ANÁLISIS")
    print("="*60)
    print(f"Veredicto Final: {'🚨 PHISHING' if resultado.is_phishing else '✅ LEGÍTIMO'}")
    print(f"Nivel de Riesgo (XGBoost): {resultado.risk_score * 100:.2f}%")
    print(f"Intención Detectada: {resultado.intent}")
    
    print("\n" + "="*60)
    print("EXPLICACIÓN GENERADA POR EL SLM (Listo para Frontend):")
    print("="*60)
    print(resultado.slm_explanation)
    
except Exception as e:
    print(f"\n❌ Ocurrió un error en el pipeline: {e}")
