import json
import time
from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema
from services.analyzer import analyze_email

phish_payload = EmailPayloadSchema(
    body="Ingresá a http://banco-falso.invalid y actualizá los datos de tu CBU.",
    metadata=MetadataSchema(
        remitente_email="admin@banco-falso.invalid",
        asunto="Actualizá tu cuenta bancaria",
    ),
    security_features=SecurityFeaturesSchema(
        spf_result="fail",
        dkim_result="fail",
        dmarc_result="fail",
        auth_as="Anonymous",
        from_return_path_match=False,
        sender_vs_from_match=True,
        scl=1
    )
)

print("Testeando extracción SHAP...")
res = analyze_email(phish_payload)
print("Phishing:", res.is_phishing)
print("Score:", res.risk_score)
print("Explicacion SLM:\n", res.slm_explanation)
