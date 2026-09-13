import json
import time
from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema
from services.analyzer import analyze_email

def run_test(name, payload):
    print(f"\n{'='*50}\nEjecutando Test: {name}\n{'='*50}")
    start = time.time()
    result = analyze_email(payload)
    elapsed = time.time() - start
    
    print(f"Es Phishing: {result.is_phishing}")
    print(f"Risk Score:  {result.risk_score}")
    print(f"Latencia:    {elapsed:.3f} segundos")
    
    if result.is_phishing:
        print("\nExplicacion del SLM (JSON parseado):")
        try:
            slm_dict = json.loads(result.slm_explanation)
            print(json.dumps(slm_dict, indent=2, ensure_ascii=False))
        except:
            print("ERROR parseando el SLM JSON:")
            print(result.slm_explanation)
    else:
        print("\nExplicacion Fast-Path (Legitimo):")
        print(result.slm_explanation)


if __name__ == "__main__":
    # Test 1: Correo Legitimo (Debe salir por el Fast-Path, casi instantaneo)
    legit_payload = EmailPayloadSchema(
        body="Hola equipo, paso a recordarles que la reunion de manana sera a las 10 am en la sala B. Saludos.",
        metadata=MetadataSchema(
            remitente_email="recursos_humanos@empresa.com",
            asunto="Reunion de equipo",
        ),
        security_features=SecurityFeaturesSchema(
            spf_result="pass",
            dkim_result="pass",
            dmarc_result="pass",
            auth_as="Internal"
        )
    )

    # Test 2: Correo Phishing (Debe disparar SHAP y SLM)
    phish_payload = EmailPayloadSchema(
        body="URGENTE: Ingrese su contrasena inmediatamente para no bloquear su cuenta. Actualice sus datos aqui: http://banco-bloqueado-falso.com",
        metadata=MetadataSchema(
            remitente_email="seguridad@gmail.com",
            asunto="Aviso de suspension de cuenta",
        ),
        security_features=SecurityFeaturesSchema(
            spf_result="fail",
            dkim_result="fail",
            dmarc_result="fail",
            auth_as="Anonymous",
            scl=9
        )
    )

    run_test("1. Correo de Oficina Legitimo", legit_payload)
    run_test("2. Phishing de Robo de Credenciales", phish_payload)
