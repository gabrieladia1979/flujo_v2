import json
import time
from tabulate import tabulate

from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema
from services.analyzer import analyze_email

def main():
    print("==========================================================")
    print(" INICIANDO SIMULACIÓN DE CASOS REALES Y EDGE CASES (v2.0) ")
    print("==========================================================")
    
    # ---------------------------------------------------------
    # Definición de Casos de Prueba (Escenarios del Mundo Real)
    # ---------------------------------------------------------
    casos = [
        {
            "id": "FP_01",
            "tipo": "FALSO POSITIVO (Objetivo: Score < 0.91)",
            "descripcion": "Newsletter de Marketing legA-timo enviado vA-a Mailchimp (Reply-To distinto al From).",
            "metadata": {"asunto": "A?Ofertas Exclusivas de Verano!", "remitente_email": "marketing@tienda.com"},
            "contenido": "Mira nuestras ofertas. Haz clic aquA- para comprar. Aprovecha ya.",
            "sec": {
                "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass",
                "from_reply_to_match": False,  # Mismatch de Mailchimp
                "from_return_path_match": False, # Mismatch de Mailchimp
                "scl": 4, "bcl": 6
            }
        },
        {
            "id": "FP_02",
            "tipo": "FALSO POSITIVO (Objetivo: Score < 0.91)",
            "descripcion": "Correo de Recursos Humanos Reenviado (Forwarded). SPF rompe, DKIM sobrevive.",
            "metadata": {"asunto": "Fwd: URGENTE - Nueva PolA-tica de Vacaciones", "remitente_email": "rrhh@empresa.com"},
            "contenido": "Adjunto la nueva polA-tica. Por favor leer inmediatamente para evitar confusiones.",
            "sec": {
                "spf_result": "softfail", "dkim_result": "pass", "dmarc_result": "fail",
                "from_reply_to_match": True, "from_return_path_match": True
            }
        },
        {
            "id": "FP_03",
            "tipo": "FALSO POSITIVO (Objetivo: Score < 0.91)",
            "descripcion": "NotificaciA3n crA-tica de sistema de tickets (SaaS) con auth as 'Anonymous' y SCL=6.",
            "metadata": {"asunto": "Aviso Urgente: Servidor CAdo", "remitente_email": "soporte@aws-alertas.com"},
            "contenido": "El servidor se ha caA-do. Se requiere acciA3n inmediata para evitar pArdida de datos.",
            "sec": {
                "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass",
                "auth_as": "Anonymous", "scl": 6,
                "from_return_path_match": False
            }
        },
        {
            "id": "TP_01",
            "tipo": "VERDADERO POSITIVO (Objetivo: Score >= 0.91)",
            "descripcion": "Phishing clAsico de suplantaciA3n de banco con SPF fail y link falso.",
            "metadata": {"asunto": "Cuenta Suspendida - AcciA3n Requerida", "remitente_email": "seguridad@santander.com.ar"},
            "contenido": "Tu cuenta fue bloqueada. Ingresa a http://santander-seguridad-validar.com para reactivarla inmediatamente.",
            "sec": {
                "spf_result": "fail", "dkim_result": "fail", "dmarc_result": "fail",
                "sender_vs_from_match": False
            }
        },
        {
            "id": "TP_02",
            "tipo": "VERDADERO POSITIVO (Objetivo: Score >= 0.91)",
            "descripcion": "Ataque BEC (Business Email Compromise) interno. Auth Pass, pero contenido urgente/financiero y URL rara.",
            "metadata": {"asunto": "URGENTE: Transferencia de fondos a proveedor", "remitente_email": "ceo@miempresa.com"},
            "contenido": "Necesito que transfieras $50.000 a la cuenta nueva del proveedor. Usa este link: http://transferencias-rapidas-proveedor.com. Hazlo ya.",
            "sec": {
                "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass",
                "auth_as": "Internal", "scl": 2
            }
        },
        {
            "id": "TP_03",
            "tipo": "VERDADERO POSITIVO (Objetivo: Amenaza CrA-tica)",
            "descripcion": "Correo inofensivo en texto, pero con archivo ejecutable oculto.",
            "metadata": {"asunto": "Te enviA los documentos", "remitente_email": "juan@conocido.com"},
            "contenido": "Hola, te paso los archivos que me pediste. Saludos.",
            "sec": {
                "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass",
                "has_executable_attachment": True
            }
        }
    ]

    resultados = []
    exitos = 0

    print("Evaluando casos...\n")
    for caso in casos:
        # Armar el payload
        sec_features = SecurityFeaturesSchema(**{
            "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass",
            "compauth_result": "pass",
            "from_return_path_match": True, "from_reply_to_match": True, "sender_vs_from_match": True,
            "scl": 0, "bcl": 0, "has_executable_attachment": False,
            "auth_as": "Anonymous"
        })
        # Aplicar overrides
        for k, v in caso["sec"].items():
            setattr(sec_features, k, v)
            
        payload = EmailPayloadSchema(
            metadata=MetadataSchema(**caso["metadata"]),
            contenido=caso["contenido"],
            security_features=sec_features
        )
        
        t0 = time.time()
        result = analyze_email(payload)
        t1 = time.time()
        
        # Validar si cumpliA3 el objetivo
        if "VERDADERO POSITIVO" in caso["tipo"]:
            es_exito = result.is_phishing
        else:
            es_exito = not result.is_phishing
            
        if es_exito: exitos += 1
            
        resultados.append({
            "ID": caso["id"],
            "Score": f"{result.risk_score:.2f}",
            "Veredicto": "PHISHING" if result.is_phishing else "SEGURO",
            "Exito": "A?" if es_exito else "a?",
            "Razón": result.reason[:60] + "..." if len(result.reason)>60 else result.reason,
            "T_ms": int((t1-t0)*1000)
        })

    # Imprimir Tabla
    print(tabulate(resultados, headers="keys", tablefmt="grid"))
    print(f"\nExitos: {exitos} / {len(casos)} ({exitos/len(casos)*100:.1f}%)")

if __name__ == "__main__":
    main()
