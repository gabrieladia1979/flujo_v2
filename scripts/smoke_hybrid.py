"""Check the packaged Hybrid artifact against benign and credential-theft mail."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schemas import EmailPayloadSchema
from services.hybrid_classifier import _load
from scripts.security_smoke import verify_security_rules


CASES = (
    (
        "informational meeting",
        "Resumen de la reunión semanal",
        "Hola, equipo: Comparto el resumen de la reunión semanal. La entrega continúa "
        "según lo planificado. La próxima revisión será el viernes a las 10:00. "
        "Este correo es únicamente informativo. No es necesario responder ni realizar ninguna acción adicional.",
        False,
    ),
    (
        "Microsoft terms notice",
        "Actualizaciones de nuestros términos de uso",
        "Hola: Ha recibido este correo electrónico porque vamos a actualizar el Contrato de "
        "servicios de Microsoft que se aplica a uno o varios de los productos o servicios "
        "de Microsoft que usa. Estamos realizando estas actualizaciones para aportar mayor "
        "claridad a nuestros términos y asegurarnos de que son transparentes para los usuarios.",
        False,
    ),
    (
        "credential theft",
        "Verifique su cuenta ahora",
        "Su cuenta será bloqueada hoy. Ingrese urgentemente a "
        "http://microsoft-login-example.net y escriba su usuario, contraseña y código MFA.",
        True,
    ),
)


def main() -> None:
    directory = os.environ["PHISHARG_HYBRID_MODEL_DIR"]
    classifier = _load(str(Path(directory).resolve()))
    for name, subject, body, expected in CASES:
        payload = EmailPayloadSchema(
            metadata={"asunto": subject, "remitente_email": "sender@example.com"},
            contenido=body,
        )
        raw = classifier.raw_score(payload)
        if (raw >= 0.5) != expected:
            raise SystemExit(f"Hybrid orientation failed for {name}: raw_score={raw}")
        if not expected and raw >= classifier.manifest["threshold"]:
            raise SystemExit(f"Hybrid false positive for {name}: raw_score={raw}")
        result = classifier.analyze(payload, quick=True)
        if result.is_phishing != expected:
            raise SystemExit(f"Hybrid verdict failed for {name}: is_phishing={result.is_phishing}")
        print(f"{name}: raw_score={raw:.4f}, is_phishing={result.is_phishing}")

    def classify(payload):
        result = classifier.analyze(payload, quick=True)
        return {'is_phishing': result.is_phishing, 'risk_score': result.risk_score}

    verify_security_rules(classify)


if __name__ == "__main__":
    main()
