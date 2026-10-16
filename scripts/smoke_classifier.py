"""Fail deployment when the packaged classifier reverses phishing labels."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schemas import EmailPayloadSchema
from services.analyzer import _classify_payload


CASES = (
    (
        "informational meeting",
        EmailPayloadSchema(
            metadata={"asunto": "Resumen de la reunión semanal", "remitente_email": "equipo@example.com"},
            contenido=(
                "Hola, equipo: Comparto el resumen de la reunión semanal. "
                "La entrega continúa según lo planificado. La próxima revisión será el viernes "
                "a las 10:00. Este correo es únicamente informativo. "
                "No es necesario responder ni realizar ninguna acción adicional."
            ),
        ),
        False,
    ),
    (
        "credential theft",
        EmailPayloadSchema(
            metadata={"asunto": "Verifique su cuenta ahora", "remitente_email": "soporte@example.net"},
            contenido=(
                "Su cuenta será bloqueada hoy. Ingrese urgentemente a "
                "http://microsoft-login-example.net y escriba su usuario, contraseña y código MFA."
            ),
        ),
        True,
    ),
)


def main() -> None:
    for name, payload, expected in CASES:
        result = _classify_payload(payload)
        raw = result["raw_score"]
        if raw is None or (raw >= 0.5) != expected:
            raise SystemExit(f"Classifier orientation failed for {name}: raw_score={raw}")
        print(f"{name}: raw_score={raw:.4f}")


if __name__ == "__main__":
    main()
