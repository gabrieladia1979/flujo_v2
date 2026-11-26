"""Reject an image/artifact that does not reproduce the selected audit behavior."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from schemas import EmailPayloadSchema
from services import analyzer
from scripts.security_smoke import verify_security_rules


def main():
    cases = [
        ("galicia-transfer", False, {"metadata": {"asunto": "Banco Galicia - Transferencia acreditada"},
            "contenido": "Se acreditó una transferencia de $7.755 en su cuenta. Origen: Empresa ABC SRL. Para ver el detalle ingrese a https://onlinebanking.bancogalicia.com.ar."}),
        ("bbva-impersonation", True, {"metadata": {"asunto": "BBVA - Aviso", "remitente_email": "avisos@bbva-validacion.invalid"},
            "contenido": "Verificá tu cuenta para mantener el acceso."}),
        ("authenticated-secrets", True, {"metadata": {"asunto": "BBVA - Aviso", "remitente_email": "avisos@bbva.com"},
            "contenido": "Envíeme su contraseña y código SMS.", "security_features": {"has_headers": True,
                "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass"}}),
    ]
    if analyzer.calibrated_model is None:
        raise RuntimeError("The selected classifier is unavailable")
    for name, expected, payload in cases:
        result = analyzer._classify_payload(EmailPayloadSchema(**payload))
        if result["is_phishing"] != expected:
            raise RuntimeError(f"Selected artifact failed {name}")
        print(f"{name}: verdict verified")
    verify_security_rules(analyzer._classify_payload)


if __name__ == "__main__":
    main()
