"""Exercise the local HTTP API with bank corpus rows and explicit synthetic mail.

Does not send email or fetch links. The real XGBoost and rules execute; the SLM
uses its offline fallback. Original corpus subjects/bodies stay out of reports.
"""
import argparse
import csv
import hashlib
import importlib.metadata
import json
import logging
from pathlib import Path
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.bank_identity import BANKS, _mentions
from scripts.evaluate_classifier import calculate_metrics


def synthetic_cases():
    for bank in BANKS:
        name, root = bank["name"], bank["domains"][0]
        brand = root.split(".")[0]
        if brand in {"macro", "hipotecario"}:
            brand = "banco" + brand
        scenarios = [
            ("summary", False, root, f"{name} - Resumen mensual disponible",
             "Ya se encuentra disponible tu resumen mensual. Podés consultarlo desde la aplicación habitual. No es necesario responder este correo."),
            ("promotion", False, root, f"{name} - Beneficios de esta semana",
             "Disfrutá descuentos en supermercados y restaurantes con tu tarjeta. Consultá las condiciones desde la aplicación del banco. No tenés que enviar datos ni responder este mensaje."),
            ("defensive_warning", False, root, f"{name} - Recomendaciones de seguridad",
             "Nunca compartas tu contraseña ni códigos SMS. Si no reconocés un acceso, rechazalo y contactá al banco desde la aplicación habitual. No respondas a solicitudes de claves."),
            ("brand_spoof", True, f"{brand}-validacion.invalid", f"{name} - Verificación de acceso",
             f"Verificá tu cuenta para mantener el acceso en https://{brand}-validacion.invalid. Tu cuenta quedará suspendida si no completás la validación."),
            ("authenticated_secret_request", True, root, f"{name} - Verificación de seguridad",
             "Responda este correo con su contraseña y el código SMS para evitar la suspensión de su cuenta."),
        ]
        for scenario, phishing, domain, subject, body in scenarios:
            yield {"id": f"synthetic-{bank['id']}-{scenario}", "group": "synthetic",
                   "banks": [name], "scenario": scenario, "expected": phishing,
                   "payload": {"metadata": {"asunto": subject, "remitente_nombre": name,
                                             "remitente_email": f"avisos@{domain}"},
                               "contenido": body, "security_features": {"has_headers": True,
                                   "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass"}}}


def historical_cases(path):
    csv.field_size_limit(20_000_000)
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for position, row in enumerate(csv.DictReader(stream), 1):
            if row.get("particion") != "test":
                continue
            banks = [b["name"] for b in BANKS if _mentions(f"{row['subject']} {row['body']}", b)]
            if not banks:
                continue
            yield {"id": row.get("row_id") or f"csv-row-{position}", "group": "historical_inherited_labels",
                   "banks": banks, "scenario": "corpus", "expected": row["Label"] == "1",
                   "payload": {"metadata": {"asunto": row["subject"]}, "contenido": row["body"],
                               "security_features": {"attachment_count": int(float(row.get("attachments_count") or 0)),
                                                     "received_hop_count": int(float(row.get("hops_count") or 0))}}}


def flow_contrasts():
    """Fixed development probes for alternate domains and RFC sender names."""
    for bank in BANKS:
        for root in bank["domains"]:
            for formatted in (False, True):
                sender = f"avisos@{root}"
                if formatted:
                    sender = f"{bank['name']} <{sender}>"
                yield {"id": f"flow-{bank['id']}-{root}-{'display' if formatted else 'plain'}",
                       "group": "synthetic_flow", "banks": [bank["name"]],
                       "scenario": "authenticated_transfer_notice", "expected": False,
                       "payload": {"metadata": {"asunto": f"{bank['name']} - Transferencia acreditada",
                                                 "remitente_email": sender},
                                   "contenido": f"Se acreditó una transferencia en su cuenta. Para ver el detalle ingrese a https://{root} desde el canal habitual.",
                                   "security_features": {"has_headers": True, "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass"}}}


def metrics(rows):
    scored = [r for r in rows if r["http_status"] == 200]
    return calculate_metrics(["phishing" if r["expected"] else "legitimate" for r in scored],
                             ["phishing" if r["is_phishing"] else "legitimate" for r in scored],
                             [r["risk_score"] for r in scored])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-flow-contrasts", action="store_true")
    parser.add_argument("--model", type=Path, help="Explicit separate artifact to probe")
    args = parser.parse_args()
    import main as api
    from fastapi.testclient import TestClient
    from services import analyzer, slm_client
    if args.model:
        analyzer._load_model(args.model)
    if analyzer.calibrated_model is None:
        raise RuntimeError("The real classifier is unavailable")
    cases = [*synthetic_cases(), *historical_cases(args.dataset)]
    if args.include_flow_contrasts:
        cases.extend(flow_contrasts())
    rows = []
    logging.getLogger("services.slm_client").setLevel(logging.CRITICAL)
    logging.getLogger("services.slm_explanation").setLevel(logging.CRITICAL)
    # This changes only explanation generation, never the classifier or rules.
    with patch.object(slm_client, "MODEL_PATH", "__bank_probe_offline__.gguf"), TestClient(api.app) as client:
        for index, case in enumerate(cases, 1):
            start = time.perf_counter()
            response = client.post("/api/v1/analyze", headers={api.API_KEY_NAME: api.API_KEY}, json=case["payload"])
            result = response.json()
            row = {key: case[key] for key in ("id", "group", "banks", "scenario", "expected")}
            row.update(http_status=response.status_code, elapsed_ms=round((time.perf_counter()-start)*1000, 2))
            if response.status_code == 200:
                row.update({key: result.get(key) for key in ("is_phishing", "risk_score", "raw_model_score", "intent", "decision_source", "bank_context", "content_signals", "explanation_source")})
                row["correct"] = row["is_phishing"] == row["expected"]
            else:
                row["correct"] = False
            if case["group"].startswith("synthetic"):
                row["synthetic_email"] = case["payload"]
            rows.append(row)
            if index % 20 == 0 or index == len(cases):
                print(f"HTTP probes {index}/{len(cases)}", flush=True)
    groups = {name: metrics([r for r in rows if r["group"] == name]) for name in sorted({r["group"] for r in rows})}
    by_bank = {name: {group: metrics([r for r in rows if name in r["banks"] and r["group"] == group]) for group in groups}
               for name in sorted({b for r in rows for b in r["banks"]})}
    report = {"method": "Local FastAPI TestClient, real model and rules, offline SLM fallback; no messages sent",
              "dataset_sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
              "model_sha256": hashlib.sha256(analyzer.LOADED_MODEL_PATH.read_bytes()).hexdigest(),
              "model_path": str(analyzer.LOADED_MODEL_PATH),
              "pipeline_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                                  ("services/analyzer.py", "services/content_rules.py", "services/bank_identity.py")},
              "runtime_versions": {key: importlib.metadata.version(key) for key in ("xgboost", "scikit-learn", "spacy")},
              "groups": groups, "by_bank": by_bank, "http_errors": sum(r["http_status"] != 200 for r in rows),
              "rows": rows,
              "limitations": ["Synthetic bank mail is authored diagnostics, not production accuracy.",
                              "Corpus labels and authenticity are inherited, not individually verified.",
                              "Historical CSV has no sender/header evidence; none was invented.",
                              "Training overlap is unknown; these are not independent holdout estimates.",
                              "SLM generation and a real Outlook session were not tested."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.with_suffix(".json").write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    lines = ["# Prueba de correos bancarios por HTTP", "", report["method"], "",
             "Resultados contra escenarios sintéticos y etiquetas heredadas; no son precisión productiva.", "",
             "| Conjunto | Casos | Aciertos | Falsas alarmas | Ataques omitidos |", "|---|---:|---:|---:|---:|"]
    for name, value in groups.items():
        cm = value["confusion_matrix"]
        lines.append(f"| {name} | {value['count']} | {cm['true_positive']+cm['true_negative']} | {cm['false_positive']} | {cm['false_negative']} |")
    lines += ["", "## Dataset por banco mencionado", "",
              "Un mensaje puede mencionar varios bancos; las filas de esta tabla se solapan.", "",
              "| Banco | Casos | Aciertos | Falsas alarmas | Ataques omitidos |", "|---|---:|---:|---:|---:|"]
    for name, bank_groups in by_bank.items():
        value = bank_groups["historical_inherited_labels"]
        cm = value["confusion_matrix"]
        if value["count"]:
            lines.append(f"| {name} | {value['count']} | {cm['true_positive']+cm['true_negative']} | {cm['false_positive']} | {cm['false_negative']} |")
    lines += ["", "## Fallos observados", "", "| ID | Conjunto | Bancos | Esperado | Obtenido | Score |", "|---|---|---|---|---|---:|"]
    for row in rows:
        if not row["correct"]:
            lines.append(f"| {row['id']} | {row['group']} | {', '.join(row['banks'])} | {'phishing' if row['expected'] else 'legítimo'} | {'phishing' if row.get('is_phishing') else 'legítimo/error HTTP'} | {row.get('risk_score',0):.4f} |")
    lines += ["", "## Límites", ""] + [f"- {item}" for item in report["limitations"]]
    args.output.with_suffix(".md").write_text("\n".join(lines)+"\n", encoding="utf-8")
    print(json.dumps({"groups": groups, "http_errors": report["http_errors"]}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
