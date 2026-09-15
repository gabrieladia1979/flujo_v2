"""Auditoría y curaduría sistemática de etiquetas dudosas en el corpus híbrido.

Inspecciona los 55 errores documentados del modelo A100 y analiza el texto completo
(asunto y cuerpo) para clasificar los casos en:
1. errores_reales_modelo: Casos difíciles legítimos donde el modelo debe aprender mejor.
2. etiqueta_dudosa_falso_positivo: Textos operativos genuinos marcados como phishing en datasets legacy.
3. etiqueta_dudosa_falso_negativo: Ataques evidentes marcados como ham en datasets legacy.
4. oportunidad_contrastiva: Avisos con lenguaje de seguridad defensivo penalizados por palabras clave.
"""

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "artifacts" / "hybrid" / "corpus" / "multilingual-v1.csv"
AUDIT_V2_PATH = ROOT / "reports" / "hybrid_a100_audit_v2.json"
OUTPUT_REPORT = ROOT / "reports" / "label_curation_audit.json"
OUTPUT_MD = ROOT / "reports" / "label_curation_audit.md"


def main():
    if not DATASET_PATH.exists() or not AUDIT_V2_PATH.exists():
        print(f"Error: No se encontró {DATASET_PATH} o {AUDIT_V2_PATH}")
        return

    audit_data = json.loads(AUDIT_V2_PATH.read_text(encoding="utf-8"))
    errors_list = audit_data.get("errors", [])
    error_ids = {e["id"]: e for e in errors_list}

    # Leer el corpus completo para extraer texto de los casos con error
    csv.field_size_limit(10_000_000)
    dataset_rows = {}
    with DATASET_PATH.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for line_num, row in enumerate(reader, 2):
            row_id = f"row-{line_num}"
            if row_id in error_ids:
                dataset_rows[row_id] = {
                    "id": row_id,
                    "subject": row.get("subject", ""),
                    "body": row.get("body", ""),
                    "label": int(row.get("Label", 0)),
                    "source": row.get("source", ""),
                    "language": row.get("language", ""),
                }

    categorized = {
        "oportunidad_contrastiva": [],
        "etiqueta_dudosa_falso_positivo": [],
        "etiqueta_dudosa_falso_negativo": [],
        "errores_reales_modelo": [],
    }

    # Palabras clave de consejo de seguridad / negación
    defensive_markers = [
        "no nos envíe", "no comparta", "nunca le pediremos", "desestime",
        "no comparta su código", "ignore este aviso", "report it",
        "will never ask", "do not share", "do not reply", "portal habitual",
        "rechace la notificación"
    ]

    # Palabras de ataque explícito
    aggressive_phish_markers = [
        "actualice su cbu", "ingrese su clave fiscal", "evite el bloqueo inmediato",
        "cuenta suspendida haga clic", "enviar contraseña y sms",
        "transfer now to new account", "verify your account immediately"
    ]

    for row_id, item in dataset_rows.items():
        err_info = error_ids[row_id]
        subj = (item["subject"] or "").lower()
        body = (item["body"] or "").lower()
        full_text = f"{subj} {body}"
        label = item["label"]
        score = err_info["score"]

        is_fp = (label == 0 and score >= 0.85937)
        is_fn = (label == 1 and score < 0.85937)

        entry = {
            "id": row_id,
            "tipo_error": "Falso Positivo" if is_fp else "Falso Negativo",
            "source": item["source"],
            "score": round(score, 4),
            "label_original": label,
            "subject": item["subject"][:100],
            "extracto": item["body"][:200].replace("\n", " "),
        }

        if any(m in full_text for m in defensive_markers):
            entry["motivo"] = "Contiene advertencia o lenguaje defensivo ('No comparta', 'Desestime', etc.)"
            categorized["oportunidad_contrastiva"].append(entry)
        elif is_fp and len(full_text.strip()) < 120 and err_info["url_count"] == 0:
            entry["motivo"] = "Texto muy corto sin enlaces ni pedidos sensibles; el modelo sobre-reaccionó a palabras aisladas"
            categorized["etiqueta_dudosa_falso_positivo"].append(entry)
        elif is_fn and any(m in full_text for m in aggressive_phish_markers):
            entry["motivo"] = "Ataque con patrones clásicos no detectado por vocabulario o evasión"
            categorized["etiqueta_dudosa_falso_negativo"].append(entry)
        else:
            entry["motivo"] = "Caso desafiante legítimo para el entrenamiento regular"
            categorized["errores_reales_modelo"].append(entry)

    summary = {
        "total_errores_analizados": len(dataset_rows),
        "conteo_por_categoria": {k: len(v) for k, v in categorized.items()},
        "detalle": categorized
    }

    OUTPUT_REPORT.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    
    # Generar reporte Markdown
    md_lines = [
        "# Auditoría de Calidad de Etiquetas y Errores (A100)",
        "",
        f"- **Total de casos de error analizados en test:** {len(dataset_rows)}",
        f"- **Oportunidades contrastivas (Defensivo vs Ataque):** {len(categorized['oportunidad_contrastiva'])}",
        f"- **Sospecha de etiqueta dudosa (Falsos Positivos / Textos cortos):** {len(categorized['etiqueta_dudosa_falso_positivo'])}",
        f"- **Ataques no detectados (Falsos Negativos):** {len(categorized['etiqueta_dudosa_falso_negativo'])}",
        f"- **Errores de generalización del modelo (para reentrenar):** {len(categorized['errores_reales_modelo'])}",
        "",
        "## Casos destacados para Curaduría",
        "",
        "| ID | Tipo | Fuente | Score | Asunto | Motivo |",
        "|---|---|---|---:|---|---|",
    ]
    for cat_name, items in categorized.items():
        for it in items[:5]: # Top 5 por categoría
            subj_clean = it['subject'].replace('|', '/')
            md_lines.append(f"| {it['id']} | {it['tipo_error']} | {it['source']} | {it['score']} | {subj_clean} | {it['motivo']} |")

    OUTPUT_MD.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"Auditoría completada. Reportes guardados en:\n- {OUTPUT_REPORT}\n- {OUTPUT_MD}")
    print(f"Resumen: {json.dumps(summary['conteo_por_categoria'], indent=2)}")


if __name__ == "__main__":
    main()
