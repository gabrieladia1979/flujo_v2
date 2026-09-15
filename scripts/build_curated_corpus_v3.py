"""Construcción del corpus curado v3 con sanitización de ruido e inyección contrastiva.

1. Toma el corpus multilingüe base (multilingual-v1.csv).
2. Filtra los casos con etiquetas dudosas/ruidosas identificadas en label_curation_audit.json.
3. Inyecta los pares contrastivos curados de data/hybrid_contrastive_curated_v3.jsonl.
4. Preserva el agrupamiento estricto por plantilla para garantizar 0 data leakage.
5. Genera artifacts/hybrid/corpus-v3/training.csv y splits.json listos para Colab GPU.
"""

import csv
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.hybrid_data import group_key, grouped_split

BASE_CORPUS = ROOT / "artifacts" / "hybrid" / "corpus" / "multilingual-v1.csv"
AUDIT_JSON = ROOT / "reports" / "label_curation_audit.json"
CONTRASTIVE_JSONL = ROOT / "data" / "hybrid_contrastive_curated_v3.jsonl"
OUTPUT_DIR = ROOT / "artifacts" / "hybrid" / "corpus-v3"


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    csv.field_size_limit(10_000_000)

    # 1. Cargar IDs ruidosos a excluir o corregir
    excluded_ids = set()
    if AUDIT_JSON.exists():
        audit = json.loads(AUDIT_JSON.read_text(encoding="utf-8"))
        for item in audit.get("detalle", {}).get("etiqueta_dudosa_falso_positivo", []):
            excluded_ids.add(item["id"])
        # Casos con inconsistencia conocida en texto operativo
        for item in audit.get("detalle", {}).get("errores_reales_modelo", []):
            if item["id"] in {"row-126", "row-190"}: # Mantenimiento y código de vestimenta
                excluded_ids.add(item["id"])

    print(f"Registros ruidosos a excluir del corpus base: {len(excluded_ids)}")

    # 2. Leer corpus base filtrando ruido
    clean_rows = []
    with BASE_CORPUS.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for line_num, row in enumerate(reader, 2):
            row_id = f"row-{line_num}"
            if row_id in excluded_ids:
                continue
            subj = row.get("subject") or ""
            body = row.get("body") or ""
            if not subj and not body:
                continue
            clean_rows.append({
                "subject": subj,
                "body": body,
                "Label": str(row.get("Label", 0)),
                "attachments_count": row.get("attachments_count") or "0",
                "hops_count": row.get("hops_count") or "0",
                "source": row.get("source") or "base",
                "language": row.get("language") or "es",
                "campaign_id": row.get("campaign_id") or ""
            })

    print(f"Registros base limpios retenidos: {len(clean_rows)}")

    # 3. Inyectar pares contrastivos curados
    contrastive_count = 0
    if CONTRASTIVE_JSONL.exists():
        for line in CONTRASTIVE_JSONL.read_text(encoding="utf-8").strip().split("\n"):
            if not line:
                continue
            item = json.loads(line)
            clean_rows.append({
                "subject": item.get("subject", ""),
                "body": item.get("body", ""),
                "Label": "1" if item.get("label") == "phishing" else "0",
                "attachments_count": "0",
                "hops_count": "0",
                "source": "curated_contrastive_v3",
                "language": "en" if "-en" in item.get("campaign_id", "") else "es",
                "campaign_id": item.get("campaign_id", "")
            })
            contrastive_count += 1

    print(f"Pares contrastivos inyectados: {contrastive_count}")
    print(f"Total de registros en corpus curado v3: {len(clean_rows)}")

    # 4. Guardar training.csv
    output_csv = OUTPUT_DIR / "training.csv"
    fields = ["subject", "body", "Label", "attachments_count", "hops_count", "source", "language", "campaign_id"]
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in clean_rows:
            writer.writerow(r)

    # 5. Generar particiones agrupadas por plantilla para evitar fuga de información
    row_objects = []
    for idx, r in enumerate(clean_rows):
        g = group_key(r["subject"], r["body"])
        row_objects.append({
            "id": f"row-{idx+2}",
            "label": int(r["Label"]),
            "group": g
        })

    previous_splits_path = ROOT / "artifacts" / "hybrid" / "multilingual-candidate-a100" / "splits.json"
    previous = json.loads(previous_splits_path.read_text(encoding="utf-8")) if previous_splits_path.exists() else None
    splits = grouped_split(row_objects, seed=42, previous=previous)
    output_splits = {
        name: [dict(id=row_objects[i]["id"], group=row_objects[i]["group"]) for i in indices]
        for name, indices in splits.items()
    }

    (OUTPUT_DIR / "splits.json").write_text(json.dumps(output_splits, indent=2), encoding="utf-8")

    # Auditoría del corpus generado
    audit_summary = {
        "dataset_name": "multilingual-v3-curated.csv",
        "sha256": hashlib.sha256(output_csv.read_bytes()).hexdigest(),
        "total_rows": len(clean_rows),
        "excluded_noisy_rows": len(excluded_ids),
        "injected_contrastive_rows": contrastive_count,
        "splits": {k: len(v) for k, v in output_splits.items()}
    }
    (OUTPUT_DIR / "manifest.json").write_text(json.dumps(audit_summary, indent=2), encoding="utf-8")

    print("\n" + "=" * 60)
    print("CORPUS CURADO V3 GENERADO CON ÉXITO")
    print("=" * 60)
    print(f"Archivo CSV:   {output_csv}")
    print(f"Particiones:   {OUTPUT_DIR / 'splits.json'}")
    print(f"Total Filas:   {audit_summary['total_rows']}")
    print(f"Train:         {audit_summary['splits']['train']}")
    print(f"Validation:    {audit_summary['splits']['validation']}")
    print(f"Test:          {audit_summary['splits']['test']}")
    print(f"SHA256:        {audit_summary['sha256']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
