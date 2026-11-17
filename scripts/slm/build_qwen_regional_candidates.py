"""Sample Argentine-brand mail for manual Qwen explanation review."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from schemas import EmailPayloadSchema  # noqa: E402
from services.hybrid_classifier import _load  # noqa: E402
from services.slm_explanation import build_analyzer_evidence, build_explanation_context, build_safe_fallback, validate_slm_output  # noqa: E402

SOURCE = ROOT.parent / "Clasificador_PFI" / "SpaPhish_Master_Final_v5.csv"
MODEL = ROOT / "artifacts/hybrid/multilingual-candidate-v3-curated"
OUTPUT = ROOT / "artifacts/slm/regional_review_candidates.jsonl"
TERMS = ("mercadopago", "mercado pago", "mercado libre", "arca", "afip", "banco", "galicia", "santander", "bbva")


def main() -> None:
    csv.field_size_limit(10_000_000)
    with SOURCE.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        rows = [(line, row) for line, row in enumerate(csv.DictReader(handle), 2)
                if any(term in ((row.get("subject") or "") + " " + (row.get("body") or "")).lower() for term in TERMS)]
    rows.sort(key=lambda entry: hashlib.sha256(f"{SOURCE.name}:{entry[0]}".encode()).digest())
    classifier = _load(str(MODEL.resolve()))
    counts: Counter[str] = Counter()
    accepted = {"phishing": 0, "legitimate": 0}
    seen: set[str] = set()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as destination:
        for line, row in rows:
            label = "phishing" if str(row.get("Label", "")).strip() == "1" else "legitimate"
            if accepted[label] >= 60:
                continue
            subject, body = row.get("subject") or "", row.get("body") or ""
            fingerprint = hashlib.sha256((subject + "\n" + body).strip().lower().encode()).hexdigest()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            counts["evaluated"] += 1
            payload = EmailPayloadSchema.model_validate({"metadata": {"asunto": subject}, "contenido": body})
            result = classifier.analyze(payload, quick=True)
            if result.is_phishing != (label == "phishing"):
                counts["label_mismatch"] += 1
                continue
            evidence = build_analyzer_evidence({}, result.security_adjustments, is_phishing=result.is_phishing, content_signals=result.content_signals)
            context = build_explanation_context(is_phishing=result.is_phishing, risk_score=result.risk_score, intent=result.intent or "comunicacion_operativa", evidence=evidence)
            explanation = build_safe_fallback(context)
            validate_slm_output(explanation.model_dump_json(), context)
            record = {
                "case_id": f"SpaPhish_Master_Final_v5:row-{line}",
                "source_id": f"SpaPhish_Master_Final_v5:row-{line}",
                "reviewed": False,
                "source_dataset": SOURCE.name,
                "source_label": label,
                "subject_for_review": subject,
                "body_for_review": body,
                "context": context.model_dump(mode="json"),
                "explanation": explanation.model_dump(mode="json"),
            }
            destination.write(json.dumps(record, ensure_ascii=False) + "\n")
            accepted[label] += 1
            counts[label] += 1
            if context.evidence[0].evidence_id == "evidence.insufficient":
                counts["insufficient_evidence"] += 1
            if all(value >= 60 for value in accepted.values()):
                break
    report = {"source": str(SOURCE), "output": str(OUTPUT), "counts": dict(counts), "reviewed": False}
    OUTPUT.with_suffix(".audit.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
