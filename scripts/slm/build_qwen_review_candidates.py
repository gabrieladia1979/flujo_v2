"""Build review candidates from labelled local mail and the current Hybrid model.

Never marks records reviewed automatically. The operator must inspect source mail,
classifier verdict, evidence, and reference explanation before training.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from schemas import EmailPayloadSchema  # noqa: E402
from services.hybrid_classifier import _load  # noqa: E402
from services.slm_explanation import (  # noqa: E402
    build_analyzer_evidence,
    build_explanation_context,
    build_safe_fallback,
    validate_slm_output,
)

SOURCES = (
    ROOT / "data" / "classifier_diagnostic_v3.jsonl",
    ROOT / "data" / "hybrid_contrastive_curated_v3.jsonl",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, default=ROOT / "artifacts/hybrid/multilingual-candidate-v3-curated")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/slm/review_candidates.jsonl")
    args = parser.parse_args()
    classifier = _load(str(args.model_dir.resolve()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    counts: Counter[str] = Counter()
    mismatches = []
    with args.output.open("w", encoding="utf-8") as destination:
        for source in SOURCES:
            for line_number, line in enumerate(source.read_text(encoding="utf-8-sig").splitlines(), 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                counts["source_total"] += 1
                payload = EmailPayloadSchema.model_validate({
                    "metadata": {"asunto": row.get("subject", "")},
                    "contenido": row.get("body", ""),
                    "security_features": row.get("security_features") or {},
                })
                result = classifier.analyze(payload, quick=True)
                label = row["label"] == "phishing"
                if result.is_phishing != label:
                    counts["label_mismatch"] += 1
                    mismatches.append({"source": source.name, "case_id": row.get("id"), "label": row["label"], "hybrid_is_phishing": result.is_phishing})
                    continue
                evidence = build_analyzer_evidence(
                    {}, result.security_adjustments, is_phishing=result.is_phishing,
                    content_signals=result.content_signals,
                )
                context = build_explanation_context(
                    is_phishing=result.is_phishing,
                    risk_score=result.risk_score,
                    intent=result.intent or "comunicacion_operativa",
                    evidence=evidence,
                )
                explanation = build_safe_fallback(context)
                validate_slm_output(explanation.model_dump_json(), context)
                candidate = {
                    "case_id": f"{source.stem}:{row.get('id', line_number)}",
                    "source_id": f"{source.stem}:{row.get('campaign_id') or row.get('id', line_number)}",
                    "reviewed": False,
                    "source_dataset": source.name,
                    "source_label": row["label"],
                    "subject_for_review": row.get("subject", ""),
                    "body_for_review": row.get("body", ""),
                    "context": context.model_dump(mode="json"),
                    "explanation": explanation.model_dump(mode="json"),
                }
                destination.write(json.dumps(candidate, ensure_ascii=False) + "\n")
                counts["candidate"] += 1
                counts["phishing" if label else "legitimate"] += 1
    report = {"counts": dict(counts), "mismatches": mismatches, "output": str(args.output)}
    args.output.with_suffix(".audit.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"counts": report["counts"], "output": report["output"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
