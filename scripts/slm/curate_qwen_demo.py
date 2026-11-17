"""Select inspected, synthetic repository cases for a Colab pipeline smoke run.

This small set is for testing SFT execution only. It is not an independent
performance benchmark or representative Argentine deployment corpus.
"""

from __future__ import annotations

import json
import hashlib
from collections import Counter
from pathlib import Path

from prepare_qwen_sft import prepare
from services.slm_explanation import SLMExplanationContext, validate_slm_output

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "artifacts/slm/review_candidates.jsonl"
OUTPUT = ROOT / "artifacts/slm/colab_demo_reviewed.jsonl"

# Inspected in source JSONL: direct credential requests, payment redirection,
# device-code/MFA coercion, and benign notices or security guidance. Exclude
# ambiguous URL/CVV/delivery examples and classifier-label disagreements.
PHISHING_IDS = {
    "phisharg-eval-0003", "challenge-010", "challenge-011", "challenge-014", "challenge-015",
    "contrast-credential_theft-01", "contrast-credential_theft-02", "contrast-credential_theft-03",
    "contrast-credential_theft-04", "contrast-credential_theft-05", "contrast-credential_theft-06",
    "contrast-credential_theft-07", "contrast-credential_theft-08", "contrast-credential_theft-09",
    "contrast-fake_invoice-01", "contrast-fake_invoice-02", "contrast-fake_invoice-03",
    "contrast-fake_invoice-04", "contrast-v3-02", "contrast-v3-04", "contrast-v3-06",
    "contrast-v3-08", "contrast-v3-10", "contrast-v3-12", "contrast-v3-14", "contrast-v3-16",
}
LEGITIMATE_IDS = {
    "phisharg-eval-0001", "phisharg-eval-0004", "phisharg-eval-0006", "challenge-001",
    "challenge-003", "challenge-005", "challenge-006", "challenge-007", "challenge-008",
    "contrast-other_legitimate-01", "contrast-other_legitimate-02", "contrast-other_legitimate-03",
    "contrast-other_legitimate-04", "contrast-other_legitimate-13", "contrast-other_legitimate-16",
    "contrast-other_legitimate-17", "contrast-v3-01", "contrast-v3-03", "contrast-v3-05",
    "contrast-v3-07", "contrast-v3-09", "contrast-v3-11", "contrast-v3-15",
    "contrast-v3-17", "contrast-v3-21", "contrast-v3-23",
}


def main() -> None:
    records = []
    seen = set()
    seen_contexts = set()
    for line in SOURCE.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        short_id = record["case_id"].split(":", 1)[1]
        expected = "phishing" if short_id in PHISHING_IDS else "legitimate" if short_id in LEGITIMATE_IDS else None
        if expected is None:
            continue
        if record["source_label"] != expected or record["context"]["is_phishing"] != (expected == "phishing"):
            raise ValueError(f"Verdict disagreement in {record['case_id']}")
        context = SLMExplanationContext.model_validate(record["context"])
        context_key = json.dumps(record["context"], ensure_ascii=False, sort_keys=True)
        if context_key in seen_contexts:
            seen.add(short_id)
            continue
        validate_slm_output(json.dumps(record["explanation"], ensure_ascii=False), context)
        if expected == "phishing" and context.evidence[0].evidence_id == "evidence.insufficient":
            raise ValueError(f"Missing phishing evidence in {record['case_id']}")
        record["reviewed"] = True
        record["source_id"] = "mail-body-sha256:" + hashlib.sha256(record["body_for_review"].strip().casefold().encode()).hexdigest()
        record["review_scope"] = "synthetic_repository_demo_inspected_against_source_text_or_fixture_headers"
        records.append(record)
        seen.add(short_id)
        seen_contexts.add(context_key)
    missing = (PHISHING_IDS | LEGITIMATE_IDS) - seen
    if missing:
        raise ValueError(f"Expected cases not found: {sorted(missing)}")
    OUTPUT.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in records), encoding="utf-8")
    result = prepare(OUTPUT, ROOT / "artifacts/slm/colab_demo_split", 25)
    labels = Counter("phishing" if row["context"]["is_phishing"] else "legitimate" for row in records)
    print(json.dumps({"output": str(OUTPUT), "labels": dict(labels), "split": result}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
