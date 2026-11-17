"""Prepare reviewed Hybrid explanation pairs for Qwen SFT.

Input JSONL records require: case_id, source_id, reviewed=true, context and
explanation. A reviewer must check the classifier output and observed signals
against the original message. This script checks the server contract, not truth.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from services.slm_explanation import (  # noqa: E402
    SLMExplanationContext,
    SLMExplanationValidationError,
    build_slm_prompt_messages,
    validate_slm_output,
)


def prepare(source: Path, destination: Path, eval_percent: int) -> dict:
    if not 1 <= eval_percent <= 50:
        raise ValueError("eval_percent must be between 1 and 50")
    destination.mkdir(parents=True, exist_ok=True)
    counts: Counter[str] = Counter()
    seen_cases: set[str] = set()
    seen_contexts: set[str] = set()
    rows = {"train": [], "eval": []}
    for line_number, line in enumerate(source.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        counts["total"] += 1
        try:
            record = json.loads(line)
            if record.get("reviewed") is not True:
                raise ValueError("not_reviewed")
            case_id = record["case_id"]
            source_id = record["source_id"]
            if not isinstance(case_id, str) or not case_id.strip():
                raise ValueError("missing_case_id")
            if not isinstance(source_id, str) or not source_id.strip():
                raise ValueError("missing_source_id")
            if case_id in seen_cases:
                raise ValueError("duplicate_case_id")
            context = SLMExplanationContext.model_validate(record["context"])
            explanation = record["explanation"]
            validate_slm_output(json.dumps(explanation, ensure_ascii=False), context)
            context_key = context.model_dump_json()
            if context_key in seen_contexts:
                raise ValueError("duplicate_context")
            messages = build_slm_prompt_messages(context)
            messages.append({"role": "assistant", "content": json.dumps(explanation, ensure_ascii=False, sort_keys=True)})
            # Group by original source so variants of one email never cross splits.
            partition = "eval" if int(hashlib.sha256(source_id.encode()).hexdigest(), 16) % 100 < eval_percent else "train"
            rows[partition].append({"messages": messages})
            seen_cases.add(case_id)
            seen_contexts.add(context_key)
            counts["accepted"] += 1
        except (KeyError, TypeError, ValueError, SLMExplanationValidationError) as exc:
            category = exc.category if isinstance(exc, SLMExplanationValidationError) else str(exc).split("\n", 1)[0][:80]
            counts[f"rejected:{category}"] += 1
            # Avoid logging record contents, which may include private mail data.
            print(f"line {line_number}: rejected ({category})", file=sys.stderr)
    for partition in ("train", "eval"):
        path = destination / f"{partition}.jsonl"
        path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows[partition]), encoding="utf-8")
    report = {"source": str(source), "counts": dict(counts), "train": len(rows["train"]), "eval": len(rows["eval"]), "split_by": "source_id_sha256"}
    (destination / "audit.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--eval-percent", type=int, default=20)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.destination, args.eval_percent), indent=2, ensure_ascii=False))
