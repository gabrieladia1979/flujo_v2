"""Validation and manifest helpers for classifier evaluation corpora."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any, Iterable


PHISHING_CATEGORIES = {
    "credential_theft",
    "tax_impersonation",
    "bank_impersonation",
    "marketplace_impersonation",
    "fake_prize",
    "fake_invoice",
    "fake_delivery",
    "malware",
    "other_phishing",
}

LEGITIMATE_CATEGORIES = {
    "internal_communication",
    "legitimate_invoice",
    "bank_notification",
    "marketplace_notification",
    "newsletter",
    "password_recovery",
    "technical_email",
    "forwarded_email",
    "other_legitimate",
}

ALLOWED_LABELS = {"phishing", "legitimate"}
ALLOWED_FIELDS = {
    "id",
    "subject",
    "body",
    "label",
    "category",
    "campaign_id",
    "security_features",
    "source",
}
REQUIRED_FIELDS = ALLOWED_FIELDS
ALLOWED_SECURITY_FIELDS = {
    "spf_result", "dkim_result", "dmarc_result", "compauth_result",
    "return_path", "reply_to", "from_return_path_match", "from_reply_to_match",
    "sender_vs_from_match", "scl", "threat_category", "spam_filtering_verdict",
    "auth_as", "bcl", "originating_ip", "originating_country", "x_mailer",
    "received_hop_count", "is_trusted_domain", "attachment_count",
    "attachment_types", "has_executable_attachment", "to_count", "cc_count",
    "internet_message_id", "has_headers",
}
_SECURITY_STRING_FIELDS = {
    "spf_result", "dkim_result", "dmarc_result", "compauth_result", "return_path",
    "reply_to", "threat_category", "spam_filtering_verdict", "auth_as",
    "originating_ip", "originating_country", "x_mailer", "internet_message_id",
}
_SECURITY_BOOLEAN_FIELDS = {
    "from_return_path_match", "from_reply_to_match", "sender_vs_from_match",
    "has_executable_attachment", "has_headers",
}
_SECURITY_INTEGER_FIELDS = {
    "scl", "bcl", "received_hop_count", "attachment_count", "to_count", "cc_count",
}

_PII_PATTERNS = {
    "email_address": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "argentine_phone": re.compile(r"(?<!\d)(?:\+?54[\s.-]?)?(?:9[\s.-]?)?\d{2,4}[\s.-]?\d{6,8}(?!\d)"),
    "dni_or_cuit": re.compile(r"(?<!\d)(?:\d{2}-?\d{8}-?\d|\d{7,8})(?!\d)"),
}


class CorpusValidationError(ValueError):
    """Raised when a corpus cannot be evaluated safely."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def dataset_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {line_number}: invalid JSON ({exc.msg})")
                continue
            if not isinstance(value, dict):
                errors.append(f"line {line_number}: record must be an object")
                continue
            records.append(value)
    if errors:
        raise CorpusValidationError("; ".join(errors))
    return records


def _normalized_message(record: dict[str, Any]) -> str:
    subject = " ".join(str(record.get("subject", "")).lower().split())
    body = " ".join(str(record.get("body", "")).lower().split())
    return f"{subject}\n{body}"


def validate_records(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    materialized = list(records)
    errors: list[str] = []
    warnings: list[str] = []
    ids: set[str] = set()
    messages: dict[str, str] = {}
    by_label: Counter[str] = Counter()
    by_category: Counter[str] = Counter()

    for position, record in enumerate(materialized, start=1):
        prefix = f"record {position}"
        missing = sorted(REQUIRED_FIELDS - set(record))
        unknown = sorted(set(record) - ALLOWED_FIELDS)
        if missing:
            errors.append(f"{prefix}: missing fields: {', '.join(missing)}")
        if unknown:
            errors.append(f"{prefix}: unknown fields: {', '.join(unknown)}")

        record_id = record.get("id")
        if not isinstance(record_id, str) or not record_id.strip():
            errors.append(f"{prefix}: id must be a non-empty string")
            record_id = f"#{position}"
        elif record_id in ids:
            errors.append(f"{prefix}: duplicate id: {record_id}")
        else:
            ids.add(record_id)

        subject = record.get("subject")
        body = record.get("body")
        if not isinstance(subject, str) or not isinstance(body, str):
            errors.append(f"{prefix}: subject and body must be strings")
        elif not subject.strip() and not body.strip():
            errors.append(f"{prefix}: subject or body must contain text")
        elif subject.strip() and subject.strip() == body.strip():
            errors.append(f"{prefix}: subject and body must not be identical")

        label = record.get("label")
        category = record.get("category")
        if label not in ALLOWED_LABELS:
            errors.append(f"{prefix}: invalid label: {label!r}")
        else:
            by_label[label] += 1
            expected_categories = PHISHING_CATEGORIES if label == "phishing" else LEGITIMATE_CATEGORIES
            if category not in expected_categories:
                errors.append(f"{prefix}: category {category!r} is inconsistent with label {label!r}")
        if isinstance(category, str):
            by_category[category] += 1

        if not isinstance(record.get("campaign_id"), str) or not record.get("campaign_id", "").strip():
            errors.append(f"{prefix}: campaign_id must be a non-empty string")
        if not isinstance(record.get("security_features"), dict):
            errors.append(f"{prefix}: security_features must be an object")
        else:
            unknown_security = sorted(set(record["security_features"]) - ALLOWED_SECURITY_FIELDS)
            if unknown_security:
                errors.append(f"{prefix}: unknown security fields: {', '.join(unknown_security)}")
            for field, value in record["security_features"].items():
                if field in _SECURITY_STRING_FIELDS and not isinstance(value, str):
                    errors.append(f"{prefix}: security field {field} must be a string")
                elif field in _SECURITY_BOOLEAN_FIELDS and not isinstance(value, bool):
                    errors.append(f"{prefix}: security field {field} must be a boolean")
                elif field in _SECURITY_INTEGER_FIELDS and (not isinstance(value, int) or isinstance(value, bool)):
                    errors.append(f"{prefix}: security field {field} must be an integer")
                elif field == "is_trusted_domain" and value is not None and not isinstance(value, bool):
                    errors.append(f"{prefix}: security field {field} must be a boolean or null")
                elif field == "attachment_types" and value is not None and (
                    not isinstance(value, list) or not all(isinstance(item, str) for item in value)
                ):
                    errors.append(f"{prefix}: security field {field} must be an array of strings or null")
        if not isinstance(record.get("source"), str) or not record.get("source", "").strip():
            errors.append(f"{prefix}: source must be a non-empty string")

        if isinstance(subject, str) and isinstance(body, str):
            fingerprint = hashlib.sha256(_normalized_message(record).encode("utf-8")).hexdigest()
            if fingerprint in messages:
                errors.append(f"{prefix}: exact normalized duplicate of {messages[fingerprint]}")
            else:
                messages[fingerprint] = str(record_id)
            inspected_text = f"{subject}\n{body}"
            for pii_name, pattern in _PII_PATTERNS.items():
                if pattern.search(inspected_text):
                    warnings.append(f"{prefix}: possible {pii_name}; review anonymization")

    used_category_shortfalls = {
        category: max(0, 10 - count)
        for category, count in sorted(by_category.items())
        if count < 10
    }
    phishing_shortfall = max(0, 200 - by_label["phishing"])
    legitimate_shortfall = max(0, 200 - by_label["legitimate"])
    complete = not errors and phishing_shortfall == 0 and legitimate_shortfall == 0 and not used_category_shortfalls

    return {
        "valid": not errors,
        "complete": complete,
        "errors": sorted(set(errors)),
        "warnings": sorted(set(warnings)),
        "counts": {
            "total": len(materialized),
            "by_label": dict(sorted(by_label.items())),
            "by_category": dict(sorted(by_category.items())),
        },
        "shortfalls": {
            "phishing": phishing_shortfall,
            "legitimate": legitimate_shortfall,
            "used_categories": used_category_shortfalls,
        },
    }


def validate_dataset(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records = load_jsonl(path)
    validation = validate_records(records)
    if not validation["valid"]:
        raise CorpusValidationError("; ".join(validation["errors"]))
    return records, validation


def build_manifest(path: Path, validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": "1.0.0",
        "generated_on": date.today().isoformat(),
        "dataset": path.name,
        "sha256": dataset_sha256(path),
        "status": "complete" if validation["complete"] else "incomplete",
        "holdout_status": "unverified",
        "counts": validation["counts"],
        "shortfalls": validation["shortfalls"],
        "warnings": validation["warnings"],
        "provenance": {
            "description": "Authorized, synthetic/anonymized cases already present in repository tests.",
            "source_files": ["test_xgboost_analyzer.py", "test_api.py"],
            "training_overlap": "unknown",
        },
        "notes": [
            "This corpus is intentionally incomplete and is not a verified holdout.",
            "No new messages were fabricated to satisfy minimum sample counts.",
        ],
    }
