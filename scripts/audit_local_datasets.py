"""Inventory local CSV/ZIP email corpora without exporting message contents.

Labels are reported verbatim: spam labels must not be assumed to mean phishing.
This command never extracts archives, changes labels, or trains a model.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
from pathlib import Path
import zipfile


def fingerprint(text):
    normalized = " ".join(text.casefold().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def audit_stream(stream, name):
    reader = csv.DictReader(stream)
    labels, sources, partitions = Counter(), Counter(), Counter()
    messages, bodies = defaultdict(list), defaultdict(list)
    group_partitions = defaultdict(set)
    empty = long = malformed = missing_campaign = 0
    for index, row in enumerate(reader, 1):
        malformed += None in row or any(value is None for value in row.values())
        label = str(row.get("Label", row.get("label", row.get("class", "missing"))))
        subject = row.get("subject", "") or ""
        body = row.get("body", row.get("text_combined", row.get("text", row.get("message", "")))) or ""
        labels[label] += 1
        sources[row.get("source", "missing")] += 1
        partition = row.get("particion", row.get("partition", row.get("split", "missing")))
        partitions[partition] += 1
        missing_campaign += not bool(row.get("campaign_id"))
        empty += not bool((subject + body).strip())
        long += len(subject + " " + body) > 50000
        if (subject + body).strip():
            messages[fingerprint(subject + "\n" + body)].append((index, label, partition))
        if body.strip():
            bodies[fingerprint(body)].append((index, label, partition))
        if row.get("group_id") and partition != "missing":
            group_partitions[row["group_id"]].add(partition)
    conflicts = [items for items in messages.values() if len({i[1] for i in items}) > 1]
    body_conflicts = [items for items in bodies.values() if len({i[1] for i in items}) > 1]
    summary = {
        "path": name, "rows": sum(labels.values()), "columns": reader.fieldnames,
        "labels_verbatim": dict(labels), "sources": dict(sources), "partitions": dict(partitions),
        "malformed_rows": malformed, "empty_messages": empty,
        "over_50000_characters": long, "missing_campaign_id": missing_campaign,
        "unique_messages": len(messages),
        "duplicate_message_rows": sum(len(v) - 1 for v in messages.values()),
        "conflicting_message_groups": len(conflicts),
        "conflicting_message_rows": sum(map(len, conflicts)),
        "duplicate_body_rows": sum(len(v) - 1 for v in bodies.values()),
        "conflicting_body_groups": len(body_conflicts),
        "conflicting_body_examples": [v[:10] for v in body_conflicts[:10]],
        "message_groups_across_partitions": sum(len({r[2] for r in v} - {"missing"}) > 1 for v in messages.values()),
        "body_groups_across_partitions": sum(len({r[2] for r in v} - {"missing"}) > 1 for v in bodies.values()),
        "declared_groups_across_partitions": sum(len(v) > 1 for v in group_partitions.values()),
    }
    return summary, {key: {v[1] for v in values} for key, values in messages.items()}


def audit_paths(paths):
    csv.field_size_limit(20_000_000)
    summaries, fingerprints = [], {}
    for path in paths:
        if path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as archive:
                for member in archive.infolist():
                    if member.filename.lower().endswith(".csv") and not member.is_dir():
                        name = f"{path}!{member.filename}"
                        with archive.open(member) as raw, io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as stream:
                            summary, keys = audit_stream(stream, name)
                        summaries.append(summary)
                        fingerprints[name] = keys
        else:
            with path.open(encoding="utf-8-sig", newline="") as stream:
                summary, keys = audit_stream(stream, str(path))
            summaries.append(summary)
            fingerprints[str(path)] = keys
    overlaps = []
    names = list(fingerprints)
    for position, left in enumerate(names):
        for right in names[position + 1:]:
            common = fingerprints[left].keys() & fingerprints[right].keys()
            if common:
                overlaps.append({"left": left, "right": right, "shared_normalized_messages": len(common),
                                 "shared_messages_with_different_labels": sum(fingerprints[left][k] != fingerprints[right][k] for k in common)})
    return {"normalization": "casefold and whitespace; subject plus body; no semantic deduplication",
            "warnings": ["Historical sources and labels do not establish contemporary real-mail accuracy.",
                         "Verbatim labels from different sources may have different meanings.",
                         "Only exact normalized overlap is measured; paraphrases and campaign leakage can remain."],
            "datasets": summaries, "overlaps": overlaps}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit_paths(args.paths)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for item in report["datasets"]:
        print(json.dumps({key: item[key] for key in ("path", "rows", "labels_verbatim", "duplicate_message_rows", "conflicting_message_groups", "conflicting_body_groups", "body_groups_across_partitions")}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
