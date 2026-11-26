"""Train a separate XGBoost candidate on fixed, disjoint corpus groups.

The already-inspected test partition is a development comparison, not a new
independent production holdout. No weights are replaced or promoted here.
"""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import importlib.metadata
import json
from pathlib import Path
import pickle
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
import xgboost as xgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from schemas import EmailPayloadSchema
from scripts.evaluate_classifier import calculate_metrics
from services.calibrated_xgboost import CalibratedXGBoost


def load_rows(path):
    csv.field_size_limit(20_000_000)
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    owner, ids = {}, set()
    for row in rows:
        if row.get("particion") not in {"train", "validation", "test"} or row.get("Label") not in {"0", "1"}:
            raise ValueError("Corpus needs explicit partition and binary labels")
        if not row.get("group_id") or not row.get("row_id") or row["row_id"] in ids:
            raise ValueError("Corpus needs unique row IDs and nonempty group IDs")
        ids.add(row["row_id"])
        group = row["group_id"]
        previous = owner.setdefault(group, row["particion"])
        if previous != row["particion"]:
            raise ValueError("A corpus group appears in multiple partitions")
    return rows


def choose_threshold(labels, scores, max_fpr):
    choices = []
    for threshold in np.arange(0.5, 0.991, 0.005):
        metrics = calculate_metrics(["phishing" if y else "legitimate" for y in labels],
            ["phishing" if p >= threshold else "legitimate" for p in scores], scores)
        if metrics["false_positive_rate"] <= max_fpr:
            choices.append((metrics["f1_phishing"] or 0, metrics["recall_phishing"] or 0, float(threshold)))
    if not choices:
        raise ValueError("No validation threshold meets the false-positive budget")
    return max(choices)[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--max-fpr", type=float, default=0.02)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output already exists; preserve the previous artifact")
    from services import analyzer
    if analyzer.calibrated_model is None:
        raise RuntimeError("Need the legacy feature/domain configuration loaded")
    rows = load_rows(args.dataset)
    started = time.perf_counter()
    prepared, skipped = [], []
    for position, row in enumerate(rows, 1):
        payload = EmailPayloadSchema(metadata={"asunto": row["subject"]}, contenido=row["body"],
            security_features={"attachment_count": int(float(row.get("attachments_count") or 0)),
                               "received_hop_count": int(float(row.get("hops_count") or 0))})
        try:
            inputs = analyzer.extract_model_inputs(payload)
        except analyzer.ClassifierInputTooLongError:
            skipped.append({"id": row["row_id"], "reason": "visible_text_exceeds_classifier_limit"})
            continue
        prepared.append((row, inputs))
        if position % 250 == 0:
            print(f"Prepared shared features {position}/{len(rows)}", flush=True)
    splits = {name: [i for i, (row, _) in enumerate(prepared) if row["particion"] == name]
              for name in ("train", "validation", "test")}
    for name, indices in splits.items():
        if {prepared[i][0]["Label"] for i in indices} != {"0", "1"}:
            raise ValueError(f"Partition {name} lacks a class")
    text = [inputs["text"] for _, inputs in prepared]
    train = splits["train"]
    # All learned preprocessing is fitted exclusively on train.
    tfidf = TfidfVectorizer(strip_accents="unicode", lowercase=True, ngram_range=(1, 2),
        min_df=2, max_df=0.995, max_features=6000, sublinear_tf=True, dtype=np.float32)
    tfidf.fit([text[i] for i in train])
    scalers = {}
    for name in ("metadata", "slots", "readability"):
        scalers[name] = StandardScaler().fit([prepared[i][1][name] for i in train])
    def matrix(indices):
        values = [prepared[i][1] for i in indices]
        return np.hstack([tfidf.transform([text[i] for i in indices]).toarray(),
                          scalers["metadata"].transform([v["metadata"] for v in values]),
                          scalers["slots"].transform([v["slots"] for v in values]),
                          np.asarray([v["urls"] for v in values]),
                          scalers["readability"].transform([v["readability"] for v in values])]).astype(np.float32)
    labels = np.array([int(row["Label"]) for row, _ in prepared])
    train_matrix, validation_matrix = matrix(train), matrix(splits["validation"])
    dtrain = xgb.DMatrix(train_matrix, label=labels[train])
    dval = xgb.DMatrix(validation_matrix, label=labels[splits["validation"]])
    print(f"Training native XGBoost on {len(train)} rows, {train_matrix.shape[1]} features", flush=True)
    booster = xgb.train({"objective": "binary:logistic", "eval_metric": "logloss", "tree_method": "hist",
                         "max_depth": 5, "min_child_weight": 2, "eta": 0.08, "subsample": 0.85,
                         "colsample_bytree": 0.85, "seed": 42, "nthread": 4},
                        dtrain, num_boost_round=350, evals=[(dval, "validation")],
                        early_stopping_rounds=30, verbose_eval=50)
    booster = booster[:booster.best_iteration + 1]
    margins = booster.predict(dval, output_margin=True).reshape(-1, 1)
    calibration = LogisticRegression(C=1.0, random_state=42).fit(margins, labels[splits["validation"]])
    if calibration.coef_[0, 0] <= 0:
        raise ValueError("Calibration is not monotonic with the native phishing score")
    model = CalibratedXGBoost(booster, calibration)
    validation_scores = model.predict_proba(validation_matrix)[:, 0]
    threshold = choose_threshold(labels[splits["validation"]], validation_scores, args.max_fpr)
    print(f"Validation-selected threshold: {threshold:.4f}", flush=True)
    test_matrix = matrix(splits["test"])
    scores = model.predict_proba(test_matrix)[:, 0]
    evaluation = calculate_metrics(["phishing" if y else "legitimate" for y in labels[splits["test"]]],
        ["phishing" if p >= threshold else "legitimate" for p in scores], scores)
    provenance = {"dataset_sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
                  "training_code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "preprocessing_fit_partition": "train", "early_stopping_calibration_threshold_partition": "validation",
                  "class_semantics": {"native_booster_1": "phishing", "public_column_0": "phishing"},
                  "runtime_versions": {name: importlib.metadata.version(name) for name in ("xgboost", "scikit-learn", "spacy", "numpy")}}
    artifact = {"tfidf": tfidf, "scaler_meta": scalers["metadata"], "scaler_slots": scalers["slots"],
                "scaler_legibilidad": scalers["readability"], "calibrated_model": model,
                "umbral_critico": threshold, "dominios_oficiales": analyzer.DOMINIOS_OFICIALES,
                "training_metadata": provenance}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as stream:
        pickle.dump(artifact, stream)
    test_rows = [{"id": prepared[i][0]["row_id"], "group": prepared[i][0]["group_id"],
                  "source": prepared[i][0].get("source", "unknown"), "label": int(labels[i]),
                  "score": float(score)} for i, score in zip(splits["test"], scores)]
    report = {"provenance": provenance, "model_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
              "model_path": str(args.output.resolve()), "threshold": threshold, "metrics": evaluation,
              "partitions": {name: dict(Counter(str(labels[i]) for i in indices)) for name, indices in splits.items()},
              "skipped": skipped, "test_rows": test_rows, "elapsed_seconds": time.perf_counter() - started,
              "limitations": ["Inherited labels were not individually authenticated.",
                              "Test partition was already inspected during development; not an independent production holdout.",
                              "Calibration quality must be verified on new, independently reviewed mail before probability claims."]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"metrics": evaluation, "skipped": skipped}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
