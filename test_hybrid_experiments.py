import numpy as np

from scripts.audit_hybrid_candidate import grouped_f1_bootstrap
from scripts.run_hybrid_experiments import commands


def test_paired_bootstrap_identical_models_has_zero_difference():
    y = np.array([0, 1, 1, 0, 1, 0])
    prediction = np.array([False, True, False, False, True, False])
    result = grouped_f1_bootstrap(y, prediction, prediction, ['a','a','b','b','c','c'], repeats=50)
    assert result['difference'] == [0.0, 0.0, 0.0]


def test_seed_experiment_preserves_split_independent_of_seed():
    config = {'common': {'epochs': 5}, 'runs': [{'id':'seed7','seed':7}, {'id':'seed21','seed':21}]}
    jobs = list(commands(config, 'python'))
    splits = [cmd[cmd.index('--previous-splits')+1] for _,cmd in jobs]
    assert splits[0] == splits[1]
    assert jobs[0][1][jobs[0][1].index('--output')+1] != jobs[1][1][jobs[1][1].index('--output')+1]


def test_curated_corpus_v3_no_leakage():
    import json
    from pathlib import Path
    corpus_dir = Path("artifacts/hybrid/corpus-v3")
    assert (corpus_dir / "training.csv").exists()
    assert (corpus_dir / "splits.json").exists()
    
    splits = json.loads((corpus_dir / "splits.json").read_text(encoding="utf-8"))
    train_groups = {item["group"] for item in splits["train"]}
    val_groups = {item["group"] for item in splits["validation"]}
    test_groups = {item["group"] for item in splits["test"]}
    
    assert len(train_groups & val_groups) == 0, "Leakage between train and validation"
    assert len(train_groups & test_groups) == 0, "Leakage between train and test"
    assert len(val_groups & test_groups) == 0, "Leakage between validation and test"


def test_contrastive_manifest_integrity():
    import json
    from pathlib import Path
    manifest_file = Path("data/hybrid_contrastive_curated_v3.manifest.json")
    jsonl_file = Path("data/hybrid_contrastive_curated_v3.jsonl")
    assert manifest_file.exists()
    assert jsonl_file.exists()

    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    lines = [json.loads(l) for l in jsonl_file.read_text(encoding="utf-8").strip().split("\n") if l]
    assert len(lines) == manifest["counts"]["total"]
    for sample in lines:
        assert sample["label"] in {"phishing", "legitimate"}
        assert "subject" in sample and "body" in sample

