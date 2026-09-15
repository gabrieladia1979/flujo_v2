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
