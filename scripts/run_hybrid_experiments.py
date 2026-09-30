"""Run controlled GPU experiments, preserving splits and all prior artifacts."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def commands(config, python):
    for run in config['runs']:
        options = dict(config['common'], **run)
        name = options.pop('id')
        expanded = options.pop('expanded', False)
        dataset = 'artifacts/hybrid/expansion-v2/training.csv' if expanded else 'artifacts/hybrid/corpus/multilingual-v1.csv'
        split = 'artifacts/hybrid/expansion-v2/splits.json' if expanded else 'artifacts/hybrid/multilingual-candidate-a100/splits.json'
        cmd = [python, 'scripts/train_hybrid.py', '--dataset', dataset, '--previous-splits', split,
               '--phishing-label', '1', '--device', 'cuda', '--output', f'artifacts/hybrid/experiments-v2/{name}',
               '--report', f'reports/hybrid_experiments_v2_{name}']
        for key, value in options.items():
            cmd += ['--'+key.replace('_', '-'), str(value)]
        yield name, cmd


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, default=ROOT/'data/hybrid_experiments_v2.json')
    p.add_argument('--run', nargs='+', help='Run listed experiment IDs; omitted prints commands only')
    args = p.parse_args()
    jobs = dict(commands(json.loads(args.config.read_text()), sys.executable))
    if args.run:
        unknown = set(args.run)-jobs.keys()
        if unknown:
            p.error(f'Unknown experiments: {sorted(unknown)}')
        import torch
        if not torch.cuda.is_available():
            p.error('These controlled runs require a CUDA runtime; no training was started')
    for name, cmd in jobs.items():
        if args.run and name not in args.run:
            continue
        print(subprocess.list2cmdline(cmd), flush=True)
        if args.run:
            subprocess.run(cmd, cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
