#!/usr/bin/env python3
"""Continuous M3 TEST scenario, pure state transitions, never a devnet claim.

The C++ ScenarioBackend can be replaced by a live publisher without changing
step ordering/assertions. This runner selects only the real-kernel pure backend.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--output', type=Path)
p.add_argument('--jobs', type=int, default=8)
a = p.parse_args()
repo = Path(__file__).resolve().parents[1]
build = a.build.resolve()
cache = (build / 'CMakeCache.txt').read_text()
entries = dict(line.split('=', 1) for line in cache.splitlines() if '=' in line and not line.startswith(('#', '//')))
if Path(entries['CMAKE_HOME_DIRECTORY:INTERNAL']).resolve() != repo:
    p.error('build belongs to another source tree')
if entries.get('TOS_UNO_CRYPTO_NODE_LINK:BOOL') != 'ON':
    p.error('real verification requires configuring this build with -DTOS_UNO_CRYPTO_NODE_LINK=ON')
if a.jobs < 1:
    p.error('--jobs must be positive')
output = a.output.resolve() if a.output else Path(tempfile.mkdtemp(prefix='uno-m3-sequence-'))
output.mkdir(parents=True, exist_ok=True)
# Avoid accidentally reusing wallet request/result files from an earlier run.
run = Path(tempfile.mkdtemp(prefix='run-', dir=output))
subprocess.run(['cmake', '--build', str(build), '--target', 'workchain-m3-scenario', '-j', str(a.jobs)], check=True)
wallet_target = build / 'm3-vector-wallet-target'
subprocess.run(['cargo', 'build', '--locked', '--offline', '--release', '--manifest-path', str(repo / 'uno/prover/Cargo.toml'),
                '--example', 'm3-scenario', '--target-dir', str(wallet_target)], check=True, cwd=repo)
print(f'TEST-only wallet inputs and outputs: {run}', flush=True)
subprocess.run([str(build / 'crypto/workchain-m3-scenario'), str(wallet_target / 'release/examples/m3-scenario'), str(run)], check=True)
