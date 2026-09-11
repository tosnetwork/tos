#!/usr/bin/env python3
"""Run real registration, funding, SEND, COLLECT and closure epoch observations."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--repo', type=Path)
p.add_argument('--build', type=Path)
p.add_argument('--scenario', type=Path)
p.add_argument('--unavailable', action='store_true')
a = p.parse_args()
if a.unavailable:
    raise SystemExit('epoch behavior requires the real confidential kernel and offline Cargo dependencies; not skipped')
if not a.repo or not a.build or not a.scenario:
    raise SystemExit('missing explicit epoch test paths')
env = dict(os.environ, CARGO_TARGET_DIR=str(a.build.resolve()))
subprocess.run(['cargo', 'build', '--locked', '--offline', '--release', '--example', 'm3-scenario'],
               cwd=a.repo / 'uno/prover', env=env, check=True)
wallet = a.build.resolve() / 'release/examples/m3-scenario'
with tempfile.TemporaryDirectory(prefix='epoch-scenario-') as tmp:
    subprocess.run([str(a.scenario.resolve()), str(wallet), tmp], check=True)
print('EPOCH_BEHAVIOR_PASS: registration, test funding, SEND, COLLECT, closure')
