#!/usr/bin/env python3
"""Freeze raw restored C04 consumer checks against an isolated native pair set."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--pair-dir', required=True, type=Path)
parser.add_argument('--output-dir', required=True, type=Path)
parser.add_argument('--native-binary', required=True, type=Path)
args = parser.parse_args()
args.output_dir.mkdir(parents=True, exist_ok=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def pair_hashes():
    assert (args.pair_dir/'index.json').is_file(), 'final producer index required'
    bodies = sorted(args.pair_dir.glob('*.prom'))
    assert len(bodies) >= 3 and {f'success-{n}' for n in (1, 2, 3)}.issubset(
        {path.stem for path in bodies}
    )
    paths = [args.pair_dir/'index.json'] + [
        path for body in bodies for path in (body, body.with_suffix('.json'))
    ]
    return {str(path): sha(path) for path in paths}

sources = [
    'contracts/consensus-v2.schema.json',
    'contracts/source-envelope.schema.json',
    'contracts/edge-snapshot.schema.json',
    'crates/health-core/src/consensus_v2.rs',
    'crates/health-core/src/native.rs',
    'crates/health-core/src/edge_snapshot.rs',
    'crates/health-core/tests/native_v2_contract.rs',
    'crates/health-core/tests/fixtures/consensus-v2.synthetic.json',
    'crates/health-services/src/collector.rs',
    'crates/health-services/src/edge.rs',
    'crates/health-services/src/manager.rs',
    'crates/health-services/src/manager_poll.rs',
    'crates/health-services/src/native_cache.rs',
    'crates/health-services/tests/native_typed.rs',
    'crates/health-services/tests/native_v2_producer_pair.rs',
    'scripts/check-contracts.py',
    'scripts/run-contract-tests.sh',
    'scripts/run-c04-cross-language.sh',
    'tests/check-c04-producer-pair.py',
    'tests/c04-consumer-mutations.py',
    'tests/c04-consumer-closure.py',
]
receipt = {
    'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip(),
    'git_status_at_start': subprocess.check_output(
        ['git', 'status', '--short'], cwd=REPO, text=True
    ),
    'source_sha256': {path: sha(ROOT/path) for path in sources},
    'pair_sha256': pair_hashes(),
    'native_binary_sha256': sha(args.native_binary),
    'checks': [],
}
env = dict(os.environ, CARGO_BUILD_JOBS='2')
checks = [
    ('fmt', ['cargo', 'fmt', '--all', '--', '--check']),
    ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings']),
    ('contracts', ['bash', 'scripts/run-contract-tests.sh']),
    ('producer-pairs', [
        'bash', 'scripts/run-c04-cross-language.sh', str(args.pair_dir),
        str(args.output_dir/'actual-route'), str(args.native_binary),
    ]),
]
for name, command in checks:
    try:
        result = subprocess.run(
            command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, timeout=240,
        )
        output, code = result.stdout, result.returncode
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b''
        if isinstance(output, bytes):
            output = output.decode(errors='replace')
        output += '\nTIMEOUT after 240 seconds\n'
        code = 124
    log = args.output_dir/f'{name}.log'
    log.write_text(f'$ {" ".join(command)}\n{output}\nEXIT={code}\n')
    receipt['checks'].append({'name': name, 'command': command, 'exit': code, 'log': str(log), 'sha256': sha(log)})
    (args.output_dir/'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True)+'\n')
    print(f'{name}: exit {code}, log SHA-256 {sha(log)}', flush=True)
    if code:
        sys.exit(code)
assert pair_hashes() == receipt['pair_sha256'], 'native pair bytes changed during closure run'
assert sha(args.native_binary) == receipt['native_binary_sha256'], 'native binary changed during closure run'
assert {path: sha(ROOT/path) for path in sources} == receipt['source_sha256'], 'consumer source changed during closure run'
print('C04 consumer source and native pair inputs unchanged throughout restored checks')
