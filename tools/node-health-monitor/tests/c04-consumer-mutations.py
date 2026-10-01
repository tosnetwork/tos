#!/usr/bin/env python3
"""C04 strict-consumer changed properties: green baseline, compiled assertion red, restore."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ('duplicate-map-refusal', 'crates/health-core/src/consensus_v2.rs',
     'if out.insert(key, value).is_some() {',
     'if out.insert(key, value).is_some() && false {',
     'duplicate_raw_keys_refuse_before_hash_or_value_normalization'),
    ('quality-no-promotion', 'crates/health-core/src/native.rs',
     'if self.quality.instrumentation_complete\n            && (!(pq_complete && consensus_complete)',
     'if false && self.quality.instrumentation_complete\n            && (!(pq_complete && consensus_complete)',
     'overall_quality_may_degrade_but_cannot_promote_incomplete_components'),
    ('masterchain-all-shard', 'crates/health-core/src/consensus_v2.rs',
     'context.scope.shard.0 != 9_223_372_036_854_775_808',
     'false && context.scope.shard.0 != 9_223_372_036_854_775_808',
     'incomplete_capability_and_context_mismatch_refuse'),
    ('post-terminal-incomplete', 'crates/health-core/src/consensus_v2.rs',
     'self.post_terminal_progress.0 > 0',
     'false && self.post_terminal_progress.0 > 0',
     'unapproved_scope_and_post_terminal_progress_cannot_stay_green'),
]
parser = argparse.ArgumentParser()
parser.add_argument('--log-dir', type=Path,
                    default=ROOT/'evidence/c04-rust-consumer/raw/mutations')
parser.add_argument('--timeout', type=int, default=120)
parser.add_argument('--jobs', type=int, default=2)
parser.add_argument('--case', action='append', dest='selected')
args = parser.parse_args()
if args.timeout <= 0 or not 1 <= args.jobs <= 8:
    parser.error('positive timeout and jobs 1..8 required')
args.log_dir.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, CARGO_BUILD_JOBS=str(args.jobs), CARGO_INCREMENTAL='0')

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def run(label, phase, test, source_sha):
    cmd = ['cargo', 'test', '--locked', '-p', 'tos-health-core',
           '--test', 'native_v2_contract', test, '--', '--exact']
    try:
        result = subprocess.run(cmd, cwd=ROOT, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=args.timeout)
        output, code = result.stdout, result.returncode
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ''
        if isinstance(output, bytes):
            output = output.decode(errors='replace')
        output += '\nTIMEOUT\n'
        code = 124
    (args.log_dir/f'{label}.{phase}.log').write_text(
        f"$ {' '.join(cmd)}\nsource_sha256={source_sha}\ntimeout_seconds={args.timeout}\n{output}\nEXIT={code}\n")
    return code, output

for label, relative, old, new, test in CASES:
    if args.selected and label not in args.selected:
        continue
    path = ROOT/relative
    original = path.read_text()
    if original.count(old) != 1:
        raise RuntimeError(f'{label}: expected one target, found {original.count(old)}')
    before = digest(original)
    code, output = run(label, 'baseline', test, before)
    if code or '1 passed; 0 failed' not in output:
        raise RuntimeError(f'{label}: baseline failed')
    try:
        changed = original.replace(old, new, 1)
        path.write_text(changed)
        code, output = run(label, 'mutant', test, digest(changed))
        if code == 0 or f'test {test} ... FAILED' not in output or '0 passed; 1 failed' not in output:
            raise RuntimeError(f'{label}: no compiled assertion red')
        print(f'{label}: compiled assertion red', flush=True)
    finally:
        path.write_text(original)
        if digest(path.read_text()) != before:
            raise RuntimeError(f'{label}: source not restored')

print('C04 consumer mutation sources restored', flush=True)
