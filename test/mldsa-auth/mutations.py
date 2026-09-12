#!/usr/bin/env python3
"""Prove both real contract verifiers are necessary; compile errors are not kills."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
# Each entry names the file, the exact text to remove, and the executed case that
# must then fail. A compile error or a crash is not a kill.
GUARDS = {
    'func': {'file': 'mldsa44-auth-module.fc', 'guard': 'real-pq-verification',
             'case': 'test_bad_pq_signatures_keys_context_and_encoding',
             'before': 'throw_unless(auth::bad_signature, pq_check_mldsa44(message, context, signature, public_key));',
             'after': 'throw_unless(auth::bad_signature, -1);'},
    'tol': {'file': 'mldsa44-auth-module.tol', 'guard': 'real-pq-verification',
            'case': 'test_bad_pq_signatures_keys_context_and_encoding',
            'before': 'assert (pqCheckMldsa44(message, context, signature, publicKey)) throw 1808;',
            'after': 'assert (true) throw 1808;'},
    # The FunC module calls the destination check for its throws alone, so the
    # compiler may only keep it while the helper is impure. Without this the
    # module would relay across workchains and to itself.
    'func-impure': {'file': 'auth-extension.fc', 'guard': 'impure-destination-check',
                    'case': 'test_signed_stale_epoch_nonce_and_expiry', 'module': 'func',
                    'before': 'int auth_module_hash(slice address) impure inline {',
                    'after': 'int auth_module_hash(slice address) inline {'},
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--signer', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    results = []
    for name, guard in GUARDS.items():
        path = ROOT / 'crypto/smartcont' / guard['file']
        before, after_text = guard['before'], guard['after']
        original = path.read_text()
        if original.count(before) != 1:
            raise RuntimeError(f'{name}: guard must occur exactly once')
        language = guard.get('module', name)
        command = [sys.executable, str(ROOT / 'test/mldsa-auth/e2e.py'),
                   '--build', str(args.build.resolve()), '--signer', str(args.signer.resolve()),
                   '--module', language, '--case', guard['case']]
        subprocess.run(command + ['--out', str((args.out / (name + '-baseline')).resolve())], check=True)
        try:
            path.write_text(original.replace(before, after_text))
            mutant = args.out / (name + '-mutant')
            result = subprocess.run(command + ['--out', str(mutant.resolve())], text=True, capture_output=True)
            (args.out / (name + '.log')).write_text(result.stdout + result.stderr)
            if result.returncode != 1 or 'E2E_ASSERTION_FAILURE' not in result.stdout:
                raise RuntimeError(f'{name}: mutation was not killed by an executed assertion')
            report = json.loads((mutant / 'e2e.json').read_text())
            if report['success']:
                raise RuntimeError(f'{name}: removal was accepted by the suite')
            results.append({'module': language, 'guard': guard['guard'], 'killed': True})
        finally:
            path.write_text(original)
        subprocess.run(command + ['--out', str((args.out / (name + '-restored')).resolve())], check=True)
    (args.out / 'mutations.json').write_text(json.dumps(results, indent=2, sort_keys=True) + '\n')
    print(f'PASS: {len(results)} compiling guard mutations killed; restored baselines pass')


if __name__ == '__main__':
    main()
