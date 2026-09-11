#!/usr/bin/env python3
"""Prove both real contract verifiers are necessary; compile errors are not kills."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
GUARDS = {
    'func': ('mldsa44-auth-module.fc',
             'throw_unless(auth::bad_signature, pq_check_mldsa44(message, context, signature, public_key));',
             'throw_unless(auth::bad_signature, -1);'),
    'tol': ('mldsa44-auth-module.tol',
            'assert (pqCheckMldsa44(message, context, signature, publicKey)) throw 1808;',
            'assert (true) throw 1808;'),
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--signer', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    results = []
    for language, (name, before, after) in GUARDS.items():
        path = ROOT / 'crypto/smartcont' / name
        original = path.read_text()
        if original.count(before) != 1:
            raise RuntimeError(f'{language}: guard must occur exactly once')
        command = [sys.executable, str(ROOT / 'test/mldsa-auth/e2e.py'),
                   '--build', str(args.build.resolve()), '--signer', str(args.signer.resolve()),
                   '--module', language, '--case', 'test_bad_pq_signatures_keys_context_and_encoding']
        subprocess.run(command + ['--out', str((args.out / (language + '-baseline')).resolve())], check=True)
        try:
            path.write_text(original.replace(before, after))
            mutant = args.out / (language + '-mutant')
            result = subprocess.run(command + ['--out', str(mutant.resolve())], text=True, capture_output=True)
            (args.out / (language + '.log')).write_text(result.stdout + result.stderr)
            if result.returncode != 1 or 'E2E_ASSERTION_FAILURE' not in result.stdout:
                raise RuntimeError(f'{language}: mutation was not killed by an executed assertion')
            report = json.loads((mutant / 'e2e.json').read_text())
            if report['success']:
                raise RuntimeError(f'{language}: verifier removal was accepted by the suite')
            results.append({'module': language, 'guard': 'real-pq-verification', 'killed': True})
        finally:
            path.write_text(original)
        subprocess.run(command + ['--out', str((args.out / (language + '-restored')).resolve())], check=True)
    (args.out / 'mutations.json').write_text(json.dumps(results, indent=2, sort_keys=True) + '\n')
    print('PASS: both compiling verifier-removal mutations killed; restored baselines pass')


if __name__ == '__main__':
    main()
