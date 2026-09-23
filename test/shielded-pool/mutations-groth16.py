#!/usr/bin/env python3
"""Remove one rule at a time from the on-chain Groth16 verifier and require the
sandbox suite to report it, by name.

A mutation that turns the wrong test red is not evidence for the one it was
aimed at, so each case names the test that must fail. A mutation that fails to
compile is not evidence at all: every replacement below still compiles and
still runs, it is simply wrong.

Usage: mutations-groth16.py [--only NAME ...]
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import sys

# This repository, never another checkout: TOS_ROOT points at the built
# toolchain, which may live somewhere else entirely.
from toolchain import toolchain_root

ROOT = Path(__file__).resolve().parents[2]
GROTH16 = ROOT / 'crypto/smartcont/shielded/groth16.fc'
CONTRACTS = ROOT / 'tosctl/src/node-control/contracts'
SUITE = 'shielded_groth16_sandbox'

VECTORS_TEST = 'the_development_proof_verifies_in_the_vm_and_its_mutations_do_not'
INPUTS_TEST = 'a_public_input_the_proof_did_not_commit_to_is_rejected'
SHAPE_TEST = 'a_verifying_key_chain_that_is_not_the_frozen_shape_is_refused'


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str


CASES = [
    # The equation itself. Each of these still verifies something; none of them
    # verifies this proof system.
    Case('pairing-sign', 'A is not negated, so the equation is the wrong one', GROTH16,
         '    bls_pairing_4(bls_g1_neg(proof_a), proof_b,',
         '    bls_pairing_4(proof_a, proof_b,', VECTORS_TEST),
    Case('pairing-order', 'gamma and delta change places', GROTH16,
         '                  vk_x, gamma,\n                  proof_c, delta));',
         '                  vk_x, delta,\n                  proof_c, gamma));', VECTORS_TEST),
    Case('pairing-ignored', 'the pairing result is not looked at', GROTH16,
         '  throw_unless(262,\n    bls_pairing_4(',
         '  throw_unless(262, 1 | \n    bls_pairing_4(', VECTORS_TEST),

    # vk_x, which is where the public inputs enter the equation at all.
    Case('vk-x-base', 'the constant term of vk_x is dropped', GROTH16,
         '  return bls_g1_add(vk_ic_at(ic, 0), bls_g1_multiexp_18(pairs));',
         '  return bls_g1_multiexp_18(pairs);', VECTORS_TEST),
    Case('vk-x-offset', 'each input is paired with the wrong IC point', GROTH16,
         '    pairs = pairs.tpush(vk_ic_at(ic, index + 1));',
         '    pairs = pairs.tpush(vk_ic_at(ic, index));', VECTORS_TEST),
    Case('vk-x-scalar', 'the scalar is the position rather than the input', GROTH16,
         '    pairs = pairs.tpush(public_input_at(inputs, index));',
         '    pairs = pairs.tpush(index);', INPUTS_TEST),

    # Section 10.1: where the key is in the stream.
    Case('vk-order', 'gamma is read before beta', GROTH16,
         '  (slice beta, cursor, next) = vk_take(cursor, next, g2_bytes());\n  (slice gamma, cursor, next) = vk_take(cursor, next, g2_bytes());',
         '  (slice gamma, cursor, next) = vk_take(cursor, next, g2_bytes());\n  (slice beta, cursor, next) = vk_take(cursor, next, g2_bytes());',
         VECTORS_TEST),
    Case('vk-ic-count', 'the key holds one IC point fewer', GROTH16,
         'int ic_count() asm "19 PUSHINT";', 'int ic_count() asm "18 PUSHINT";', SHAPE_TEST),
    Case('vk-tail', 'anything after the key in the chain is ignored', GROTH16,
         '  throw_unless(261, (cursor.slice_bits() == 0) & cell_null?(next));\n', '',
         SHAPE_TEST),
    Case('vk-alignment', 'a chain cell need not hold whole bytes', GROTH16,
         '  throw_unless(261, (s.slice_bits() % 8) == 0);\n', '', SHAPE_TEST),
    Case('vk-exhausted', 'running off the end of the chain is not refused', GROTH16,
         '  throw_if(260, cell_null?(node));\n', '', SHAPE_TEST),
    Case('vk-refs', 'a chain cell may carry any references', GROTH16,
         '    throw_unless(261, s.slice_refs() == 0);\n', '', SHAPE_TEST),
]


def run_suite() -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env['PATH'] = str(Path.home() / '.cargo/bin') + os.pathsep + env.get('PATH', '')
    env['CARGO_TERM_COLOR'] = 'never'
    # TOS_ROOT only locates the built func/fift toolchain and stdlib.fc; the
    # library under test is found from the crate manifest, inside this tree.
    env.setdefault('TOS_ROOT', str(toolchain_root(ROOT)))
    return subprocess.run(['cargo', 'test', '--test', SUITE, '--', '--test-threads=1'],
                          cwd=CONTRACTS, capture_output=True, text=True, timeout=3600, env=env)


def failed_tests(output: str) -> set[str]:
    return set(re.findall(r'^test (\S+) \.\.\. FAILED$', output, flags=re.M))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--only', nargs='*', default=None)
    options = parser.parse_args()
    cases = CASES if options.only is None else [c for c in CASES if c.name in options.only]
    if options.only and len(cases) != len(options.only):
        raise SystemExit(f'unknown case name in {options.only}')

    baseline = run_suite()
    if baseline.returncode:
        raise SystemExit('the suite is not green before any mutation:\n'
                         + baseline.stdout + baseline.stderr)
    print('baseline green', flush=True)

    survivors = []
    for case in cases:
        original = case.path.read_text()
        count = original.count(case.before)
        if count != 1:
            raise SystemExit(f'{case.name}: anchor appears {count} times, expected once')
        try:
            case.path.write_text(original.replace(case.before, case.after))
            result = run_suite()
            failures = failed_tests(result.stdout + result.stderr)
            if result.returncode == 0:
                survivors.append(f'{case.name}: the suite stayed green')
                verdict = 'SURVIVED'
            elif 'error[' in result.stderr or 'could not compile' in result.stderr:
                survivors.append(f'{case.name}: no longer compiles, which is not evidence')
                verdict = 'UNCOMPILED'
            elif case.expect not in failures:
                survivors.append(f'{case.name}: failed as {sorted(failures)}, not {case.expect}')
                verdict = 'WRONG-TEST'
            else:
                verdict = 'killed'
            print(f'{case.name:20} {case.why:58} {verdict}', flush=True)
        finally:
            case.path.write_text(original)

    restored = run_suite()
    if restored.returncode:
        raise SystemExit('the suite did not come back green:\n' + restored.stdout + restored.stderr)
    print('green again', flush=True)

    if survivors:
        print('\nSURVIVORS:', file=sys.stderr)
        for line in survivors:
            print('  ' + line, file=sys.stderr)
        return 1
    print(f'\n{len(cases)} mutations, all killed by the test they were aimed at')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
