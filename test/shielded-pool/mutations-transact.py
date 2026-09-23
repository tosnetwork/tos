#!/usr/bin/env python3
"""Remove one rule at a time from the transact parser and the public-input
vector, and require the sandbox suite to report it, by name.

A mutation that turns the wrong test red is not evidence for the one it was
aimed at, so each case names the test that must fail. A mutation that fails to
compile is not evidence at all: every replacement below still compiles and
still runs, it is simply wrong.

Usage: mutations-transact.py [--only NAME ...]
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
TRANSACT = ROOT / 'crypto/smartcont/shielded/transact.fc'
CONTRACTS = ROOT / 'tosctl/src/node-control/contracts'
SUITE = 'shielded_transact_sandbox'

ORDER_TEST = 'the_eighteen_public_inputs_are_the_frozen_order'
DERIVED_TEST = 'the_eight_derived_inputs_come_from_the_bytes_that_arrived'
SHAPE_TEST = 'every_frozen_shape_is_refused_when_it_is_not_that_shape'
CANONICAL_TEST = 'a_field_element_on_the_wire_must_already_be_canonical'
MODE_TEST = 'the_query_id_and_the_mode_have_to_agree_with_the_rest'


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str


CASES = [
    # Section 12: a field element that arrives is canonical or it is refused.
    Case('canonical', 'a wire field element may be anything', TRANSACT,
         '  throw_unless(236, (value >= 0) & (value < field_modulus()));',
         '  throw_unless(236, value >= 0);', CANONICAL_TEST),

    # Section 13.3: the shapes, one bundle at a time.
    Case('root-refs', 'a transact root with too few references is not refused here', TRANSACT,
         '  throw_unless(230, body.slice_refs() == 4);',
         '  throw_unless(230, body.slice_refs() >= 0);', SHAPE_TEST),
    Case('root-leftover', 'anything left over in the root is ignored', TRANSACT,
         '  throw_unless(230, body.slice_empty?());\n', '', SHAPE_TEST),
    Case('proof-bundle', 'the proof bundle may be any shape', TRANSACT,
         '  throw_unless(231, (s.slice_bits() == 768) & (s.slice_refs() == 2));',
         '  throw_unless(231, s.slice_refs() >= 2);', SHAPE_TEST),
    Case('note-bodies', 'the note-bodies cell may be any shape', TRANSACT,
         '  throw_unless(232, (s.slice_bits() == 768) & (s.slice_refs() == 0));',
         '  throw_unless(232, s.slice_bits() >= 0);', SHAPE_TEST),
    Case('groth16-shape', 'the proof cells may be any shape', TRANSACT,
         '  throw_unless(241, (s.slice_bits() == 768) & (s.slice_refs() == 1));',
         '  throw_unless(241, s.slice_refs() == 1);', SHAPE_TEST),
    Case('groth16-b', 'the B cell may carry references', TRANSACT,
         '  throw_unless(241, (b.slice_bits() == 768) & (b.slice_refs() == 0));',
         '  throw_unless(241, b.slice_bits() == 768);', SHAPE_TEST),
    Case('output-bundle', 'the output bundle may be any shape', TRANSACT,
         '  throw_unless(233, (s.slice_bits() == 256) & (s.slice_refs() == 4));',
         '  throw_unless(233, s.slice_bits() == 256);', SHAPE_TEST),
    Case('auth-bundle', 'the auth bundle may be any shape', TRANSACT,
         '  throw_unless(234, (s.slice_bits() == 0) & (s.slice_refs() == 4));',
         '  throw_unless(234, s.slice_bits() == 0);', SHAPE_TEST),
    Case('witness-bundle', 'the witness bundle may be any shape', TRANSACT,
         '  throw_unless(235, (s.slice_bits() == 0) & (s.slice_refs() == 2));',
         '  throw_unless(235, s.slice_bits() == 0);', SHAPE_TEST),
    Case('witness-unchecked', 'the witness bundle is never looked at', TRANSACT,
         '  (_, _) = witness_bundle_parse(witness_bundle);\n', '', SHAPE_TEST),

    # Section 12.2: the query id is the digest's low bits.
    Case('query-id', 'the query id is free-form again', TRANSACT,
         '  throw_unless(237, query_id == (intent_digest % 18446744073709551616));\n', '',
         MODE_TEST),

    # Sections 8 and 11.3: the mode.
    Case('transfer-recipient', 'a transfer may name a recipient', TRANSACT,
         '    throw_unless(239, address_is_none(recipient));\n', '', MODE_TEST),
    Case('withdrawal-recipient', 'a withdrawal may have nowhere to go', TRANSACT,
         '  throw_if(238, address_is_none(recipient));\n', '', MODE_TEST),
    Case('transfer-recovery-owner', 'a transfer may pre-authorise a recovery', TRANSACT,
         '    throw_unless(240, recovery_owner_commitment == 0);\n', '', MODE_TEST),
    Case('transfer-recovery-data', 'a transfer may carry recovery data', TRANSACT,
         '    throw_unless(240, s.slice_empty?());\n    return 0;',
         '    return 0;', MODE_TEST),

    # Section 10: the frozen order, and which inputs are derived.
    Case('order-swap', 'two public inputs change places', TRANSACT,
         '  inputs = inputs.tpush(nullifier_0);                       ;;  1\n  inputs = inputs.tpush(nullifier_1);                       ;;  2',
         '  inputs = inputs.tpush(nullifier_1);                       ;;  1\n  inputs = inputs.tpush(nullifier_0);                       ;;  2',
         ORDER_TEST),
    Case('derived-payload', 'the second payload hash is the first one again', TRANSACT,
         '  inputs = inputs.tpush(output_data_hash(data_1));          ;;  7',
         '  inputs = inputs.tpush(output_data_hash(data_0));          ;;  7', DERIVED_TEST),
    Case('derived-key', 'the second key hash is the first one again', TRANSACT,
         '  inputs = inputs.tpush(pq_auth_key_hash(public_key_1));    ;; 10',
         '  inputs = inputs.tpush(pq_auth_key_hash(public_key_0));    ;; 10', DERIVED_TEST),
    Case('derived-recipient', 'the recipient hash is taken from the wire instead', TRANSACT,
         '  inputs = inputs.tpush(recipient_hash_for(recipient, public_amount_out));  ;; 13',
         '  inputs = inputs.tpush(0);  ;; 13', ORDER_TEST),
    Case('derived-domain', 'the execution domain is a constant', TRANSACT,
         '  inputs = inputs.tpush(execution_domain());                ;; 15',
         '  inputs = inputs.tpush(0);                ;; 15', ORDER_TEST),
    Case('derived-recovery', 'the recovery template hash is always zero', TRANSACT,
         '  inputs = inputs.tpush(recovery_hash_for(public_amount_out, recovery_owner_commitment,\n                                          recovery_data));  ;; 16',
         '  inputs = inputs.tpush(0);  ;; 16', ORDER_TEST),
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
