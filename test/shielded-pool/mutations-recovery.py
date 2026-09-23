#!/usr/bin/env python3
"""Remove one rule at a time from the bounce-recovery library and require the
sandbox suite to report it, by name.

A mutation that turns the wrong test red is not evidence for the one it was
aimed at, so each case names the test that must fail. A mutation that fails to
compile is not evidence at all: every replacement below still compiles and
still runs, it is simply wrong.

Usage: mutations-recovery.py [--only NAME ...]
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
RECOVERY = ROOT / 'crypto/smartcont/shielded/recovery.fc'
POOL = ROOT / 'crypto/smartcont/tos-shielded-pool-v1.fc'
CONTRACTS = ROOT / 'tosctl/src/node-control/contracts'
SUITE = 'shielded_recovery_sandbox'

ENVELOPE_TEST = 'only_the_new_bounce_envelope_is_read'
SHAPE_TEST = 'only_the_frozen_payout_shape_is_a_payout'
FROZEN_TEST = 'every_frozen_shape_is_refused_when_it_is_not_that_shape'
AUTHENTIC_TEST = 'a_record_cannot_vouch_for_itself'
NOTE_TEST = 'the_note_is_built_for_the_amount_that_actually_returned'
RECOVERED_TEST = 'a_bounced_payout_becomes_a_note_for_what_came_back'
WRONG_ADDRESS_TEST = 'a_bounce_from_the_wrong_address_recovers_nothing'
RESERVE_TEST = 'a_bounce_that_is_not_a_payout_is_reserve'


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str


CASES = [
    # The envelope.
    Case('envelope-tag', 'any bounce tag is the new envelope', RECOVERY,
         '  throw_unless(264, body~load_uint(32) == recovery_envelope_tag());\n', '',
         ENVELOPE_TEST),
    Case('envelope-refs', 'an envelope need not carry an original body', RECOVERY,
         '  throw_unless(264, body.slice_refs() >= 1);\n', '', ENVELOPE_TEST),
    Case('envelope-bits', 'a body too short to hold a tag is read as one', RECOVERY,
         '  throw_unless(264, body.slice_bits() >= 32);\n', '', ENVELOPE_TEST),

    # Section 15.2's shape, which is also what excludes the bits-only bounce.
    Case('payout-op', 'the outbound operation need not be zero', RECOVERY,
         '  throw_unless(265, root~load_uint(32) == 0);', '  root~load_uint(32);',
         FROZEN_TEST),
    Case('payout-root-bits', 'the payout root may be any size', RECOVERY,
         '  throw_unless(265, root.slice_bits() == 96);\n', '', FROZEN_TEST),
    Case('payout-root-refs', 'the payout root need not carry a record', RECOVERY,
         '  throw_unless(265, root.slice_refs() == 1);\n', '', SHAPE_TEST),
    Case('record-bits', 'the record may be any size', RECOVERY,
         '  throw_unless(265, record.slice_bits() == 768);\n', '', FROZEN_TEST),
    Case('record-refs', 'the record need not carry a tail', RECOVERY,
         '  throw_unless(265, record.slice_refs() == 1);\n', '', FROZEN_TEST),
    Case('tail-bits', 'the tail may be any size', RECOVERY,
         '  throw_unless(265, tail.slice_bits() == 256);\n', '', FROZEN_TEST),
    Case('tail-refs', 'the tail need not carry a payload', RECOVERY,
         '  throw_unless(265, tail.slice_refs() == 1);\n', '', FROZEN_TEST),
    Case('record-field-order', 'the record is read in another order', RECOVERY,
         '  int intent_digest = record~load_uint(256);\n  int template_hash = record~load_uint(256);',
         '  int template_hash = record~load_uint(256);\n  int intent_digest = record~load_uint(256);',
         SHAPE_TEST),

    # Section 15.3 checks 4 to 7.
    Case('query-unchecked', 'the query id need not name the intent', RECOVERY,
         '  throw_unless(266, query_id == (intent_digest % 18446744073709551616));\n', '',
         AUTHENTIC_TEST),
    Case('sender-unchecked', 'any address may present any record', RECOVERY,
         '  throw_unless(267, recipient_hash == public_recipient_hash(sender));\n', '',
         AUTHENTIC_TEST),
    Case('template-unchecked', 'the template hash is taken on trust', RECOVERY,
         '  throw_unless(268,\n    template_hash == recovery_template_hash(owner_commitment, output_data_hash(recovery_data)));\n',
         '', AUTHENTIC_TEST),

    # Section 15.4.
    Case('note-owner', 'the note is not built for the owner the record names', RECOVERY,
         '  return note_body_commitment(owner_commitment, recovered_amount,',
         '  return note_body_commitment(0, recovered_amount,', NOTE_TEST),
    Case('note-amount', 'the note is built for a fixed amount', RECOVERY,
         '  return note_body_commitment(owner_commitment, recovered_amount,',
         '  return note_body_commitment(owner_commitment, 1000000000,', NOTE_TEST),

    # Section 16.3, in the handler.
    Case('handler-mints-what-left', 'the note is for what went out, not what came back', POOL,
         '  int recovered_amount = msg_value - charge;',
         '  int recovered_amount = 9000000000;', RECOVERED_TEST),

    # Section 15.4's charge. The recovery pays for itself out of what it is
    # returning; before it did, an immutable fee pre-paid it on every
    # withdrawal including the ones that never bounce.
    Case('charge-not-applied', 'the charge is quoted and not taken', POOL,
         '  int recovered_amount = msg_value - charge;',
         '  int recovered_amount = msg_value;', RECOVERED_TEST),
    Case('charge-is-nothing', 'the recovery costs the bounce nothing', RECOVERY,
         '  return get_compute_fee(0, bounce_gas_ceiling);', '  return 0;', RECOVERED_TEST),
    # The threshold's own case is not here: `bounce_dust_boundary` is a
    # crosscheck test and this battery runs the contract sandboxes, so naming
    # it would report WRONG-TEST forever. It is covered by
    # `mutations-recovery-charge.py`, which runs that suite.
    Case('handler-no-liability', 'recovered money is not owed again', POOL,
         '  native_liability = native_liability + recovered_amount;',
         '  native_liability = native_liability;', RECOVERED_TEST),
    Case('handler-no-note', 'the recovery appends nothing', POOL,
         '  (frontier, commitment_root) =\n    frontier_append(frontier, leaf_index, note_commitment(note_body, leaf_index));\n',
         '', RECOVERED_TEST),
    Case('handler-unauthenticated', 'the bounce is accepted before it is authenticated', POOL,
         '  recovery_require_authentic(sender, query_id, intent_digest, template_hash,\n                             recipient_hash, owner_commitment, recovery_data);\n',
         '', WRONG_ADDRESS_TEST),
    Case('handler-not-a-payout', 'a bounce with no envelope is parsed as one anyway', POOL,
         '  if (body.preload_uint(32) != recovery_envelope_tag()) {\n    return ();\n  }\n',
         '', RESERVE_TEST),
    Case('handler-empty-bounce', 'a bounce with no body at all is parsed', POOL,
         '  if (body.slice_bits() < 32) {\n    return ();\n  }\n', '', RESERVE_TEST),
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
