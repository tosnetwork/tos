#!/usr/bin/env python3
"""Remove one rule at a time from the withdrawal payout library and require the
sandbox suite to report it, by name.

A mutation that turns the wrong test red is not evidence for the one it was
aimed at, so each case names the test that must fail. A mutation that fails to
compile is not evidence at all: every replacement below still compiles and
still runs, it is simply wrong.

Usage: mutations-payout.py [--only NAME ...]
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
PAYOUT = ROOT / 'crypto/smartcont/shielded/payout.fc'
CONTRACTS = ROOT / 'tosctl/src/node-control/contracts'
SUITE = 'shielded_payout_sandbox'

RECORD_TEST = 'the_record_has_the_shape_section_15_2_fixes'
QUERY_TEST = 'the_query_id_is_the_low_half_of_the_intent_digest'
MESSAGE_TEST = 'the_message_is_bouncable_and_asks_for_the_full_original_body'
NOBODY_TEST = 'a_payout_to_nobody_is_refused'
FEE_TEST = 'the_fee_must_cover_the_message_and_not_the_recovery'
LIABILITY_TEST = 'a_payout_never_discharges_more_liability_than_there_is'
CHARGED_TEST = 'the_computed_forward_fee_is_the_fee_the_chain_charges'


@dataclass
class Case:
    name: str
    why: str
    before: str
    after: str
    expect: str


CASES = [
    # Section 15.2's split. Four field elements do not fit one cell, and the
    # profile says where the fourth goes.
    Case('record-order', 'the record root carries the fields in another order',
         '    .store_uint(intent_digest, 256)\n    .store_uint(recovery_template_hash, 256)',
         '    .store_uint(recovery_template_hash, 256)\n    .store_uint(intent_digest, 256)',
         RECORD_TEST),
    Case('record-owner', 'the owner commitment is not in the tail',
         '  cell tail = begin_cell()\n    .store_uint(recovery_owner_commitment, 256)',
         '  cell tail = begin_cell()\n    .store_uint(0, 256)', RECORD_TEST),
    Case('record-payload', 'the tail carries no payload at all',
         '    .store_ref(recovery_data)\n    .end_cell();',
         '    .store_ref(begin_cell().end_cell())\n    .end_cell();', RECORD_TEST),

    # Section 15.3 step 4: the reply names the intent it answers.
    Case('query-whole-digest', 'the query id is the whole digest rather than its low half',
         '  return intent_digest % 18446744073709551616;', '  return intent_digest;',
         QUERY_TEST),
    Case('body-op', 'the outbound operation is not zero',
         '    .store_uint(payout_op(), 32)', '    .store_uint(1, 32)', QUERY_TEST),

    # The two bits that make recovery possible at all.
    Case('bounce-flags-none', 'the payout asks for no rich bounce',
         'int payout_bounce_flags() asm "3 PUSHINT";',
         'int payout_bounce_flags() asm "0 PUSHINT";', MESSAGE_TEST),
    Case('bounce-flags-bits-only', 'the payout asks for a bounce without the full body',
         'int payout_bounce_flags() asm "3 PUSHINT";',
         'int payout_bounce_flags() asm "1 PUSHINT";', MESSAGE_TEST),
    Case('not-bouncable', 'the payout is sent unbouncable, so a failure keeps the money',
         '    .store_uint(0x18, 6)                   ;; int_msg_info, ihr disabled, bounce',
         '    .store_uint(0x10, 6)                   ;; int_msg_info, ihr disabled, bounce',
         MESSAGE_TEST),
    Case('payout-nobody', 'a payout to addr_none is built',
         '  throw_if(245, recipient.preload_uint(2) == 0);\n', '', NOBODY_TEST),

    # Section 14.2.
    Case('fee-not-config', 'the fee on the wire need not be the configured one',
         '  throw_unless(242, withdrawal_fee == config_withdrawal_fee);\n', '', FEE_TEST),
    Case('fee-no-forward', 'the fee need not cover forwarding the message',
         '  throw_unless(243, withdrawal_fee >= payout_forward_fee(body));',
         '  throw_unless(243, withdrawal_fee >= 0);', FEE_TEST),
    # The term that was taken out. Putting it back is not a bug the contract
    # can detect -- the configured fee still clears the larger floor today --
    # but it is the regression this change exists to prevent, and the test
    # says so by pinning the boundary to the forward fee exactly.
    Case('fee-recovery-again', 'the floor pre-pays a whole bounded recovery again',
         '  throw_unless(243, withdrawal_fee >= payout_forward_fee(body));',
         '  throw_unless(243,\n    withdrawal_fee >= payout_forward_fee(body) '
         '+ get_compute_fee(0, 240000));', FEE_TEST),
    Case('forward-fee-cells', 'the forward fee ignores how many cells the message has',
         '  return get_forward_fee(0, bits, cells);', '  return get_forward_fee(0, bits, 0);',
         CHARGED_TEST),
    Case('forward-fee-bits', 'the forward fee ignores how many bits the message has',
         '  return get_forward_fee(0, bits, cells);', '  return get_forward_fee(0, 0, cells);',
         CHARGED_TEST),

    # Section 16.2 step 16's arithmetic.
    Case('liability-no-fee', 'the fee does not leave with the payout',
         '  return native_liability - public_amount_out - withdrawal_fee;',
         '  return native_liability - public_amount_out;', LIABILITY_TEST),
    Case('liability-underflow', 'a payout may discharge liability the pool does not have',
         '  throw_unless(244, native_liability >= public_amount_out + withdrawal_fee);\n', '',
         LIABILITY_TEST),
    Case('liability-off-by-one', 'the bound is strict where it should not be',
         '  throw_unless(244, native_liability >= public_amount_out + withdrawal_fee);',
         '  throw_unless(244, native_liability > public_amount_out + withdrawal_fee);',
         LIABILITY_TEST),
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
        original = PAYOUT.read_text()
        count = original.count(case.before)
        if count != 1:
            raise SystemExit(f'{case.name}: anchor appears {count} times, expected once')
        try:
            PAYOUT.write_text(original.replace(case.before, case.after))
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
            PAYOUT.write_text(original)

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
