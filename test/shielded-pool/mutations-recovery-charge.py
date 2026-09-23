#!/usr/bin/env python3
"""Weaken section 15.4's recovery charge and require the crosscheck suite to
report it, by name.

Every other battery here runs the contract sandboxes under
`tosctl/src/node-control/contracts`. The evidence that the recovery charges
itself does not live there: it is a whole message cascade -- pay out, refuse,
bounce, recover -- so it lives in the crosscheck suite, which until now had no
mutation coverage at all. A check nobody can break on purpose is a check
nobody has tested.

Two tests carry it and they are aimed at different halves:

* `a_withdrawal_that_is_refused_comes_back_as_a_note` pins the arithmetic --
  the note is the bounced value less exactly what the contract quotes;
* `the_smallest_recoverable_bounce_is_measured_rather_than_assumed` pins the
  threshold -- the smallest bounce that mints anything is one nanotos above
  the charge, so the charge is what binds rather than the pre-ACCEPT
  authentication.

The suite is slow: the dust boundary bisects a whole withdrawal cascade per
step, about fifty seconds. A full run is a few minutes.

Usage: mutations-recovery-charge.py [--only NAME ...]
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from toolchain import toolchain_root

ROOT = Path(__file__).resolve().parents[2]
CROSSCHECK = ROOT / 'tools/shielded-pool-circuit/crosscheck'
POOL = ROOT / 'crypto/smartcont/tos-shielded-pool-v1.fc'
RECOVERY = ROOT / 'crypto/smartcont/shielded/recovery.fc'

ARITHMETIC = 'a_withdrawal_that_is_refused_comes_back_as_a_note'
THRESHOLD = 'the_smallest_recoverable_bounce_is_measured_rather_than_assumed'


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str


CASES = [
    # The charge itself.
    Case('charge-not-taken', 'the charge is quoted and not subtracted', POOL,
         '  int recovered_amount = msg_value - charge;',
         '  int recovered_amount = msg_value;', ARITHMETIC),
    Case('charge-is-zero', 'the recovery costs the bounce nothing', RECOVERY,
         '  return get_compute_fee(0, bounce_gas_ceiling);', '  return 0;', ARITHMETIC),
    # Not ARITHMETIC, and the reason is worth keeping. That test compares the
    # minted note against the charge the contract *quotes*, so a charge that
    # is wrong but self-consistent satisfies it -- the handler and the get
    # method are reading the same mutated function. What catches it is the
    # observable consequence: make the charge tiny and the pre-ACCEPT
    # authentication becomes the dearer of the two thresholds, so the boundary
    # stops being the charge plus one and the assertion says exactly that.
    Case('charge-is-flat', 'the charge ignores the bounce ceiling it is for', RECOVERY,
         '  return get_compute_fee(0, bounce_gas_ceiling);',
         '  return get_compute_fee(0, 1);', THRESHOLD),

    # The threshold below which nothing is minted. Each of these leaves the
    # arithmetic alone and moves only where the cliff is, so only the boundary
    # test can object.
    Case('threshold-at-zero', 'a bounce below the charge still mints', POOL,
         '  if (msg_value <= charge) {', '  if (msg_value == 0) {', THRESHOLD),
    Case('threshold-off-by-one', 'a bounce worth exactly the charge mints nothing extra', POOL,
         '  if (msg_value <= charge) {', '  if (msg_value < charge) {', THRESHOLD),

    # And the quote a wallet reads, which is what both tests ask the contract
    # for. A get method that disagreed with the handler would make both tests
    # agree with a lie.
    Case('quote-disagrees', 'the quoted charge is not the one the handler takes', POOL,
         '  return recovery_charge_at(bounce_gas_ceiling());',
         '  return recovery_charge_at(bounce_gas_ceiling()) + 1;', ARITHMETIC),
]


def run_suite() -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env['PATH'] = str(Path.home() / '.cargo/bin') + os.pathsep + env.get('PATH', '')
    env['CARGO_TERM_COLOR'] = 'never'
    env.setdefault('TOS_ROOT', str(toolchain_root(ROOT)))
    # `--no-fail-fast`, or the second suite never runs when the first goes red
    # and every case naming it comes back WRONG-TEST.
    return subprocess.run(
        ['cargo', 'test', '--release', '--no-fail-fast',
         '--test', 'withdrawal_round_trip', '--test', 'bounce_dust_boundary',
         '--', '--test-threads=2'],
        cwd=CROSSCHECK, capture_output=True, text=True, timeout=5400, env=env)


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
    blob = baseline.stdout + baseline.stderr
    if 'error[' in blob or 'could not compile' in blob:
        raise SystemExit('the crate does not build before any mutation:\n' + blob[-4000:])
    if baseline.returncode:
        raise SystemExit('the suite is not green before any mutation:\n' + blob[-4000:])
    print('baseline green', flush=True)

    problems = []
    for case in cases:
        original = case.path.read_text()
        count = original.count(case.before)
        if count != 1:
            raise SystemExit(f'{case.name}: anchor appears {count} times, expected once')
        try:
            case.path.write_text(original.replace(case.before, case.after))
            result = run_suite()
            output = result.stdout + result.stderr
            failures = failed_tests(output)
            if 'error[' in output or 'could not compile' in output:
                problems.append(f'{case.name}: no longer compiles, which is not evidence')
                verdict = 'UNCOMPILED'
            elif result.returncode == 0:
                problems.append(f'{case.name}: the suite stayed green')
                verdict = 'SURVIVED'
            elif case.expect not in failures:
                problems.append(f'{case.name}: failed as {sorted(failures)}, not {case.expect}')
                verdict = 'WRONG-TEST'
            else:
                verdict = 'killed'
            print(f'{case.name:22} {case.why:58} {verdict}', flush=True)
        finally:
            case.path.write_text(original)

    restored = run_suite()
    if restored.returncode:
        raise SystemExit('the suite did not come back green:\n'
                         + restored.stdout + restored.stderr)
    print('green again', flush=True)

    if problems:
        print('\nPROBLEMS:', file=sys.stderr)
        for line in problems:
            print('  ' + line, file=sys.stderr)
        return 1
    print(f'\n{len(cases)} mutations, all killed by the test they were aimed at')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
