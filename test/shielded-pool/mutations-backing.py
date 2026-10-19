#!/usr/bin/env python3
"""Take the backing invariant back to what it was, and require a named test
to notice.

`balance >= liability + reserve_floor` can be asked of the balance the
contract sees or of the balance the transaction leaves. They are the same
number everywhere with headroom, which is why every backing test in this tree
passed under both readings and none of them told the two apart. They differ in
a band one compute fee wide, just under the floor.

So the cases here are all one shape: put the pre-fee reading back, and require
`backing_at_the_floor` to go red. Each has to fail by its own name -- a case
that turns some other test red is not evidence about the one it was aimed at.

Run it alone. It edits the contract in place and restores it, so a second
battery running at the same time would be building a tree nobody meant.
"""
from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from toolchain import toolchain_root  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
POOL = ROOT / 'crypto/smartcont/tos-shielded-pool-v1.fc'
CROSSCHECK = ROOT / 'tools/shielded-pool-circuit/crosscheck'

FLOOR_TEST = 'a_pool_just_under_its_floor_refuses_a_deposit_it_could_not_back'
CONTROL_TEST = 'a_pool_above_its_floor_still_takes_deposits'


@dataclass
class Case:
    name: str
    why: str
    before: str
    after: str
    expect: str


CASES = [
    # The deposit path, which is the one the test reaches.
    Case('deposit-pre-fee',
         'the deposit checks the balance it can see, not the one it leaves',
         '  throw_unless(204,\n'
         '    balance - get_compute_fee(0, deposit_gas_ceiling()) >= new_liability + reserve_floor);',
         '  throw_unless(204, balance >= new_liability + reserve_floor);',
         FLOOR_TEST),
    # There is deliberately no `raw_reserve` case for these paths.
    #
    # One was written, and it survived. That is the right answer: the check
    # above subtracts the *ceiling* fee, and the executor can only charge the
    # gas actually used, which `set_gas_limit` holds at or below that ceiling.
    # So a balance that passes the check cannot fail a later reservation, and
    # a reservation added beside it can never fire.
    #
    # A guard no input reaches is decoration, so the reservations were removed
    # rather than kept with a case that could not kill them. The withdrawal
    # path keeps its own, where it is load-bearing for a different reason: it
    # runs before `send_raw_message`, so the payout cannot spend what backs
    # the notes.
    # And the control, so a mutation that simply breaks deposits everywhere is
    # not mistaken for one that found the band.
    Case('deposit-always-refuse',
         'every deposit is refused, which is not what the floor check means',
         '  throw_unless(204,\n'
         '    balance - get_compute_fee(0, deposit_gas_ceiling()) >= new_liability + reserve_floor);',
         '  throw_unless(204, 0);',
         CONTROL_TEST),
]


def run_suite() -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env['PATH'] = str(Path.home() / '.cargo/bin') + os.pathsep + env.get('PATH', '')
    env['CARGO_TERM_COLOR'] = 'never'
    env.setdefault('TOS_ROOT', str(toolchain_root(ROOT)))
    return subprocess.run(
        ['cargo', 'test', '--release', '--no-fail-fast',
         '--test', 'backing_at_the_floor', '--', '--test-threads=1'],
        cwd=CROSSCHECK, capture_output=True, text=True, timeout=3600, env=env)


def failed_tests(output: str) -> set[str]:
    return set(re.findall(r'^test (\S+) \.\.\. FAILED$', output, flags=re.M))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--only', nargs='*', default=None)
    options = parser.parse_args()
    cases = CASES if options.only is None else [c for c in CASES if c.name in options.only]
    if options.only and len(cases) != len(options.only):
        raise SystemExit(f'unknown case name in {options.only}')

    source = POOL.read_text()
    for case in cases:
        count = source.count(case.before)
        if count != 1:
            raise SystemExit(f'{case.name}: anchor appears {count} times, expected once')

    baseline = run_suite()
    blob = baseline.stdout + baseline.stderr
    if 'error[' in blob or 'could not compile' in blob:
        raise SystemExit('the tree does not build before any mutation:\n' + blob[-3000:])
    if baseline.returncode:
        raise SystemExit('the suite is not green before any mutation:\n' + blob[-3000:])
    print('baseline green', flush=True)

    survivors = []
    try:
        for case in cases:
            POOL.write_text(source.replace(case.before, case.after))
            result = run_suite()
            output = result.stdout + result.stderr
            failed = failed_tests(output)
            if 'error[' in output or 'could not compile' in output:
                verdict = 'DID NOT COMPILE'
            elif case.expect in failed:
                verdict = 'killed'
            elif failed:
                verdict = f'WRONG TEST ({", ".join(sorted(failed))})'
            else:
                verdict = 'SURVIVED'
            print(f'{case.name:<24} {case.why:<62} {verdict}', flush=True)
            if verdict != 'killed':
                survivors.append(f'{case.name}: {verdict}')
    finally:
        POOL.write_text(source)

    again = run_suite()
    if again.returncode:
        raise SystemExit('the suite did not come back green:\n'
                         + (again.stdout + again.stderr)[-3000:])
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
