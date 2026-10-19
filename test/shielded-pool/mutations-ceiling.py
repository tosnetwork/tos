#!/usr/bin/env python3
"""Break the derivation, and require the test that derives to notice.

`gas_ceiling_bound` claims something no measurement can: that no legal path,
at any age of the pool, at any leaf index, against any anchor, for any
denomination, in either nullifier order, can cost more than the number beside
each ceiling. The claim rests on three things, and each has a case here.

  * the ceilings are what section 14.1's rule gives for that bound, read as
    the equality the profile states. Moving one in either direction is a
    ceiling nobody derived;
  * the bound is the measurement plus the spans, so the spans have to be
    added. A sum that ignores them is the sampled maximum again wearing the
    word bound;
  * the twelve-level append is composed from per-level terms, which is only
    legitimate while the levels are independent. A level that reads more than
    its own digit breaks the composition, and the additivity check is what
    catches it.

Two mutations that were written and are NOT here, because they survive and
saying why is more useful than a case that cannot fail:

  * pricing the nullifier insert in one order rather than both. That whole
    domain is worth 300 gas out of 1.2 million, and section 14.1's rule
    rounds to ten thousand, so removing it moves no ceiling. The degeneracy
    check in the test is what covers it instead: a sweep reduced to a single
    point reports `worst == best` and is caught there;
  * sampling the epoch ring's keys instead of walking them. Worth about 300
    gas for the same reason.

Both say the same thing: below the rule's resolution, a domain cannot be
defended by a ceiling assertion, only by an assertion about the sweep.

Run it alone. It edits three files in place and restores them, so a second
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
TREE = ROOT / 'crypto/smartcont/shielded/tree.fc'
CROSSCHECK = ROOT / 'tools/shielded-pool-circuit/crosscheck'
DERIVATION = CROSSCHECK / 'src/ceiling.rs'

BOUND_TEST = 'the_ceilings_cover_a_derived_upper_bound'


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str


CASES = [
    # --- the ceilings themselves ------------------------------------------
    Case('transact-ceiling-sampled',
         'the transact ceiling goes back to the sampled maximum',
         POOL,
         'int transact_gas_ceiling() asm "1510000 PUSHINT";',
         'int transact_gas_ceiling() asm "1470000 PUSHINT";', BOUND_TEST),
    Case('transact-ceiling-padded',
         'the transact ceiling is padded past what the rule gives',
         POOL,
         'int transact_gas_ceiling() asm "1510000 PUSHINT";',
         'int transact_gas_ceiling() asm "2000000 PUSHINT";', BOUND_TEST),
    Case('deposit-ceiling-sampled',
         'the deposit ceiling goes back to the sampled maximum',
         POOL,
         'int deposit_gas_ceiling() asm "230000 PUSHINT";',
         'int deposit_gas_ceiling() asm "220000 PUSHINT";', BOUND_TEST),
    Case('bounce-ceiling-sampled',
         'the bounce ceiling goes back to the sampled maximum',
         POOL,
         'int bounce_gas_ceiling() asm "240000 PUSHINT";',
         'int bounce_gas_ceiling() asm "220000 PUSHINT";', BOUND_TEST),
    Case('topup-ceiling-padded',
         'the top-up ceiling is twice the rule\'s floor',
         POOL,
         'int topup_gas_ceiling() asm "10000 PUSHINT";',
         'int topup_gas_ceiling() asm "20000 PUSHINT";', BOUND_TEST),

    # --- the sum ----------------------------------------------------------
    Case('spans-not-added',
         'the bound is the measurement again, with the spans ignored',
         DERIVATION,
         '        self.calls * (self.worst - self.best)',
         '        0',
         BOUND_TEST),
    Case('preserve-domain-one-entry',
         'the anchor write is priced against rings that never fill',
         DERIVATION,
         '    for occupancy in 1..=RECENT_SLOTS {\n'
         '        store = anchors.extend_recent(store, occupancy - 1, occupancy)?;\n'
         '        let gas = probe.preserve_gas(&store, 0, far, now, now / 30 - 1)?;\n'
         '        worst = worst.max(gas);\n'
         '        best = best.min(gas);\n'
         '    }',
         '    for occupancy in 1..=1 {\n'
         '        store = anchors.extend_recent(store, occupancy - 1, occupancy)?;\n'
         '        let gas = probe.preserve_gas(&store, 0, far, now, now / 30 - 1)?;\n'
         '        worst = worst.max(gas);\n'
         '        best = best.min(gas);\n'
         '    }',
         BOUND_TEST),
    Case('append-composed-from-the-cheapest',
         'the append is composed from each level\'s cheapest digit',
         DERIVATION,
         '        let level_worst = row.iter().copied().max().unwrap_or(zero) - zero;',
         '        let level_worst = row.iter().copied().min().unwrap_or(zero) - zero;',
         BOUND_TEST),

    # --- the composition's premise ----------------------------------------
    #
    # A level that reads its neighbour's digit as well as its own. The tree
    # it builds is the same tree -- the burn loop computes nothing -- so
    # every correctness test stays green and only the additivity check can
    # see it. The product of two digits is what makes it non-separable: a
    # sum or a shift of one digit would still compose.
    Case('append-not-separable',
         'a level\'s cost depends on more than its own digit',
         TREE,
         '    int digit = (index / stride) % tree_arity();\n'
         '    int empty = empty_root_at(level);',
         '    int digit = (index / stride) % tree_arity();\n'
         '    int burn = digit * ((index / (stride * tree_arity())) % tree_arity());\n'
         '    while (burn > 0) { burn = burn - 1; }\n'
         '    int empty = empty_root_at(level);',
         BOUND_TEST),
]


def run_suite() -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env['PATH'] = str(Path.home() / '.cargo/bin') + os.pathsep + env.get('PATH', '')
    env['CARGO_TERM_COLOR'] = 'never'
    env.setdefault('TOS_ROOT', str(toolchain_root(ROOT)))
    return subprocess.run(
        ['cargo', 'test', '--release', '--no-fail-fast',
         '--test', 'gas_ceiling_bound', '--', '--test-threads=1'],
        cwd=CROSSCHECK, capture_output=True, text=True, timeout=7200, env=env)


def failed_tests(output: str) -> set[str]:
    return set(re.findall(r'^test (\S+) \.\.\. FAILED$', output, flags=re.M))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--only', nargs='*', default=None)
    options = parser.parse_args()
    cases = CASES if options.only is None else [c for c in CASES if c.name in options.only]
    if options.only and len(cases) != len(options.only):
        raise SystemExit(f'unknown case name in {options.only}')

    sources = {path: path.read_text() for path in {c.path for c in cases}}
    for case in cases:
        count = sources[case.path].count(case.before)
        if count != 1:
            raise SystemExit(f'{case.name}: anchor appears {count} times in '
                             f'{case.path.name}, expected once')

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
            case.path.write_text(sources[case.path].replace(case.before, case.after))
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
            print(f'{case.name:<34} {case.why:<58} {verdict}', flush=True)
            if verdict != 'killed':
                survivors.append(f'{case.name}: {verdict}')
            case.path.write_text(sources[case.path])
    finally:
        for path, text in sources.items():
            path.write_text(text)

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
