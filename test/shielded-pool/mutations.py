#!/usr/bin/env python3
"""Remove one rule at a time from the shielded note/tree library and require the
sandbox suite to report it, by name.

A mutation that turns the wrong test red is not evidence for the one it was
aimed at, so each case names the test that must fail. A mutation that fails to
compile is not evidence at all.

Usage: mutations.py [--only NAME ...]
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import sys

from toolchain import toolchain_root

ROOT = Path(__file__).resolve().parents[2]

NOTES = ROOT / 'crypto/smartcont/shielded/notes.fc'
TREE = ROOT / 'crypto/smartcont/shielded/tree.fc'
CONTRACTS = ROOT / 'tosctl/src/node-control/contracts'


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str


CASES = [
    Case('domain-swap', 'the owner commitment borrows another structure\'s domain', NOTES,
         'return h7(domain_owner_commitment(),',
         'return h7(domain_note_body(),',
         'each_commitment_matches_the_profile_and_binds_every_argument'),
    Case('padding', 'one padding lane is no longer zero', NOTES,
         'return h7(domain_note_commitment(), note_body_commitment, leaf_index, 0, 0, 0, 0, 0);',
         'return h7(domain_note_commitment(), note_body_commitment, leaf_index, 1, 0, 0, 0, 0);',
         'each_commitment_matches_the_profile_and_binds_every_argument'),
    Case('argument-order', 'the nullifier takes its two arguments the other way round', NOTES,
         'return h7(domain_nullifier(), note_body_commitment, owner_nf_key, 0, 0, 0, 0, 0);',
         'return h7(domain_nullifier(), owner_nf_key, note_body_commitment, 0, 0, 0, 0, 0);',
         'each_commitment_matches_the_profile_and_binds_every_argument'),
    Case('reduction', 'hashing into the field stops reducing', NOTES,
         'return digest % field_modulus();', 'return digest;',
         'hashing_into_the_field_is_a_reduction_and_only_a_reduction'),
    Case('empty-ladder', 'the empty-subtree ladder is read one level off', TREE,
         'if (level == 5) { return empty_root_5(); }',
         'if (level == 5) { return empty_root_6(); }',
         'the_generated_empty_root_ladder_is_what_the_permutation_produces'),
    Case('stale-slot', 'a stale frontier slot is read instead of the empty root', TREE,
         'int c6 = digit == 6 ? carry : empty;',
         'int c6 = digit == 6 ? carry : v6;',
         'the_frontier_agrees_with_rebuilding_the_whole_tree'),
    Case('tail-slot', 'the seventh slot of a level is not persisted', TREE,
         'cell third = begin_cell().store_uint(v.at(6), 256).end_cell();',
         'cell third = begin_cell().store_uint(0, 256).end_cell();',
         'the_frontier_agrees_with_rebuilding_the_whole_tree'),
    Case('genesis-levels', 'the store a pool is deployed with is a level short', TREE,
         """  cell chain = null();
  int level = tree_depth() - 1;
  while (level >= 0) {
    chain = frontier_level_build(zeros, chain, level == (tree_depth() - 1));
""",
         """  cell chain = null();
  int level = tree_depth() - 2;
  while (level >= 0) {
    chain = frontier_level_build(zeros, chain, level == (tree_depth() - 2));
""",
         'the_frontier_agrees_with_rebuilding_the_whole_tree'),
    Case('capacity', 'the exhausted-tree sentinel is not checked', TREE,
         '  throw_unless(92, index < commitment_capacity());\n', '',
         'the_capacity_sentinel_is_refused'),
]


def run_suite() -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env['PATH'] = str(Path.home() / '.cargo/bin') + os.pathsep + env.get('PATH', '')
    env['CARGO_TERM_COLOR'] = 'never'
    env.setdefault('TOS_ROOT', str(toolchain_root(ROOT)))
    return subprocess.run(['cargo', 'test', '--test', 'shielded_notes_sandbox'],
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
            print(f'{case.name:16} {case.why:58} {verdict}', flush=True)
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
