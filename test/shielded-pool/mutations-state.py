#!/usr/bin/env python3
"""Remove one rule at a time from the persistent-state library and require the
sandbox suite to report it, by name.

A mutation that turns the wrong test red is not evidence for the one it was
aimed at, so each case names the test that must fail. A mutation that fails to
compile is not evidence at all: every replacement below still compiles and
still runs, it is simply wrong.

Usage: mutations-state.py [--only NAME ...]
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

STATE = ROOT / 'crypto/smartcont/shielded/state.fc'
CONTRACTS = ROOT / 'tosctl/src/node-control/contracts'
SUITE = 'shielded_state_sandbox'

GENESIS_TEST = 'genesis_is_the_state_section_13_2_describes'
SHAPE_TEST = 'a_state_root_that_is_not_the_frozen_shape_is_refused'
COUNTER_TEST = 'a_counter_above_the_sentinel_is_not_a_state'
CONFIG_TEST = 'the_config_is_revalidated_rather_than_trusted'
VK_TEST = 'the_verifying_key_chain_is_the_frozen_shape'
REFUSE_TEST = 'genesis_refuses_a_configuration_it_would_have_to_live_with'
FRONTIER_TEST = 'a_state_without_a_frontier_is_refused'


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str


CASES = [
    # The one that is not about a rule but about the language: a function that
    # only throws has no used result, so FunC may drop the call entirely unless
    # it is impure. That is how the genesis validation was silently skipped the
    # first time this was written.
    Case('config-parse-purity', 'the config parser is no longer impure, so its call is dropped',
         STATE,
         '(int, int, int, int, int, cell) config_parse(cell config) impure inline_ref {',
         '(int, int, int, int, int, cell) config_parse(cell config) inline_ref {',
         REFUSE_TEST),

    # A level chain always has a root cell, so an absent frontier is not a
    # state this contract can have written. Without the refusal it is read as
    # a null and the failure moves to whatever touches it first.
    Case('frontier-absent', 'a state with no frontier is parsed anyway', STATE,
         '  throw_if(181, cell_null?(frontier));\n',
         '',
         FRONTIER_TEST),

    # Section 13: the state root.
    Case('magic', 'any magic is accepted', STATE,
         '  throw_unless(180, s~load_uint(32) == state_magic());',
         '  s~load_uint(32);', SHAPE_TEST),
    Case('version', 'any version is accepted', STATE,
         '  throw_unless(180, s~load_uint(16) == state_version());',
         '  s~load_uint(16);', SHAPE_TEST),
    Case('state-trailing', 'trailing bits after the state fields are ignored', STATE,
         '  throw_unless(181, s.slice_empty?());\n\n  throw_unless(182, commitment_next_index',
         '  throw_unless(182, commitment_next_index', SHAPE_TEST),
    Case('state-refs', 'a state root may carry any number of references', STATE,
         '  throw_unless(181, s.slice_refs() == 4);',
         '  throw_unless(181, s.slice_refs() >= 3);', SHAPE_TEST),
    Case('index-sentinel', 'a counter past the exhausted sentinel is accepted', STATE,
         '  throw_unless(182, commitment_next_index <= index_sentinel());\n  throw_unless(182, nullifier_next_index <= index_sentinel());\n\n  return (commitment_root',
         '  return (commitment_root', COUNTER_TEST),

    # Section 13.1: the config store.
    Case('config-refs', 'a config store with no denominations is not refused here', STATE,
         '  throw_unless(183, s.slice_refs() == 1);',
         '  throw_unless(183, s.slice_refs() >= 0);', CONFIG_TEST),
    Case('config-trailing', 'trailing bits after the config fields are ignored', STATE,
         '  cell denominations = s~load_ref();\n  throw_unless(183, s.slice_empty?());',
         '  cell denominations = s~load_ref();', CONFIG_TEST),
    Case('fee-positive', 'a zero withdrawal fee is accepted', STATE,
         '  throw_unless(184, withdrawal_fee > 0);',
         '  throw_unless(184, withdrawal_fee >= 0);', CONFIG_TEST),
    Case('denom-count', 'the denomination count is unbounded', STATE,
         '  throw_unless(185, (count > 0) & (count <= max_denominations()));',
         '  throw_unless(185, count >= 0);', CONFIG_TEST),
    Case('denom-positive', 'a zero denomination is accepted', STATE,
         '    throw_unless(187, amount > 0);', '    throw_unless(187, amount >= 0);', CONFIG_TEST),
    Case('denom-sorted', 'equal denominations are accepted', STATE,
         '    throw_unless(188, amount > previous);',
         '    throw_unless(188, amount >= previous);', CONFIG_TEST),
    Case('denom-chain-end', 'a chain longer than its count is accepted', STATE,
         '    throw_unless(186, s.slice_empty?());',
         '    throw_unless(186, s.slice_bits() == 0);', CONFIG_TEST),

    # Section 13.1: the verifying key.
    Case('vk-bits', 'a verifying-key cell may hold any number of bits', STATE,
         '    throw_unless(189, s.slice_bits() == expected_bits);',
         '    throw_unless(189, s.slice_bits() >= 0);', VK_TEST),
    Case('vk-refs', 'a verifying-key cell may carry any references', STATE,
         '    throw_unless(189, s.slice_refs() == (final? ? 0 : 1));',
         '    throw_unless(189, s.slice_refs() >= 0);', VK_TEST),
    Case('vk-length', 'the verifying key is one cell shorter', STATE,
         'int vk_full_chunks() asm "9 PUSHINT";', 'int vk_full_chunks() asm "8 PUSHINT";', VK_TEST),

    # Section 13.2: genesis.
    Case('genesis-nullifier-index', 'the nullifier counter starts at zero', STATE,
         '    nullifier_genesis_root, 1,', '    nullifier_genesis_root, 0,', GENESIS_TEST),
    Case('genesis-epoch', 'the epoch sentinel is not written at genesis', STATE,
         '    anchor_epoch_none(), 0, reserve_floor,', '    0, 0, reserve_floor,', GENESIS_TEST),
    Case('genesis-reserve', 'a zero reserve floor is accepted at genesis', STATE,
         '  throw_unless(184, reserve_floor > 0);', '  throw_unless(184, reserve_floor >= 0);',
         REFUSE_TEST),
    Case('genesis-vk', 'genesis no longer checks the verifying key', STATE,
         '  vk_require_canonical(vk);\n', '', REFUSE_TEST),
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
