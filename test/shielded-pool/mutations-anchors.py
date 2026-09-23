#!/usr/bin/env python3
"""Remove one rule at a time from the anchor policy and the execution-domain
library, and require the sandbox suite to report it, by name.

A mutation that turns the wrong test red is not evidence for the one it was
aimed at, so each case names the test that must fail. A mutation that fails to
compile is not evidence at all: every replacement below still compiles and
still runs, it is simply wrong.

Usage: mutations-anchors.py [--only NAME ...]
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
ANCHORS = ROOT / 'crypto/smartcont/shielded/anchors.fc'
DOMAIN = ROOT / 'crypto/smartcont/shielded/domain.fc'
CONTRACTS = ROOT / 'tosctl/src/node-control/contracts'
SUITE = 'shielded_anchors_sandbox'

EXEC_TEST = 'the_execution_domain_is_the_profiles_preimage_over_this_account'
ADDR_TEST = 'a_recipient_hash_is_only_defined_for_a_workchain_zero_std_address'
VERSION_TEST = 'preserving_writes_the_pre_transaction_root_under_its_own_version'
EPOCH_TEST = 'the_epoch_checkpoint_keeps_the_root_that_opened_the_epoch'
ACCEPT_TEST = 'an_anchor_is_accepted_only_on_an_exact_match'
CAPACITY_TEST = 'an_exhausted_tree_has_no_version_left_to_preserve'
SHAPE_TEST = 'a_store_that_is_not_the_frozen_shape_is_refused'


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str


CASES = [
    # Section 8: the execution domain preimage, field by field.
    Case('exec-global-id', 'the chain id leaves the execution domain preimage', DOMAIN,
         '      begin_cell().store_int(global_id(), 32).end_cell().begin_parse(),',
         '      begin_cell().store_int(0, 32).end_cell().begin_parse(),', EXEC_TEST),
    Case('exec-account', 'the pool account leaves the preimage', DOMAIN,
         '      begin_cell().store_uint(pool, 256).end_cell().begin_parse(),',
         '      begin_cell().store_uint(0, 256).end_cell().begin_parse(),', EXEC_TEST),
    Case('exec-suffix', 'the trailing uint16 is no longer one', DOMAIN,
         '      begin_cell().store_uint(1, 16).end_cell().begin_parse()));',
         '      begin_cell().store_uint(2, 16).end_cell().begin_parse()));', EXEC_TEST),
    Case('exec-prefix', 'the execution domain borrows the recipient tag', DOMAIN,
         '      "TOS-SHIELDED-EXEC-v1",', '      "TOS-SHIELDED-RECIPIENT-v1",', EXEC_TEST),
    Case('exec-reduction', 'the digest is no longer brought into the field', DOMAIN,
         'int execution_domain() inline_ref {\n  int pool = std_account_id(my_address());\n  return reduce_to_field(',
         'int execution_domain() inline_ref {\n  int pool = std_account_id(my_address());\n  return (',
         EXEC_TEST),
    Case('recipient-prefix', 'the recipient hash borrows the execution tag', DOMAIN,
         '      "TOS-SHIELDED-RECIPIENT-v1",', '      "TOS-SHIELDED-EXEC-v1",', ADDR_TEST),

    # Section 8: what counts as a recipient address.
    Case('address-workchain', 'any workchain is accepted as a recipient', DOMAIN,
         '  throw_unless(170, (tag == 2) & (anycast == 0) & (workchain == 0)\n                    & address.slice_empty?());',
         '  throw_unless(170, (tag == 2) & (anycast == 0) & (workchain >= -128)\n                    & address.slice_empty?());',
         ADDR_TEST),
    Case('address-anycast', 'an anycast address is accepted', DOMAIN,
         '  throw_unless(170, (tag == 2) & (anycast == 0) & (workchain == 0)',
         '  throw_unless(170, (tag == 2) & (anycast >= 0) & (workchain == 0)', ADDR_TEST),
    Case('address-trailing', 'trailing bits after the address are ignored', DOMAIN,
         '                    & address.slice_empty?());', '                    & 1);', ADDR_TEST),

    # Section 6.1: which root, under which version.
    Case('preserve-version', 'the version preserved is the one after the append', ANCHORS,
         '  int root_version = commitment_next_index;',
         '  int root_version = commitment_next_index + 1;', VERSION_TEST),
    Case('preserve-slot', 'the ring is addressed by the wrong modulus', ANCHORS,
         '                                    root_version % recent_root_slots(),',
         '                                    root_version % 2048,', VERSION_TEST),
    Case('preserve-capacity', 'the exhausted tree is no longer refused', ANCHORS,
         '  throw_unless(156, commitment_next_index < commitment_capacity_32());\n', '',
         CAPACITY_TEST),

    # Section 6.2: when a checkpoint is written.
    Case('epoch-every-time', 'a checkpoint is written for every mutation', ANCHORS,
         '  if ((last_anchor_epoch == anchor_epoch_none()) | (epoch > last_anchor_epoch)) {',
         '  if (1) {', EPOCH_TEST),
    Case('epoch-sentinel', 'the genesis sentinel is compared by ordering', ANCHORS,
         '  if ((last_anchor_epoch == anchor_epoch_none()) | (epoch > last_anchor_epoch)) {',
         '  if (epoch > last_anchor_epoch) {', VERSION_TEST),
    Case('epoch-seconds', 'an epoch is no longer thirty seconds', ANCHORS,
         'int anchor_epoch_seconds() asm "30 PUSHINT";',
         'int anchor_epoch_seconds() asm "60 PUSHINT";', EPOCH_TEST),

    # Section 6.3 and acceptance.
    Case('current-id', 'a current anchor may carry any id', ANCHORS,
         '    throw_unless(152, (id == 0) & (root == commitment_root));',
         '    throw_unless(152, (root == commitment_root));', ACCEPT_TEST),
    Case('current-root', 'a current anchor is not compared to the current root', ANCHORS,
         '    throw_unless(152, (id == 0) & (root == commitment_root));',
         '    throw_unless(152, (id == 0));', ACCEPT_TEST),
    Case('recent-id', 'occupying the slot is enough, the version is not compared', ANCHORS,
         '    throw_unless(153, (stored_id == id) & (stored_root == root));',
         '    throw_unless(153, (stored_root == root));', ACCEPT_TEST),
    Case('recent-root', 'occupying the slot is enough, the root is not compared', ANCHORS,
         '    throw_unless(153, (stored_id == id) & (stored_root == root));',
         '    throw_unless(153, (stored_id == id));', ACCEPT_TEST),
    Case('epoch-pair', 'an epoch slot is not compared to the supplied pair', ANCHORS,
         '    throw_unless(154, (stored_id == id) & (stored_root == root));',
         '    throw_unless(154, found);', ACCEPT_TEST),
    Case('epoch-retention', 'an epoch anchor never goes stale', ANCHORS,
         '    throw_unless(155, current_epoch - id < anchor_epoch_slots());\n', '',
         ACCEPT_TEST),
    Case('unknown-kind', 'an unknown anchor kind falls through as valid', ANCHORS,
         '  throw(151);', '  return ();', ACCEPT_TEST),

    # Section 13.1: the store shape.
    Case('store-shape', 'the anchor store shape is not enforced', ANCHORS,
         '  throw_unless(150, (s.slice_bits() == 0) & (s.slice_refs() == 2));',
         '  throw_unless(150, s.slice_refs() >= 1);', SHAPE_TEST),
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
