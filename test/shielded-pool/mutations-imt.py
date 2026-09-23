#!/usr/bin/env python3
"""Remove one rule at a time from the nullifier indexed Merkle tree and require
the sandbox suite to report it, by name.

A mutation that turns the wrong test red is not evidence for the one it was
aimed at, so each case names the test that must fail. A mutation that fails to
compile is not evidence at all.

Every case edits only files inside this repository, and runs cargo inside this
repository, so a second checkout of the same tree is never the thing measured.

Usage: mutations-imt.py [--only NAME ...]
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
IMT = ROOT / 'crypto/smartcont/shielded/imt.fc'
# The path walk moved into POSEIDON2_PATH7 at global version 18. The two
# mutations that aimed at it had to move with it: a mutation whose anchor no
# longer exists is not a mutation that passed, and the suite says so by
# refusing to run.
VM = ROOT / 'tosctl/src/vm/src/executor/poseidon2.rs'
CONTRACTS = ROOT / 'tosctl/src/node-control/contracts'
SUITE = 'shielded_imt_sandbox'

LADDER = 'the_empty_ladder_and_the_genesis_root_are_what_the_permutation_produces'
LEAF = 'an_allocated_leaf_matches_the_profile_and_binds_every_argument'
SEQUENTIAL = 'two_sequential_nullifiers_both_insert_and_match_the_rebuilt_tree'
ZERO_NF = 'a_zero_nullifier_is_refused_by_the_head_sentinel'
SUCCESSOR = 'a_bad_successor_tuple_is_refused'
APPEND = 'a_non_empty_append_slot_is_refused'
REPLAY = 'duplicate_and_reordered_witnesses_fail'
UNALLOCATED = 'a_witness_that_names_an_unallocated_leaf_is_refused'
ENCODING = 'the_witness_encoding_is_rejected_unless_it_is_canonical'
ORDER = 'the_sibling_order_is_the_one_the_profile_froze'
CAPACITY = 'the_capacity_boundary_is_exactly_two_to_the_thirty_two'

LEAF_CALL = (
    '    h7(domain_imt_leaf(), value, next_index, next_value, 0, 0, 0, 0));'
)
APPEND_CHECK = """  throw_unless(120,
    imt_root_from_path(append_path, new_index, imt_unallocated_leaf()) == root1);"""


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str


CASES = [
    # Section 7.0: the zero-leaf sentinel. Unreachable through imt_leaf_hash --
    # which is exactly why it is a function of its own, and why these two
    # mutations are the only evidence that the guard is real.
    Case('sentinel-removed', 'the zero-leaf sentinel stops refusing zero', IMT,
         '  throw_if(121, leaf == imt_unallocated_leaf());\n  return leaf;',
         '  return leaf;',
         'an_allocated_leaf_hash_of_zero_is_refused_by_the_sentinel'),
    Case('sentinel-inverted', 'the zero-leaf sentinel refuses everything but zero', IMT,
         '  throw_if(121, leaf == imt_unallocated_leaf());',
         '  throw_if(121, leaf != imt_unallocated_leaf());',
         'an_allocated_leaf_hash_of_zero_is_refused_by_the_sentinel'),

    # Section 7: the leaf and node hashes.
    Case('leaf-domain', 'the leaf hash borrows the node domain', IMT,
         LEAF_CALL,
         '    h7(domain_imt_node(), value, next_index, next_value, 0, 0, 0, 0));',
         LEAF),
    Case('leaf-padding', 'one padding lane of the leaf hash is no longer zero', IMT,
         LEAF_CALL,
         '    h7(domain_imt_leaf(), value, next_index, next_value, 1, 0, 0, 0));',
         LEAF),
    Case('leaf-tuple-order', 'the leaf tuple is absorbed value-last', IMT,
         LEAF_CALL,
         '    h7(domain_imt_leaf(), next_value, next_index, value, 0, 0, 0, 0));',
         LEAF),
    Case('node-domain', 'the IMT node borrows the commitment tree domain', IMT,
         'return h7(domain_imt_node(), c0, c1, c2, c3, c4, c5, c6);',
         'return h7(domain_commit_node(), c0, c1, c2, c3, c4, c5, c6);',
         LADDER),

    # Section 7.0: the ladder, the unallocated leaf and the genesis root.
    Case('empty-ladder-short', 'the empty ladder stops one level early', IMT,
         '  while (step < level) {', '  while (step + 1 < level) {',
         LADDER),
    Case('unallocated-leaf', 'the unallocated leaf is no longer field zero', IMT,
         'int imt_unallocated_leaf() asm "0 PUSHINT";',
         'int imt_unallocated_leaf() asm "1 PUSHINT";',
         LADDER),
    Case('genesis-position', 'the head sentinel is inserted at child position 1', IMT,
         '    carry = imt_node(carry, empty, empty, empty, empty, empty, empty);',
         '    carry = imt_node(empty, carry, empty, empty, empty, empty, empty);',
         LADDER),
    Case('depth', 'the frozen depth becomes eleven', IMT,
         'int imt_depth() asm "12 PUSHINT";', 'int imt_depth() asm "11 PUSHINT";',
         LADDER),

    # Section 7.2: the path fold.
    Case('path-digit', 'the path digit ignores the level', VM,
         '            state[1 + slot] = if slot == usize::from(*digit) {',
         '            state[1 + slot] = if slot == usize::from(digits[0]) {',
         SEQUENTIAL),
    Case('sibling-order', 'two sibling positions are read the other way round', VM,
         '        let siblings = [first[0], first[1], first[2], second[0], second[1], second[2]];',
         '        let siblings = [first[0], first[2], first[1], second[0], second[1], second[2]];',
         ORDER),
    Case('arity', 'the frozen arity becomes six', VM,
         '        for slot in 0..7 {', '        for slot in 0..6 {',
         ORDER),

    # Section 7.2: the decoder, which now lives in POSEIDON2_PATH7. These four
    # aimed at the FunC reader until global version 18; the reader was deleted
    # with the walk rather than kept, because a mutation aimed at a check
    # nothing can reach survives, and a check nothing can reach looks tested.
    Case('path-cell-bits', 'a path cell may carry trailing bits', VM,
         '    if slice.remaining_bits() != 768 {',
         '    if slice.remaining_bits() < 768 {',
         ENCODING),
    Case('path-field-canonical', 'a path field is no longer required to be canonical', VM,
         '        if !poseidon2::is_canonical(element) {',
         '        if false {',
         ENCODING),
    Case('non-final-ref', 'a non-final path cell may carry extra references', VM,
         '    let expected = usize::from(!last);',
         '    let expected = slice.remaining_references();',
         ENCODING),
    Case('final-ref', 'the final path cell may carry a reference', VM,
         '    if slice.remaining_references() != expected {',
         '    if slice.remaining_references() < expected {',
         ENCODING),
    Case('witness-bits', 'the witness root may carry trailing bits', IMT,
         '  throw_unless(108, bits == imt_witness_bits());',
         '  throw_unless(108, bits >= imt_witness_bits());',
         ENCODING),
    Case('witness-refs', 'the witness root may carry extra references', IMT,
         '  throw_unless(109, refs == imt_witness_refs());',
         '  throw_unless(109, refs >= imt_witness_refs());',
         ENCODING),
    Case('low-index-width', 'the low index is decoded one bit short', IMT,
         '  int low_index = body~load_uint(32);', '  int low_index = body~load_uint(31);',
         SEQUENTIAL),
    Case('low-value-canonical', 'the low value is no longer required to be canonical', IMT,
         '  throw_unless(110, low_value < field_modulus());',
         '  throw_unless(110, low_value >= 0);',
         ENCODING),
    Case('low-next-value-canonical', 'the successor value may sit outside the field', IMT,
         '  throw_unless(111, low_next_value < field_modulus());',
         '  throw_unless(111, low_next_value >= 0);',
         ENCODING),
    Case('nullifier-canonical', 'the nullifier may sit outside the field', IMT,
         '  throw_unless(112, nf < field_modulus());', '  throw_unless(112, nf >= 0);',
         ENCODING),
    Case('low-index-allocated', 'a witness may name a leaf that was never allocated', IMT,
         '  throw_unless(113, low_index < nullifier_next_index);\n', '',
         UNALLOCATED),
    Case('low-next-index-allocated', 'a successor may point past the allocated range', IMT,
         """  if (low_next_index != 0) {
    throw_unless(114, low_next_index < nullifier_next_index);
  }
""",
         '',
         UNALLOCATED),

    # Section 7.1: the eight numbered steps.
    Case('membership', 'the low leaf no longer has to be in the current root', IMT,
         '  throw_unless(115, imt_root_from_path(low_path, low_index, low_leaf) == nullifier_root);',
         '  throw_unless(115, imt_root_from_path(low_path, low_index, low_leaf) >= 0);',
         REPLAY),
    Case('low-ordering', 'the low leaf may equal the nullifier', IMT,
         '  throw_unless(116, low_value < nf);', '  throw_unless(116, low_value <= nf);',
         ZERO_NF),
    Case('bracket-tail', 'a tail leaf may still carry a successor value', IMT,
         '  int bracketed = (low_next_index == 0) & (low_next_value == 0);',
         '  int bracketed = (low_next_index == 0);',
         SUCCESSOR),
    Case('bracket-strict', 'the nullifier may equal the low leaf\'s successor', IMT,
         '  bracketed = bracketed | ((low_next_index != 0) & (nf < low_next_value));',
         '  bracketed = bracketed | ((low_next_index != 0) & (nf <= low_next_value));',
         REPLAY),
    Case('capacity', 'the exhausted-tree check is gone', IMT,
         '  throw_unless(118, nullifier_next_index < imt_capacity());\n', '',
         CAPACITY),
    Case('updated-low-link', 'the updated low leaf keeps its old successor index', IMT,
         '  int updated_low = imt_leaf_hash(low_value, new_index, nf);',
         '  int updated_low = imt_leaf_hash(low_value, low_next_index, nf);',
         SEQUENTIAL),
    Case('append-empty', 'the append slot no longer has to be unallocated', IMT,
         APPEND_CHECK,
         """  throw_unless(120,
    imt_root_from_path(append_path, new_index, imt_unallocated_leaf()) >= 0);""",
         APPEND),
    Case('new-leaf-successor', 'the new leaf drops the link it inherited', IMT,
         '  int new_leaf = imt_leaf_hash(nf, low_next_index, low_next_value);',
         '  int new_leaf = imt_leaf_hash(nf, 0, 0);',
         SEQUENTIAL),
    Case('next-index', 'the next index stops advancing', IMT,
         '  return (root2, nullifier_next_index + 1);', '  return (root2, nullifier_next_index);',
         SEQUENTIAL),
]


def run_suite() -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env['PATH'] = str(Path.home() / '.cargo/bin') + os.pathsep + env.get('PATH', '')
    env['CARGO_TERM_COLOR'] = 'never'
    # TOS_ROOT only tells the sandbox where the built compiler lives; the suite
    # derives the FunC library it compiles from its own manifest directory.
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
            print(f'{case.name:26} {case.why:58} {verdict}', flush=True)
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
