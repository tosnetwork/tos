#!/usr/bin/env python3
"""D51/D69 expiry of the Deposit-only sequence installation premise.

Inventory syntax units that directly name the authenticated counter or its
checked allocator, from explicit wc=2 state/execution roots. The sole current
installation is Deposit's next_coordinator.deposit_sequence assignment. New
references conservatively require review, even if ultimately read-only; never
refresh this inventory to admit another writer without real sequencing controls.

LIMIT: static literal include reachability and lexical syntax units, not a C++
call graph or semantic proof. Aliases, indirect writes, runtime coupling and
separately linked units not reachable from these roots are not covered. Adjacent
unrelated declarations are excluded. A scope-limit failure requires root review.
This does not verify future multi-origin issuance or count synthetic mutations
as successful host settlement.
"""
import argparse
import json
from pathlib import Path
import re
import runpy
import types
from workchain_guard_reachability import Sources, reach

ACTION = ('system sequence premise expired: before enabling another issuance path, '
          'install real host controls for staged shared counters, competing successors, '
          'and failure/no-receipt paths publishing no increment; do not refresh the inventory alone; '
          'follow doc/uno-m5-sequence-handoff.md and run '
          'crypto/test/workchain-system-sequence-handoff.py --build BUILD_DIRECTORY')
ROOTS = ('crypto/block/workchain-account-settlement.h',
         'crypto/block/workchain-deposit-transition.h',
         'crypto/block/workchain-coordinator-state.h',
         'crypto/block/transaction.cpp',
         'crypto/test/workchain-m3-node-engine.h')
# The last root is the explicitly named test-scope registered Native adapter,
# included so its first real issuance call cannot evade this expiry guard. No
# other test directories are scanned.
# Same explicit Native/account roots as prior premise guards, not all repositories
# containing a same-name identifier. Initial reachable count is recorded below
# in the pinned inventory; exceeding twice that baseline requires scope review.
LIMIT = 442  # Twice the initial 221 reachable files.

# Reuse the tested balanced syntax-unit extractor, with an independent token
# predicate. Do not mutate the epoch module or reuse its entrypoint list.
base = runpy.run_path(str(Path(__file__).with_name('workchain-key-epoch-expiry.py')))
namespace = dict(base['inventory'].__globals__)
namespace['EPOCH'] = re.compile(r'(?:deposit_sequence|next_workchain_deposit_sequence)')
namespace['units'] = types.FunctionType(base['units'].__code__, namespace)
extract = types.FunctionType(base['inventory'].__code__, namespace)


def inventory(repo, edits=None, emit=False):
    found = reach(Sources(repo, edits), ROOTS, LIMIT, 'system-sequence-expiry', emit)
    return extract(found), len(found)


def check(repo, expected, edits=None, emit=False):
    actual, count = inventory(repo, edits, emit)
    if count > 2 * expected['baseline_reachable_count']:
        raise ValueError(ACTION + ': source scope exceeded twice the baseline')
    if actual != expected['syntax_units']:
        changed = sorted(k for k in actual.keys() | expected['syntax_units'].keys()
                         if actual.get(k) != expected['syntax_units'].get(k))
        raise ValueError(ACTION + ': ' + ', '.join(changed))


def controls(repo, expected):
    path = 'crypto/block/workchain-deposit-transition.h'
    old = (repo / path).read_text()
    body = 'inline void next_origin(WorkchainCoordinatorState& state) { state.deposit_sequence = 2; }\n'
    new = 'crypto/block/system-sequence-next-origin.h'
    examples = {
        'new reachable writer': {path: old+'\n#include "system-sequence-next-origin.h"\n', new: body},
        'same file writer': {path: old+'\n'+body},
        'changed existing writer': {path: old.replace('next_coordinator.deposit_sequence = admitted.next_sequence;',
                                                     'next_coordinator.deposit_sequence = 0;')},
    }
    for label, edits in examples.items():
        try:
            check(repo, expected, edits)
        except ValueError as error:
            if not str(error).startswith(ACTION):
                raise
        else:
            raise ValueError('expiry control failed to detect '+label)
        print('EXPECTED_EXPIRY: '+label)
    # Unconnected same-name source and an unrelated neighboring field do not
    # alter the inventory. The new-file red control uses a real include edge.
    check(repo, expected, {new: body})
    check(repo, expected, {path: old+'\nstruct SequenceUnrelated { unsigned checkpoint; };\n'})
    print('UNRELATED_CONTROLS_PASS')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    expected = json.loads(Path(__file__).with_suffix('.json').read_text())
    check(args.repo, expected, emit=True)
    controls(args.repo, expected)
    print('SYSTEM_SEQUENCE_EXPIRY_PASS; real three-origin host controls remain pending')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print(error)
        raise SystemExit(1)
