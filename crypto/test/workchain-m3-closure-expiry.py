#!/usr/bin/env python3
"""Default expiry of M3's structural no-settlement-obligation premise.

Freeze the exact UNO TL-B family and C++ state representations, not just the
absence of one field spelling. Additionally inventory obligation/deposit/
withdrawal identifiers reachable from the explicit operation roots, including
new files connected through literal includes. Existing refundable registration deposits are NOT M4
Deposit operations; their recorded occurrences are retained, not excluded.
The one-way refund materializer's bucket arithmetic is inventoried too: it adds
no authenticated representation or operation, no return association/recredit,
and promises no delivery.

M4's sender-only unexpected bucket cannot attribute a right to a confidential
account. It does not carry account_id. D29's account_id category mechanically
credits a confidential account, but only follows M5 late-return rejection and
is unreachable in M4. Sender attribution is not a claim that no Native sender
has a right: the structural premise concerns this confidential account's closure.
Accepted Deposit clears D within its batch; rejection either returns value or
credits sender-only unexpected funds, never a confidential account's obligation.
The full bucket representation is frozen below, not excluded by its name.
The rejected-ingress planner consumes the one authenticated inbox message for
its source/destination and reuses Native bounce rules; it returns no retained
return association. It only plans same-batch Native credit or return plus bucket
update, never deferred confidential credit.

LIMIT: literal include/module reachability, not a semantic C++/Rust proof.
Runtime coupling, indirect references and aliases are outside coverage. New
separately linked translation units or schema generators require explicit roots.
The test-funding operation is an explicit exception, not a test-directory scan.
Within reachable files, identifier tokens are inventoried (not semicolon chunks).
The three state representations and test-funding operation deliberately retain
whole-definition hashes: any new representation requires a premise review.
TL-B semicolons delimit complete schema declarations, not C++/Rust fragments.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from workchain_guard_reachability import Sources, reach, controls as reachability_controls

ACTION = ("closure's no-obligation condition was structurally satisfied and no longer is; "
          "implement an authenticated obligation view before allowing closure; "
          "when M5 account_id bucket attribution becomes reachable, also require "
          "no bucket entries attributable to the closing account (D29/section 10)")
STATE = {'crypto/block/workchain-confidential-state.h',
         'crypto/block/workchain-coordinator-state.h',
         'crypto/block/workchain-unexpected-bucket.h'}
TEST_OPERATION = 'crypto/test/workchain-m3-test-funding-operation.h'
# Native installation/refund and all current confidential transitions. Schema
# is the generated codec input; test funding is separately explicit below.
ROOTS = (
    'crypto/block/workchain-account-settlement.h',
    'crypto/block/workchain-confidential-execution.h',
    'crypto/block/workchain-deposit-transition.h',
    'crypto/block/transaction.cpp',
    'crypto/block/block.tlb',
    TEST_OPERATION,
)
# Baseline 6ea2fbf80: 215 reachable files; over twice that requires
# entrypoint review rather than accepting an unexpectedly large subtree.
MAX_REACHABLE = 430
TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|[^\s]')
WATCH = re.compile(r'obligation|settlement_?refs?|withdraw|deposit', re.I)


def tokens(source):
    source = source.replace('\\\r\n', '').replace('\\\n', '')
    return [m.group() for m in TOKEN.finditer(source)
            if not m.group().startswith(('//', '/*', '"', "'"))]


def digest(value):
    return hashlib.sha256(' '.join(value).encode()).hexdigest()


def inventory(sources):
    result = {}
    for name, source in sorted(sources.items()):
        # Generated native RPC schemas/configuration templates are dependency
        # inputs, not C++/Rust state declarations or UNO TL-B constructors.
        if Path(name).suffix not in {'.h', '.hpp', '.cpp', '.cc', '.c', '.rs', '.tlb', '.inc', '.ipp', '.tpp'}:
            continue
        ts = tokens(source)
        if name == TEST_OPERATION:
            # This explicitly inventoried test operation completes its balance
            # write in the same batch. No async association/obligation survives.
            # Freeze its whole definition; do not exempt future test operations.
            result[name + ':test-operation'] = digest(ts)
        if name in STATE:
            result[name + ':state'] = digest(ts)
        if Path(name).suffix == '.tlb':
            # Every UNO constructor, including future additional records or
            # operations in a reachable schema input. Comments and layout whitespace do not
            # establish or erase a schema identity.
            records = ' '.join(ts).split(';')
            uno = [r.strip() for r in records if re.search(r'\b(?:uno_|Uno)', r)]
            if uno:
                result[name + ':schema'] = digest(uno)
        watched = [t for t in ts if re.fullmatch(r'[A-Za-z_]\w*', t) and WATCH.search(t)]
        if watched:
            result[name + ':identifiers'] = digest(watched)
    for name in STATE | {TEST_OPERATION}:
        if name not in sources:
            raise ValueError('missing authenticated state representation: ' + name)
    if 'crypto/block/block.tlb' not in sources:
        raise ValueError('missing operation schema')
    return result


def read_sources(repo, edits=None, emit=False):
    return reach(Sources(repo, edits), ROOTS, MAX_REACHABLE, 'closure-expiry', emit)


def controls(repo, sources, expected):
    # Same inventory used by the real check, with a temporary source snapshot;
    # never mutate a repository or a concurrent compilation's input.
    changed = dict(sources)
    path = 'crypto/block/workchain-confidential-state.h'
    marker = 'struct WorkchainConfidentialAccount {'
    if changed[path].count(marker) != 1:
        raise ValueError('field control insertion point unavailable')
    changed[path] = changed[path].replace(marker, marker + '\n  td::Ref<vm::Cell> settlement_refs;')
    if inventory(read_sources(repo, changed)) == expected:
        raise ValueError('added obligation field was not detected')
    changed = dict(sources)
    changed[path] += '\n#include "validator/new-obligation-view.h"\n'
    changed['validator/new-obligation-view.h'] = 'struct SettlementObligationView { unsigned count; };'
    if inventory(read_sources(repo, changed)) == expected:
        raise ValueError('new obligation view was not detected')
    changed = dict(sources)
    # TL-B has no include syntax. Extend the actual generated codec input,
    # rather than pretend an unreferenced third schema is part of this build.
    changed['crypto/block/block.tlb'] += '\nuno_v2_withdraw amount:uint64 = UnoV2TransferInputV1;\n'
    if inventory(read_sources(repo, changed)) == expected:
        raise ValueError('new operation was not detected')
    changed = dict(sources)
    changed[TEST_OPERATION] += '\nstruct TestFundingSettlementObligation { unsigned count; };\n'
    if inventory(read_sources(repo, changed)) == expected:
        raise ValueError('changed test funding operation was not detected')
    changed = dict(sources)
    path = 'crypto/block/workchain-unexpected-bucket.h'
    marker = 'struct WorkchainUnexpectedEntry {'
    if changed[path].count(marker) != 1:
        raise ValueError('bucket attribution insertion point unavailable')
    changed[path] = changed[path].replace(marker, marker + '\n  td::Bits256 account_id;')
    if inventory(read_sources(repo, changed)) == expected:
        raise ValueError('confidential bucket attribution was not detected')
    if inventory(sources) != expected:
        raise ValueError('unchanged source no longer passes')
    print('Expiry controls: obligation field, third-file view, new operation, changed test operation, bucket account_id rejected; '
          'unchanged source accepted.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    try:
        expected = json.loads(Path(__file__).with_suffix('.json').read_text())
        sources = read_sources(args.repo, emit=True)
        actual = inventory(sources)
        if actual != expected:
            print(json.dumps({'identity': 'm3.closure.structural_expiry', 'action': ACTION,
                              'changed': sorted(k for k in actual.keys() | expected.keys()
                                                if actual.get(k) != expected.get(k))}))
            return 1
        if args.controls:
            reachability_controls(args.repo, ROOTS, MAX_REACHABLE, 'closure-expiry')
            controls(args.repo, sources, expected)
        print('M3/M4 confidential closure premise checked, including sender-only bucket; '
              'no runtime obligation check or absence of Native sender rights claimed.')
        return 0
    except (OSError, ValueError) as error:
        print(json.dumps({'identity': 'm3.closure.inventory_unavailable', 'detail': str(error), 'action': ACTION}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
