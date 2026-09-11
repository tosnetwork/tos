#!/usr/bin/env python3
"""Default expiry of M3's structural no-settlement-obligation premise.

Freeze the exact UNO TL-B family and C++ state representations, not just the
absence of one field spelling. Additionally inventory obligation/deposit/
withdrawal identifiers throughout Git-visible first-party production sources,
including new files. Existing refundable registration deposits are NOT M4
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

LIMIT: lexical source check, not a semantic C++/Rust proof. Generated or renamed
operations outside the frozen representations require human identification.
Tests/docs/vendors are excluded by path component, not directory prefix.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ACTION = ("closure's no-obligation condition was structurally satisfied and no longer is; "
          "implement an authenticated obligation view before allowing closure; "
          "when M5 account_id bucket attribution becomes reachable, also require "
          "no bucket entries attributable to the closing account (D29/section 10)")
EXCLUDED = {'test', 'tests', 'doc', 'third-party', 'third_party', 'vendor'}
SUFFIXES = {'.h', '.hpp', '.cpp', '.cc', '.c', '.rs', '.tlb', '.inc', '.ipp', '.tpp'}
STATE = {'crypto/block/workchain-confidential-state.h',
         'crypto/block/workchain-coordinator-state.h',
         'crypto/block/workchain-unexpected-bucket.h'}
TEST_OPERATION = 'crypto/test/workchain-m3-test-funding-operation.h'
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
            # operations in a third file. Comments and layout whitespace do not
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


def read_sources(repo):
    names = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-z',
                                    '--cached', '--others', '--exclude-standard']).decode().split('\0')
    return {name: (repo / name).read_text() for name in sorted(set(names) - {''})
            if Path(name).suffix in SUFFIXES and
            (name == TEST_OPERATION or not EXCLUDED.intersection(Path(name).parts))}


def controls(sources, expected):
    # Same inventory used by the real check, with a temporary source snapshot;
    # never mutate a repository or a concurrent compilation's input.
    changed = dict(sources)
    path = 'crypto/block/workchain-confidential-state.h'
    marker = 'struct WorkchainConfidentialAccount {'
    if changed[path].count(marker) != 1:
        raise ValueError('field control insertion point unavailable')
    changed[path] = changed[path].replace(marker, marker + '\n  td::Ref<vm::Cell> settlement_refs;')
    if inventory(changed) == expected:
        raise ValueError('added obligation field was not detected')
    changed = dict(sources)
    changed['validator/new-obligation-view.h'] = 'struct SettlementObligationView { unsigned count; };'
    if inventory(changed) == expected:
        raise ValueError('new obligation view was not detected')
    changed = dict(sources)
    changed['crypto/block/new-operation.tlb'] = 'uno_v2_withdraw amount:uint64 = UnoV2TransferInputV1;'
    if inventory(changed) == expected:
        raise ValueError('new operation was not detected')
    changed = dict(sources)
    changed[TEST_OPERATION] += '\nstruct TestFundingSettlementObligation { unsigned count; };\n'
    if inventory(changed) == expected:
        raise ValueError('changed test funding operation was not detected')
    changed = dict(sources)
    path = 'crypto/block/workchain-unexpected-bucket.h'
    marker = 'struct WorkchainUnexpectedEntry {'
    if changed[path].count(marker) != 1:
        raise ValueError('bucket attribution insertion point unavailable')
    changed[path] = changed[path].replace(marker, marker + '\n  td::Bits256 account_id;')
    if inventory(changed) == expected:
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
        sources = read_sources(args.repo)
        actual = inventory(sources)
        if actual != expected:
            print(json.dumps({'identity': 'm3.closure.structural_expiry', 'action': ACTION,
                              'changed': sorted(k for k in actual.keys() | expected.keys()
                                                if actual.get(k) != expected.get(k))}))
            return 1
        if args.controls:
            controls(sources, expected)
        print('M3/M4 confidential closure premise checked, including sender-only bucket; '
              'no runtime obligation check or absence of Native sender rights claimed.')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({'identity': 'm3.closure.inventory_unavailable', 'detail': str(error), 'action': ACTION}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
