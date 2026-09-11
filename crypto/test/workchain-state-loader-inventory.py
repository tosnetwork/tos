#!/usr/bin/env python3
"""Inventory ordinary cell loaders in wc=2 authenticated-state decoding.

EXPIRY: new or changed ordinary loader calls require an individually justified
provenance/exception boundary before they can enter this inventory.
LIMIT: lexical, not alias/interprocedural analysis. Indirect calls can evade it.
The explicit state-decoding file set is not a whole-repository scan. New state
codecs must be added to it. Special-aware loaders still require descendant error
handling; this check does not prove that traversals cannot throw.
"""
import argparse
from pathlib import Path
import re

FILES = (
    'crypto/block/workchain-coordinator-state.h',
    'crypto/block/workchain-confidential-state.h',
    'crypto/block/workchain-system-state-access.h',
    'crypto/block/workchain-unexpected-bucket.h',
    'crypto/block/workchain-deposit-admission.h',
    'crypto/block/workchain-deposit-transition.h',
)
# This loader is inside read_workchain_system_state's VmError/VmVirtError
# boundary. Its caller supplies ReceivedCandidate versus AcquiredView; the
# catch uses that provenance, and acquisition precedes any proof verification.
ALLOWED = {
    ('crypto/block/workchain-system-state-access.h',
     'vm::load_cell_slice_ref(shard.accounts)'),
}
TOKENS = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|[^\s]')
CALL = re.compile(r'\b(load_cell_slice(?:_ref|_impl)?)\s*\(')


def calls(source):
    text = ' '.join(m.group() for m in TOKENS.finditer(source)
                    if not m.group().startswith(('//', '/*', '"', "'")))
    result = []
    for match in CALL.finditer(text):
        start = match.start()
        if text[:start].endswith('vm : : '):
            start -= len('vm : : ')
        depth = 1
        end = match.end()
        while end < len(text) and depth:
            depth += (text[end] == '(') - (text[end] == ')')
            end += 1
        result.append(re.sub(r'\s+', '', text[start:end]))
    return result


def inventory(sources):
    return sorted((name, call) for name, source in sources.items() for call in calls(source))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    sources = {name: (args.repo / name).read_text() for name in FILES}
    expected = sorted(ALLOWED)
    actual = inventory(sources)
    if actual != expected:
        raise SystemExit('state-loader inventory expired: review ordinary loading and caller provenance; '
                         f'expected={expected}; actual={actual}')
    # Controls exercise the same inventory, including same-file new calls and
    # changes to the one approved use. Do not rely on a non-running scanner.
    for name in FILES:
        for loader in ('load_cell_slice', 'load_cell_slice_ref', 'load_cell_slice_impl'):
            changed = dict(sources)
            changed[name] += f'\nvoid control() {{ vm::{loader}(root); }}\n'
            if inventory(changed) == expected:
                raise SystemExit('new ordinary loader control did not fail')
    changed = dict(sources)
    name = 'crypto/block/workchain-system-state-access.h'
    changed[name] = changed[name].replace('load_cell_slice_ref(shard.accounts)', 'load_cell_slice_ref(other)')
    if inventory(changed) == expected:
        raise SystemExit('changed approved loader control did not fail')
    print('state-loader inventory PASS; 18 new-call controls and approved-call change detected')


if __name__ == '__main__':
    main()
