#!/usr/bin/env python3
"""Inventory the current epoch-bearing production statements.

Registration installs a complete initial account; it does not assign a scalar
key_epoch member. Existing explicit assignments build proof requests, not state.
Inventory all epoch uses, including aggregate initialization and new files, so
that an unfamiliar use requires a decision rather than guessing its provenance.

EXPIRY: before introducing rotation, preserve old pending/refund rights (section
5). workchain-confidential-execution.h checks receipt epoch against current epoch;
COLLECT historical-key support needs a section 6.2 relation / D34 scope decision.
LIMIT: lexical inventory cannot prove absence of arbitrary alias-based writes.
The companion scenario checks actual transitions. Neither check verifies that a
future rotation preserves old pending; review remains necessary for opaque writes.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

ACTION = 'epoch guard expired: preserve old pending before implementing rotation (section 5 / D34)'
TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|[^\s]')
EXCLUDED = {'test', 'tests', 'doc', 'third-party', 'third_party', 'vendor'}


def inventory(sources):
    result = {}
    for name, source in sorted(sources.items()):
        ts = [m.group() for m in TOKEN.finditer(source)
              if not m.group().startswith(('//', '/*', '"', "'"))]
        # Keep complete semicolon-delimited statements, not just assignment
        # spellings: an epoch may be passed by reference or aggregate initialized.
        rows = [' '.join(row.split()) for row in ' '.join(ts).split(';')
                if re.search(r'\b\w*key_epoch\w*\b', row)]
        if rows:
            result[name] = rows
    return result


def sources(repo):
    names = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-z',
                                    '--cached', '--others', '--exclude-standard']).decode().split('\0')
    return {n: (repo / n).read_text() for n in sorted(set(names) - {''})
            if Path(n).suffix in {'.h', '.hpp', '.cpp', '.cc', '.c', '.rs', '.inc', '.tlb'}
            and not EXCLUDED.intersection(Path(n).parts)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    expected = json.loads(Path(__file__).with_suffix('.json').read_text())
    current = sources(args.repo)
    actual = inventory(current)
    if actual != expected:
        changed = sorted(k for k in actual.keys() | expected.keys() if actual.get(k) != expected.get(k))
        raise ValueError(ACTION + ': ' + ', '.join(changed))
    changed = dict(current)
    changed['crypto/block/new-rotation.cpp'] = 'void rotate(Account& a) { ++a.key_epoch; }'
    if inventory(changed) == expected:
        raise ValueError('new-file epoch mutation control was not detected')
    changed['crypto/block/new-rotation.cpp'] = 'void rotate(Account& a, bool enabled) { if(enabled) a.key_epoch = 1; }'
    if inventory(changed) == expected:
        raise ValueError('conditional epoch mutation control was not detected')
    print('EPOCH_INVENTORY_PASS; new-file and conditional mutation controls detected')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(error)
        raise SystemExit(1)
