#!/usr/bin/env python3
"""Inventory the current epoch-bearing production statements.

Registration installs a complete initial account; it does not assign a scalar
key_epoch member. Existing explicit assignments build proof requests, not state.
Inventory epoch-bearing declarations, expressions and control headers reachable
from the named UNO operation roots. Whole aggregate initializers/call arguments
remain expressions: field order and the receiver can affect an epoch write.
Adjacent declarations are not part of the same syntax unit. TL-B entries retain
only the named epoch member's type and constructor identity.

EXPIRY: before introducing rotation, preserve old pending/refund rights (section
5). workchain-confidential-execution.h checks receipt epoch against current epoch;
COLLECT historical-key support needs a section 6.2 relation / D34 scope decision.
LIMIT: reachability is static literal include/module traversal. Runtime coupling,
indirect references and aliases are not covered. Same-name identifiers outside
these wc=2 paths are not covered. Syntax-unit extraction is lexical and does not
resolve types, macros or arbitrary alias-based writes.
The companion scenario checks actual transitions. Neither check verifies that a
future rotation preserves old pending; review remains necessary for opaque writes.
"""
import argparse
import json
from pathlib import Path
import re
from workchain_guard_reachability import Sources, reach, controls as reachability_controls

ACTION = 'epoch guard expired: preserve old pending before implementing rotation (section 5 / D34)'
TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|[^\s]')
# Operation execution, Native installation, the separately linked possession
# bridge, kernel module root, and the generated codec's schema input.
ROOTS = (
    'crypto/block/workchain-account-settlement.h',
    'crypto/block/workchain-confidential-execution.h',
    'crypto/block/workchain-deposit-transition.h',
    'crypto/block/workchain-registration-proof.cpp',
    'uno/crypto/src/lib.rs',
    'crypto/block/block.tlb',
)
# Baseline 6ea2fbf80: 215 reachable files. More than twice that is an
# entrypoint expansion requiring review, not an automatic baseline refresh.
MAX_REACHABLE = 430
EPOCH = re.compile(r'\b\w*key_epoch\w*\b')


def units(ts):
    """Declarations/expressions/control headers, with balanced calls/initializers.

    A comma ends a field declaration outside parentheses/aggregate expressions;
    braces begin a new declaration/control scope. Semicolons terminate only the
    current unit, never a whole run of neighboring structs. This deliberately
    does not claim to parse arbitrary C++/Rust macro expansions.
    """
    result, current, scopes, brackets = [], [], [], []

    def flush():
        if any(EPOCH.fullmatch(t) for t in current):
            result.append(' :: '.join(scopes + [' '.join(current)]))
        current.clear()

    for token in ts:
        if brackets:
            current.append(token)
            if token in ('(', '[', '{'):
                brackets.append({'(': ')', '[': ']', '{': '}'}[token])
            elif token == brackets[-1]:
                brackets.pop()
            continue
        if token in ('(', '['):
            current.append(token)
            brackets.append(')' if token == '(' else ']')
        elif token == '{':
            # Calls/explicit aggregate expressions are kept balanced as one
            # expression. Named declaration scopes and function/control bodies
            # are boundaries, so their neighboring members do not leak in.
            is_scope = (not current or current[-1] in (')', 'try', 'noexcept', 'override', 'final') or
                        any(t in current for t in ('struct', 'class', 'union', 'enum', 'namespace', 'impl', 'mod', 'fn')) or
                        current[0] in ('if', 'else', 'for', 'while', 'match', 'try', 'do', 'loop', 'unsafe'))
            if is_scope:
                owner = ' '.join(current)
                flush()
                scopes.append(owner)
            else:
                current.append(token)
                brackets.append('}')
        elif token == '}':
            flush()
            if scopes:
                scopes.pop()
        elif token == ',' and 'fn' in current:
            current.append(token)  # A Rust function header may return Result<T, E>.
        elif token in (';', ','):
            flush()
        else:
            current.append(token)
    flush()
    return result


def inventory(sources):
    result = {}
    for name, source in sorted(sources.items()):
        if not name.endswith(('.rs', '.tlb')):
            source = re.sub(r'^\s*#.*(?:\\\n.*)*', '', source, flags=re.M)
        ts = [m.group() for m in TOKEN.finditer(source)
              if not m.group().startswith(('//', '/*', '"', "'"))]
        if name.endswith('.tlb'):
            # TL-B field names end at the next name:type or constructor result.
            # Neighboring non-epoch fields do not define this member's identity.
            rows = []
            for record in ' '.join(ts).split(';'):
                fields = list(re.finditer(r'(\w+)\s*:\s*(.*?)(?=\s+\w+\s*:|\s*=|$)', record))
                owner = record.strip().split(' ', 1)[0]
                rows.extend(owner + ' :: ' + m.group(1) + ' : ' + m.group(2).strip()
                            for m in fields if EPOCH.fullmatch(m.group(1)))
        else:
            rows = units(ts)
        if rows:
            result[name] = rows
    return result


def sources(repo, edits=None, emit=False):
    return reach(Sources(repo, edits), ROOTS, MAX_REACHABLE, 'key-epoch', emit)


def controls(repo, expected):
    path = 'crypto/block/workchain-confidential-state.h'
    original = (repo / path).read_text()
    new_path = 'crypto/block/new-rotation.h'
    for body in ('void rotate(Account& a) { ++a.key_epoch; }',
                 'void rotate(Account& a, bool enabled) { if(enabled) a.key_epoch = 1; }'):
        edits = {path: original + '\n#include "new-rotation.h"\n', new_path: body}
        if inventory(sources(repo, edits)) == expected:
            raise ValueError('reachable new-file/conditional epoch mutation was not detected')
    marker = 'std::uint32_t key_epoch;'
    if original.count(marker) != 1:
        raise ValueError('epoch member control insertion point unavailable')
    edits = {path: original.replace(marker, marker + '\n  unsigned unrelated_neighbor;')}
    if inventory(sources(repo, edits)) != expected:
        raise ValueError('unrelated adjacent field polluted an epoch syntax unit')
    edits = {path: original.replace(marker, 'std::uint64_t key_epoch;')}
    if inventory(sources(repo, edits)) == expected:
        raise ValueError('retained epoch member type change was not detected')
    rust = 'uno/crypto/src/ffi.rs'
    original_rust = (repo / rust).read_text()
    # Rust fields are comma-delimited. Reproduce the adjacent-struct shape
    # which exposed the original semicolon scanner's overreach.
    marker = '#[repr(C)]\n#[derive(Clone, Copy)]\npub struct KeyPossessionRequestV2 {'
    neighbor = 'struct UnrelatedCheckpoint { checkpoint_file: String, checkpoint_pause_ms: u32 }\n'
    if original_rust.count(marker) != 1:
        raise ValueError('Rust declaration insertion point unavailable')
    edits = {rust: original_rust.replace(marker, neighbor + marker)}
    if inventory(sources(repo, edits)) != expected:
        raise ValueError('adjacent Rust struct polluted an epoch declaration')
    edits = {rust: original_rust.replace('pub key_epoch: u32,',
             'pub unrelated_checkpoint: u64,\n    pub key_epoch: u32,', 1)}
    if inventory(sources(repo, edits)) != expected:
        raise ValueError('adjacent Rust field polluted an epoch declaration')
    edits = {rust: original_rust.replace('pub key_epoch: u32,', 'pub key_epoch: u64,', 1)}
    if inventory(sources(repo, edits)) == expected:
        raise ValueError('Rust epoch member change was not detected')
    # Also exercise a statement in an existing function, not just field types.
    edits = {'crypto/block/workchain-registration-proof.cpp':
             (repo / 'crypto/block/workchain-registration-proof.cpp').read_text().replace(
                 'r.key_epoch = a.key_epoch;', 'r.key_epoch = a.key_epoch + 1;')}
    if inventory(sources(repo, edits)) == expected:
        raise ValueError('existing epoch assignment change was not detected')
    # An unconnected same-name declaration cannot enter the real reader's set.
    edits = {'tosctl/unrelated-epoch.rs': 'struct Other { key_epoch: u32, checkpoint_file: String }'}
    if inventory(sources(repo, edits)) != expected:
        raise ValueError('unreachable same-name declaration entered epoch scope')
    print('EPOCH_CONTROLS_PASS: reachable new-file and conditional write, retained member change rejected; '
          'adjacent unrelated member and unreachable declaration accepted')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    expected = json.loads(Path(__file__).with_suffix('.json').read_text())
    current = sources(args.repo, emit=True)
    actual = inventory(current)
    if actual != expected:
        changed = sorted(k for k in actual.keys() | expected.keys() if actual.get(k) != expected.get(k))
        raise ValueError(ACTION + ': ' + ', '.join(changed))
    reachability_controls(args.repo, ROOTS, MAX_REACHABLE, 'key-epoch')
    controls(args.repo, expected)
    print('EPOCH_INVENTORY_PASS; new-file and conditional mutation controls detected')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print(error)
        raise SystemExit(1)
