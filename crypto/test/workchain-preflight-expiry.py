#!/usr/bin/env python3
"""Default source lifecycle check, not a proof of operation coverage.

Scan all Git-visible first-party C/C++ source, including untracked additions.
Unknown proof_work occurrences fail closed, including declarations and calls:
this deliberately expires on changes to the recorded tokens rather than
guessing whether a new occurrence is harmless. Return types, enclosing classes
and call receivers preceding the identifier are not fingerprinted. Tests,
documentation and vendored code are not production engine implementations. Token-pasting/generated identifiers
are outside this lexical guard's guarantee; this is not a C++ semantic verifier.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

SUFFIXES = {'.h', '.hpp', '.hh', '.hxx', '.c', '.cc', '.cpp', '.cxx', '.inc', '.ipp', '.tpp', '.ixx', '.cppm'}
EXCLUDED = {'test', 'tests', 'third-party', 'third_party', 'vendor', 'doc'}
# Exact token identities, not file-wide exemptions. Updated only after review.
EXPECTED = {
    # Abstract two-argument declaration and the existing admission call.
    'crypto/block/workchain-account-engine.h': [
        '712a281a1970c665440e2a1d2055d89acb293bb3dc02a1b2139f4fb53b15cff9',
        'd428f4a3746529d06b786b1bf1c7e6dff4127a01cff63109545606654b703f50'],
    # Abstract configured declaration, adapter body, and its forwarded call.
    'crypto/block/workchain-execution-dispatch.h': [
        'b70a1f959f0d1274f2726610269ea73e06a71389a1b097a7f23546c418e121ef',
        'cfdf8bbfdab674cc69193985379e06b4bda507e2b2e6f2699ed28376b76095d0',
        'fdb9a3965d7990e787369a5a9415c086c2f0a159e8abd1dbc7f3663b5ba237bf'],
}

TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|R"([^ ()\\\t\r\n]{0,16})\([\s\S]*?\)\1"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|[^\s]')


def occurrences(source):
    # C++ translation phase 2 joins escaped newlines before tokenization.
    # A split identifier must not evade the inventory.
    source = source.replace('\\\r\n', '').replace('\\\n', '')
    # Retain string tokens inside a body's identity, but never search them for
    # identifiers. Comments cannot supply an implementation or its exemption.
    tokens = [m.group() for m in TOKEN.finditer(source)
              if not m.group().startswith(('//', '/*'))]
    found = []
    for start, token in enumerate(tokens):
        if token != 'proof_work':
            continue
        depth = 0
        end = start + 1
        while end < len(tokens):
            current = tokens[end]
            if current in ('(', '{', '['):
                depth += 1
            elif current in (')', '}', ']'):
                depth -= 1
                if depth < 0:
                    break
                if current == '}' and depth == 0:
                    end += 1
                    break
            elif current == ';' and depth == 0:
                end += 1
                break
            end += 1
        identity = ' '.join(tokens[start:end])
        found.append(hashlib.sha256(identity.encode()).hexdigest())
    return found


def inventory(repo):
    names = subprocess.check_output(
        ['git', '-C', str(repo), 'ls-files', '-z', '--cached', '--others', '--exclude-standard'])
    result = {}
    for name in sorted(set(names.decode().split('\0')) - {''}):
        path = Path(name)
        if path.suffix.lower() not in SUFFIXES or EXCLUDED.intersection(path.parts):
            continue
        values = occurrences((repo / path).read_text())
        if values:
            result[name] = sorted(values)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    try:
        actual = inventory(args.repo)
    except (OSError, UnicodeError, subprocess.SubprocessError) as error:
        print(json.dumps({'identity': 'preflight.inventory_unavailable',
                          'detail': str(error),
                          'action': 'Restore a readable source inventory; missing observations cannot pass expiry.'}), file=sys.stderr)
        return 1
    if actual != EXPECTED:
        print(json.dumps({'identity': 'preflight.production_expiry', 'actual': actual,
                          'expected': EXPECTED,
                          'action': 'Connect the budget contract and delete this guard; retarget controls to production call sites.'}), file=sys.stderr)
        return 1
    print('Preflight expiry checked: only frozen abstract interfaces, admission call and configured forwarding remain; no concrete production implementation.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
