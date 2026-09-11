#!/usr/bin/env python3
"""Fail closed when the reviewed UNO crypto ABI source inventory changes.

All Git-visible first-party source (including tests, archives and untracked
files) is scanned, not just the current backend directory. Full-file hashes
also watch the surrounding meter and cfg(test) boundaries. Strings/comments
are deliberately included: an ambiguous new occurrence requires disposition.
This is a source-lifecycle check, not a C++/Rust semantic proof. Generated or
token-pasted names, external code and dynamically assembled symbol names are
outside its guarantee; it does not prove per-operation counting correctness.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

SOURCE = {'.h', '.hpp', '.hh', '.hxx', '.c', '.cc', '.cpp', '.cxx', '.inc',
          '.ipp', '.tpp', '.ixx', '.cppm', '.rs', '.py', '.js', '.mjs', '.ts'}
# Only external code is excluded, by path component, not tests or archives.
EXTERNAL = {'third-party', 'third_party', 'vendor', 'node_modules'}
SYMBOL = re.compile(r'\b(?:__real_|__wrap_)?uno_crypto_[A-Za-z0-9_]+\b')
ACTION = ('Route node verification through WorkchainProofVerifier before the ABI; '
          'classify other uses explicitly and update the reviewed inventory. '
          'Do not exempt a production caller as a test.')


def record(data):
    names = sorted(set(SYMBOL.findall(data.decode('utf-8'))))
    return {'symbols': names, 'sha256': hashlib.sha256(data).hexdigest()} if names else None


def inventory(repo):
    names = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-z',
                                     '--cached', '--others', '--exclude-standard'])
    result = {}
    for name in sorted(set(names.decode().split('\0')) - {''}):
        path = Path(name)
        if path.suffix.lower() not in SOURCE or EXTERNAL.intersection(path.parts):
            continue
        item = record((repo / path).read_bytes())
        if item:
            result[name] = item
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = json.loads(Path(__file__).with_suffix('.json').read_text())
        expected = {name: {key: value[key] for key in ('symbols', 'sha256')}
                    for name, value in manifest.items()}
        if any(not value.get('disposition') for value in manifest.values()):
            raise ValueError('Every ABI source must have an explicit disposition')
        actual = inventory(args.repo)
        if actual != expected:
            print(json.dumps({'identity': 'crypto.abi.boundary_changed',
                              'actual': actual, 'expected': expected, 'action': ACTION}), file=sys.stderr)
            return 1
        print(json.dumps({'identity': 'crypto.abi.boundary_checked', 'files': len(actual),
                          'dispositions': {name: value['disposition'] for name, value in manifest.items()}}))
        return 0
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
        print(json.dumps({'identity': 'crypto.abi.inventory_unavailable',
                          'detail': str(error), 'action': ACTION}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
