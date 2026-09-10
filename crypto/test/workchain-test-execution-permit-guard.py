#!/usr/bin/env python3
"""D59 default source guard: deployment code must never enable test execution.

Inventory every setter occurrence, not just apparent calls: address-taking and
new wrappers also require an explicit decision. Scan all Git-visible C/C++ files
including untracked files and test/vendor directories; no path-wide exemptions.
This is a lexical guard, not a C++ semantic verifier. Generated/token-pasted
identifiers remain outside its guarantee. Closed live-run observations are a
separate requirement, not established by this source inventory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SETTER = 'enable_test_only_account_instance_execution'
SUFFIXES = {'.h', '.hpp', '.hh', '.hxx', '.c', '.cc', '.cpp', '.cxx', '.inc', '.ipp', '.tpp', '.ixx', '.cppm'}
TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|R"([^ ()\\\t\r\n]{0,16})\([\s\S]*?\)\1"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|[^\s]')
EXPECTED = {
    # These two are declaration/definition identities, never file exemptions.
    'crypto/block/workchain-execution-dispatch.cpp': [
        'b33ad7686ff099d3916c277ea7a2291eafaa01ab734373a4653218cfdc1df477'],
    'crypto/block/workchain-execution-dispatch.h': [
        'cf10aefb6bac0bd86d332da79c79273edd07c2886fabfceae619889158612f9d'],
    # Explicit enable and disable using the configuration constructed in-test.
    'crypto/test/test-workchain-test-execution-permit.cpp': [
        '5b8975b723241a97f392197d4b3b2fbb0af72c51ddac56ca5e107b491422d6b3',
        'a75a023b318a4adbb1b7b96841e145e0f089924f9a7371d09769f8b694e19461'],
}
ACTION = ('Remove deployment-side access to the test setter. Only test-constructed '
          'configuration may enable it; do not weaken the production refusal or broaden this allowlist.')


def identities(source):
    source = source.replace('\\\r\n', '').replace('\\\n', '')
    tokens = [m.group() for m in TOKEN.finditer(source) if not m.group().startswith(('//', '/*'))]
    result = []
    for start, token in enumerate(tokens):
        if token != SETTER:
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
        result.append(hashlib.sha256(' '.join(tokens[start:end]).encode()).hexdigest())
    return sorted(result)


def inventory(repo):
    names = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-z', '--cached', '--others', '--exclude-standard'])
    actual = {}
    for name in sorted(set(names.decode().split('\0')) - {''}):
        if Path(name).suffix.lower() not in SUFFIXES:
            continue
        # Byte-preserving decoding also scans legacy non-UTF8 source comments;
        # the guarded identifier and C++ punctuation are all ASCII. Do not use
        # errors='ignore', which could concatenate distinct bytes into tokens.
        found = identities((repo / name).read_bytes().decode('latin1'))
        if found:
            actual[name] = found
    return actual


def check(repo):
    actual = inventory(repo)
    if actual != EXPECTED:
        print(json.dumps({'identity': 'test_execution.unapproved_setter_access',
                          'actual': actual, 'expected': EXPECTED, 'action': ACTION}), file=sys.stderr)
        return 1
    print('D59 setter inventory matches explicit test-configuration calls; no deployment access.')
    return 0


def controls(repo):
    # Exercise actual CLI exit codes against isolated source copies; repository
    # production files are never changed by this test.
    script = Path(__file__).resolve()
    with tempfile.TemporaryDirectory(prefix='uno-d59-guard-') as name:
        root = Path(name)
        subprocess.run(['git', 'init', '-q', str(root)], check=True)
        for path in EXPECTED:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((repo / path).read_bytes())
        def invoke():
            return subprocess.run([sys.executable, str(script), '--repo', str(root)], capture_output=True, text=True)
        baseline = invoke()
        if baseline.returncode != 0:
            raise RuntimeError('guard control baseline did not pass: ' + baseline.stderr)
        call = '\nvoid forbidden(block::WorkchainExecutionRegistry& r, td::Bits256 id) { r.' + SETTER + '(2, id, true).ensure(); }\n'
        for path in ('crypto/block/workchain-execution-dispatch.cpp', 'validator/new-production-entry.cpp'):
            target = root / path
            previous = target.read_bytes() if target.exists() else None
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((previous or b'') + call.encode())
            rejected = invoke()
            if rejected.returncode != 1 or json.loads(rejected.stderr).get('identity') != 'test_execution.unapproved_setter_access':
                raise RuntimeError('new production call was not rejected: ' + path)
            if previous is None:
                target.unlink()
            else:
                target.write_bytes(previous)
        restored = invoke()
        if restored.returncode != 0:
            raise RuntimeError('guard control restored source did not pass: ' + restored.stderr)
    print('D59 guard controls: original production file rejected; third file rejected; unchanged source accepted.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    try:
        status = check(args.repo)
        if status == 0 and args.controls:
            controls(args.repo)
        return status
    except (OSError, UnicodeError, subprocess.SubprocessError, RuntimeError, ValueError) as error:
        print(json.dumps({'identity': 'test_execution.inventory_unavailable', 'detail': str(error), 'action': ACTION}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
