#!/usr/bin/env python3
"""D51 trigger: the registered Failed branch must not acquire a funding edge.

Scope: Clang's AST of M3NodeEngine::execute_metered_accounts, its Failed branch
and shared finish lambda. This is a structural capability trigger, NOT a real
subsidy-rejection test. It does not prove absence of arbitrary callee side effects
or changes in Native materialization. D63's other branches remain outside scope.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

EXPIRED = 'FAILED_FUNDING_PREMISE_EXPIRED'
ENGINE = 'crypto/test/workchain-m3-node-engine.h'


def walk(node):
    yield node
    for child in node.get('inner', []):
        yield from walk(child)


def named_reference(node, name):
    return any(n.get('referencedDecl', {}).get('name') == name for n in walk(node))


def inspect(method):
    branches = [n for n in walk(method) if n.get('kind') == 'IfStmt'
                and n.get('inner') and named_reference(n['inner'][0], 'is_m5_test_failed')]
    if len(branches) != 1:
        raise ValueError(EXPIRED + ': Failed dispatch no longer resolves uniquely')
    finishes = [n for n in walk(method) if n.get('kind') == 'VarDecl' and n.get('name') == 'finish']
    if len(finishes) != 1:
        raise ValueError(EXPIRED + ': finish continuation no longer resolves uniquely')
    for scope, allowed in [(branches[0], {'updates', 'fees'}),
                           (finishes[0], {'protected_coordinator_snapshot'})]:
        for n in walk(scope):
            if n.get('kind') != 'MemberExpr' or not n.get('inner'):
                continue
            receiver = n['inner'][0].get('type', {}).get('qualType', '')
            if 'WorkchainAccountEffects' in receiver and n.get('name') not in allowed:
                raise ValueError(EXPIRED + ': effects capability ' + str(n.get('name')))
    # The branch must still publish its local effects through the inspected
    # continuation. A replacement producer is not silently admitted.
    body = branches[0]['inner'][-1]
    terminal = body.get('inner', [])[-1]
    if terminal.get('kind') != 'ReturnStmt' or not named_reference(terminal, 'finish'):
        raise ValueError(EXPIRED + ': Failed publication bypasses inspected finish')
    print('FAILED_FUNDING_STRUCTURE: Failed effects members=updates,fees; finish=protected snapshot')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', required=True, type=Path)
    args = p.parse_args()
    repo = Path(__file__).resolve().parents[2]
    build = args.build.resolve()
    commands = json.loads((build / 'compile_commands.json').read_text())
    entries = [e for e in commands if Path(e['file']).resolve() == repo / 'test/test-m3-live.cpp']
    if len(entries) != 1:
        raise ValueError('FUNDING_GUARD_UNAVAILABLE: live compile command missing or ambiguous')
    original = (repo / ENGINE).read_text()
    with tempfile.TemporaryDirectory(prefix='uno-failed-funding-expiry-') as temporary:
        temp = Path(temporary)
        header = temp / ENGINE
        header.parent.mkdir(parents=True)
        def check(source):
            header.write_text(source)
            argv = shlex.split(entries[0]['command'])
            output = argv.index('-o')
            del argv[output:output+2]
            argv.remove('-c')
            # Use the configured Clang rather than parsing source text. A
            # non-Clang configuration must not count this check as executed.
            if 'clang' not in Path(argv[0]).name:
                raise ValueError('FUNDING_GUARD_UNAVAILABLE: Clang AST required')
            argv[1:1] = ['-I' + str(temp), '-I' + str(repo / 'crypto/test')]
            argv += ['-fsyntax-only', '-Xclang', '-ast-dump=json', '-Xclang',
                     '-ast-dump-filter=M3NodeEngine::execute_metered_accounts']
            result = subprocess.run(argv, cwd=build, text=True, capture_output=True, timeout=120)
            if result.returncode:
                raise ValueError('FUNDING_GUARD_UNAVAILABLE: AST compilation failed\n' + result.stderr)
            method = json.loads(result.stdout)
            if method.get('kind') != 'CXXMethodDecl':
                raise ValueError('FUNDING_GUARD_UNAVAILABLE: unexpected AST root')
            inspect(method)
        check(original)
        marker = '      result.fees = accepted.fees;'
        if original.count(marker) != 1:
            raise ValueError('funding mutation insertion point ambiguous')
        funding = '\n      result.native_transfers.push_back({cfg->ingress.executor_address, *cfg->ingress.custody_address, CurrencyCollection(1)});'
        try:
            check(original.replace(marker, marker + funding))
        except ValueError as e:
            if not str(e).startswith(EXPIRED):
                raise
            print('EXPECTED_EXPIRY: direct Failed operator edge: ' + str(e))
        else:
            raise ValueError('FUNDING_CONTROL_MISSED: direct operator edge')
        check(original + '\n// Comment-only change must not expire the premise.\n')
        # Deposit already has a legitimate coordinator->custody transfer.
        # Altering another branch does not give Failed this capability.
        other = '      result.native_transfers = {accepted.principal_transfer};'
        if original.count(other) != 1:
            raise ValueError('other-branch control insertion point ambiguous')
        check(original.replace(other, other + funding))
        print('FAILED_FUNDING_TRIGGER_PRESENT; real subsidy mutation NOT_READY; no guard retirement')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        print(e)
        raise SystemExit(1)
