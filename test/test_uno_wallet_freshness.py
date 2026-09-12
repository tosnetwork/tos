#!/usr/bin/env python3
"""Real stale-wallet control; failure must be at the source pin, before requests."""
import argparse
import ast
from pathlib import Path
import shutil
import subprocess
import tempfile
from uno_wallet_freshness import identity, pin


def expect_stale(repo, binary, output, checker=pin):
    try:
        checker(repo, binary, output)
    except RuntimeError as error:
        assert str(error).startswith('WALLET_FRESHNESS_MISMATCH:'), str(error)
        assert not (output / 'wallet-freshness.json').exists()
        print('EXPECTED_RED at source pin: ' + str(error), flush=True)
        return
    raise AssertionError('STALE_WALLET_ACCEPTED: freshness oracle failed to reject')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='wallet-pin-control-') as temporary:
        root = Path(temporary)
        for package in ('crypto', 'prover'):
            shutil.copytree(args.repo / 'uno' / package, root / 'uno' / package,
                            ignore=shutil.ignore_patterns('target', '.git', '__pycache__'))
        (root / 'test').mkdir()
        shutil.copyfile(args.repo / 'test/uno-m3-live.py', root / 'test/uno-m3-live.py')
        shutil.copyfile(args.repo / 'test/uno_wallet_freshness.py', root / 'test/uno_wallet_freshness.py')
        command = ['cargo', 'build', '--locked', '--offline', '--release', '--example', 'm3-scenario',
                   '--manifest-path', str(root / 'uno/prover/Cargo.toml'), '--target-dir', str(args.target.resolve()), '-j', '2']
        subprocess.run(command, cwd=root / 'uno/prover', check=True)
        built = args.target.resolve() / 'release/examples/m3-scenario'
        old = pin(root, built, root / 'old')
        original = identity(root)
        # Same-size semantic change, not a tag-length change or missing-field failure.
        source = root / 'uno/crypto/src/withdrawal_statement.rs'
        data = source.read_text()
        assert data.count('uno-v2/withdrawal-opening') == 1
        source.write_text(data.replace('uno-v2/withdrawal-opening', 'uno-v2/withdrawal-openinh'))
        assert identity(root) != original
        expect_stale(root, old, root / 'stale')
        # Run the real live entry point: stale rejection precedes all Native commands.
        build = root / 'build'; build.mkdir()
        (build / 'CMakeCache.txt').write_text(
            f'CMAKE_HOME_DIRECTORY:INTERNAL={root}\nTOS_UNO_CRYPTO_NODE_LINK:BOOL=ON\n')
        wallet_path = build / 'm3-vector-wallet-target/release/examples/m3-scenario'
        wallet_path.parent.mkdir(parents=True); shutil.copyfile(old, wallet_path); wallet_path.chmod(0o500)
        live = subprocess.run(['python3', str(root / 'test/uno-m3-live.py'), '--build', str(build)],
                              text=True, capture_output=True)
        assert live.returncode != 0 and 'WALLET_FRESHNESS_MISMATCH:' in live.stderr, live.stderr
        print('EXPECTED_RED real live entry point at WALLET_FRESHNESS_MISMATCH', flush=True)
        # Semantic mutation: bypass the live runner's pin, not its diagnostic text.
        runner = root / 'test/uno-m3-live.py'
        runner_text = runner.read_text()
        assignments = [node for node in ast.walk(ast.parse(runner_text))
                       if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                       and isinstance(node.value.func, ast.Name) and node.value.func.id == 'pin']
        assert len(assignments) == 1, 'live pin mutation site changed'
        node = assignments[0]; lines = runner_text.splitlines(keepends=True)
        lines[node.lineno - 1:node.end_lineno] = [f'wallet = Path({str(wallet_path)!r})\n']
        runner.write_text(''.join(lines))
        bypassed = subprocess.run(['python3', str(runner), '--build', str(build)], text=True, capture_output=True)
        try:
            assert bypassed.returncode != 0 and 'WALLET_FRESHNESS_MISMATCH:' in bypassed.stderr, 'LIVE_PIN_NOT_ENFORCED'
        except AssertionError as error:
            assert str(error) == 'LIVE_PIN_NOT_ENFORCED'
            print('EXPECTED_RED live pin removed: LIVE_PIN_NOT_ENFORCED (other failures are not pin evidence)', flush=True)
        else:
            raise AssertionError('live pin removal mutation did not reach the observer')
        runner.write_text(runner_text)


        # The observer must fail when its pin is removed, with the stale binary retained.
        try:
            expect_stale(root, old, root / 'disabled', checker=lambda *unused: old)
        except AssertionError as error:
            assert str(error).startswith('STALE_WALLET_ACCEPTED:')
            print('EXPECTED_RED oracle disabled: ' + str(error), flush=True)
        else:
            raise AssertionError('disabled freshness oracle went unnoticed')
        subprocess.run(command, cwd=root / 'uno/prover', check=True)
        fresh = pin(root, built, root / 'fresh')
        assert fresh.read_bytes() != old.read_bytes()
        # Execute a business command only on the newly pinned snapshot.
        request = root / 'key.txt'; request.write_text('secret=101\n')
        subprocess.run([str(fresh), 'key', str(request), str(root / 'key.out')], check=True)
        assert (root / 'key.out').read_text().startswith('public_key=')
        # Restoring source makes the old pin valid and the changed binary stale.
        source.write_text(data)
        assert identity(root) == original
        pin(root, old, root / 'restored')
        expect_stale(root, fresh, root / 'reverse-stale')
        print('PASS real build / stale red / disabled-oracle red / rebuilt green / restored green', flush=True)


if __name__ == '__main__':
    main()
