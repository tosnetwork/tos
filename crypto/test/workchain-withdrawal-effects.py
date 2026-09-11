#!/usr/bin/env python3
"""D51 execution-effect check, separate from the AST capability trigger.

Compare complete serialized account fixtures before/after real statement calls.
LIMIT: these are committed account fixtures, NOT a published Native ShardAccounts
root. No claim of full Native authenticated-cut enforcement or immunity to all
side effects follows. Writes outside the observed fixture set are not covered.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def unchanged(before, paths):
    after = {name: path.read_bytes() for name, path in paths.items()}
    if before != after:
        raise RuntimeError('withdrawal.account_fixture_changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    with tempfile.TemporaryDirectory(prefix='uno-statement-effects-') as directory:
        scratch = Path(directory)
        crate = scratch / 'crypto'
        crate.mkdir()
        for name in ('Cargo.toml', 'Cargo.lock', 'build.rs', 'cbindgen.toml'):
            shutil.copy2(repo / 'uno/crypto' / name, crate / name)
        for name in ('src', 'include'):
            shutil.copytree(repo / 'uno/crypto' / name, crate / name)
        (crate / 'vendor').symlink_to(repo / 'uno/crypto/vendor', target_is_directory=True)
        (crate / 'examples').mkdir()
        shutil.copy2(repo / 'crypto/test/workchain-withdrawal-effects.rs',
                     crate / 'examples/withdrawal-effects.rs')
        paths = {name: scratch / name for name in ('alice.boc', 'bob.boc')}
        before = {name: (repo / 'crypto/test/workchain-m3-vectors/send' / name).read_bytes()
                  for name in paths}
        if before['alice.boc'] == before['bob.boc']:
            raise RuntimeError('mutation fixture has no distinguishable replacement')
        def restore():
            for name, path in paths.items():
                path.write_bytes(before[name])
        environment = dict(os.environ, UNO_EFFECT_SOURCE=str(paths['bob.boc']),
                           UNO_EFFECT_DEST=str(paths['alice.boc']))
        command = ['cargo', 'run', '--locked', '--offline', '--manifest-path',
                   str(crate / 'Cargo.toml'), '--target-dir', str(args.target.resolve()),
                   '--example', 'withdrawal-effects']
        def execute():
            run = subprocess.run(command, env=environment, text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if run.returncode or 'STATEMENT_SUCCESS=success' not in run.stdout or \
                    'STATEMENT_DECODE=decode' not in run.stdout:
                raise RuntimeError('execution fixture failed, not an effect rejection:\n' + run.stdout)
        restore()
        execute()
        unchanged(before, paths)
        print('BASELINE: successful and rejected statement calls; complete account files unchanged', flush=True)
        statement = (crate / 'src/withdrawal_statement.rs').read_bytes()
        callee = crate / 'src/relation.rs'
        original = callee.read_text()
        anchor = 'pub(crate) fn validate_limits(limits: &KernelLimits) -> Result<(), Error> {'
        if original.count(anchor) != 1:
            raise RuntimeError('callee control site changed; control was not installed')
        mutation = '''
    std::fs::copy(std::env::var("UNO_EFFECT_SOURCE").expect("source fixture"),
                  std::env::var("UNO_EFFECT_DEST").expect("destination fixture"))
        .map_err(|_| Error::UNO_CRYPTO_ARGUMENTS)?;
'''
        callee.write_text(original.replace(anchor, anchor + mutation))
        execute()
        if (crate / 'src/withdrawal_statement.rs').read_bytes() != statement:
            raise RuntimeError('control unexpectedly edited statement')
        if paths['alice.boc'].read_bytes() != before['bob.boc']:
            raise RuntimeError('callee did not perform the intended account replacement')
        try:
            unchanged(before, paths)
        except RuntimeError as error:
            if str(error) != 'withdrawal.account_fixture_changed':
                raise
            print('RED: withdrawal.account_fixture_changed; actual callee write observed', flush=True)
        else:
            raise RuntimeError('effect control was silently accepted')
        callee.write_text(original)
        restore()
        execute()
        unchanged(before, paths)
        print('RESTORED: unchanged; no Native publication or full authenticated-cut claim', flush=True)


if __name__ == '__main__':
    main()
