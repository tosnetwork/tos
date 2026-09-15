"""Falsify sanitizer visibility using the actual focused executable link command."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def main(build, out):
    if sys.platform != 'linux':
        raise RuntimeError('This ELF linker regression requires Linux')
    build = build.resolve()
    target = 'test-p0-keyring-sanitized'
    commands = subprocess.check_output(
        ['ninja', '-C', str(build), '-t', 'commands', target], text=True).splitlines()
    # CMake surrounds its one compiler invocation with no-op shell commands.
    links = [line for line in commands if ' -o test/validator-auth-implementation/' + target + ' ' in line]
    if len(links) != 1:
        raise RuntimeError('Expected one native sanitizer link command')
    command = links[0].strip()
    if not (command.startswith(': && ') and command.endswith(' && :')):
        raise RuntimeError('Unrecognized CMake link command')
    args = shlex.split(command[5:-5])
    index = args.index('-o') + 1
    executable = build / args[index]
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:detect_stack_use_after_return=1',
               UBSAN_OPTIONS='halt_on_error=1')
    with tempfile.TemporaryDirectory(prefix='p0-sanitizer-link-') as tmp:
        baseline = subprocess.run([str(executable), str(Path(tmp) / 'baseline')],
                                  capture_output=True, text=True, env=env)
        if baseline.returncode != 0:
            raise RuntimeError(baseline.stdout + baseline.stderr)
        mutant = Path(tmp) / 'hidden-runtime'
        args[index] = str(mutant)
        args.append('-Wl,--exclude-libs,ALL')
        subprocess.run(args, cwd=build, check=True, capture_output=True, text=True)
        result = subprocess.run([str(mutant), str(Path(tmp) / 'mutant')],
                                capture_output=True, text=True, env=env)
        if result.returncode != 1 or result.stderr.strip() != 'ASSERTION: sanitizer-runtime-visibility':
            raise RuntimeError(f'Expected a visibility assertion, got {result.returncode}: {result.stderr}')
        if (Path(tmp) / 'mutant').exists():
            raise RuntimeError('Broken runtime reached fixture creation')
    out.write_text(json.dumps({'baseline_passed': True, 'mutant_linked': True,
                              'assertion_failed': True, 'fixture_not_entered': True}, indent=2) + '\n')
    print('PASS: sanitizer link visibility; hidden runtime rejected before fixture creation')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    main(args.build, args.out)
