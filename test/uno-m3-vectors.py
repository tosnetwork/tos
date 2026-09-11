#!/usr/bin/env python3
"""Regenerate TEST-ONLY formal M3 inputs and their committed pre-state roots.

No node execution or live-chain claim. The wallet crate generates fresh proof
randomness, and its exported uno_crypto_verify_v2 checks the persisted input.
"""
import argparse
import pathlib
import subprocess


def run(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--cargo', default='cargo')
    parser.add_argument('--jobs', type=int, default=8)
    args = parser.parse_args()
    repo = pathlib.Path(__file__).resolve().parents[1]
    build = args.build.resolve()
    cache = (build / 'CMakeCache.txt').read_text()
    source = next(line.split('=', 1)[1] for line in cache.splitlines()
                  if line.startswith('CMAKE_HOME_DIRECTORY:INTERNAL='))
    if pathlib.Path(source).resolve() != repo:
        raise SystemExit('Build belongs to a different source tree; refusing stale tool selection')
    run('cmake', '--build', build, '--target', 'uno-m3-vector-tool', '--parallel', args.jobs)
    cargo_target = build / 'm3-vector-wallet-target'
    run(args.cargo, 'build', '--manifest-path', repo / 'uno/prover/Cargo.toml',
        '--example', 'm3-vectors', '--release', '--locked', '--offline',
        '--target-dir', cargo_target, '-j', args.jobs, cwd=repo)
    prover = cargo_target / 'release/examples/m3-vectors'
    codec = build / 'crypto/uno-m3-vector-tool'
    for scenario, fee in [('send', 11), ('collect1', 17), ('collect3', 17)]:
        target = args.output.resolve() / scenario
        target.mkdir(parents=True, exist_ok=True)
        run(prover, 'prepare', scenario, fee, target / 'public.txt')
        run(codec, 'prepare', scenario, target)
        names = ['candidate-1', 'candidate-2'] if scenario == 'send' else ['candidate-1']
        for name in names:
            run(prover, 'prove', scenario, target / 'request.txt', target / 'authorization.txt')
            run(codec, 'finish', target, name)
            run(prover, 'verify', scenario, target / (name + '.verify.txt'),
                target / (name + '.verified.txt'))
        if scenario == 'send':
            # Same request, hence same ID/context/witnesses, fresh authorization.
            if (target / 'candidate-1.boc').read_bytes() == (target / 'candidate-2.boc').read_bytes():
                raise SystemExit('Fresh SEND proofs unexpectedly identical')
    print('Four formal candidates accepted by uno_crypto_verify_v2; TEST DATA ONLY.')


if __name__ == '__main__':
    main()
