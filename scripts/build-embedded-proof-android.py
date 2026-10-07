#!/usr/bin/env python3
"""Build the C proof verifier from current source for an Android ABI."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--host-build', type=Path, required=True)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--abi', choices=['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'], default='arm64-v8a')
    parser.add_argument('--api', type=int, default=26)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    host = args.host_build.resolve()
    target = args.build_dir.resolve()
    ndk = args.ndk.resolve()
    if host == target or target == root or args.api < 26 or not 1 <= args.jobs <= 32:
        parser.error('Use separate host/target builds, API >= 26, and 1..32 jobs')
    cache = host / 'CMakeCache.txt'
    if not cache.is_file() or f'CMAKE_HOME_DIRECTORY:INTERNAL={root}' not in cache.read_text().splitlines():
        parser.error('Host build must be configured from this source checkout')
    toolchain = ndk / 'build/cmake/android.toolchain.cmake'
    if not toolchain.is_file():
        parser.error('NDK toolchain not found')
    env = os.environ.copy()
    if sys.platform == 'darwin':
        env['SDKROOT'] = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip()
    # Refresh all public generated contract sources through their real dependencies.
    subprocess.run(['cmake', '--build', str(host), '--target', 'smc-envelope', '-j', str(args.jobs)], env=env, check=True)
    sources = sorted((host / 'crypto/smartcont/auto').glob('*.cpp'))
    if not sources:
        raise RuntimeError('Host contract generation produced no sources')
    subprocess.run(['cmake', '-S', str(root), '-B', str(target), '-G', 'Ninja',
                    f'-DCMAKE_TOOLCHAIN_FILE={toolchain}', f'-DANDROID_ABI={args.abi}',
                    f'-DANDROID_PLATFORM=android-{args.api}', '-DANDROID_CPP_FEATURES=exceptions rtti',
                    '-DCMAKE_BUILD_TYPE=Release', '-DTOS_ONLY_TOSLIB=ON', '-DTOS_ARCH='], check=True)
    destination = target / 'crypto/smartcont/auto'
    destination.mkdir(parents=True, exist_ok=True)
    for source in sources:
        shutil.copy2(source, destination / source.name)
    subprocess.run(['cmake', '--build', str(target), '--target', 'tos-proof-embedded', '-j', str(args.jobs)], check=True)


if __name__ == '__main__':
    main()
