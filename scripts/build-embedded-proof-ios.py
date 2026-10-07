#!/usr/bin/env python3
"""Build the in-process proof library for one Apple mobile platform slice."""
import argparse
import os
import re
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-build', type=Path, required=True)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--sdk', choices=['iphoneos', 'iphonesimulator'], required=True)
    parser.add_argument('--arch', choices=['arm64', 'x86_64'], required=True)
    parser.add_argument('--minimum', default='15.0')
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9]+\.[0-9]+', args.minimum):
        parser.error('Minimum version must be a numeric major.minor value')
    root = Path(__file__).resolve().parents[1]
    host, target = args.host_build.resolve(), args.build_dir.resolve()
    if host == target or target == root or (args.sdk == 'iphoneos' and args.arch != 'arm64') or not 1 <= args.jobs <= 32:
        parser.error('Use separate builds and a supported SDK/architecture pair')
    cache = host / 'CMakeCache.txt'
    if not cache.is_file() or f'CMAKE_HOME_DIRECTORY:INTERNAL={root}' not in cache.read_text().splitlines():
        parser.error('Host build must be configured from this source checkout')
    target_cache = target / 'CMakeCache.txt'
    if target_cache.exists():
        values = dict(re.findall(r'^([A-Za-z_][A-Za-z0-9_]*):[^=\r\n]+=(.*)$', target_cache.read_text(), re.MULTILINE))
        cached_sdk = values.get('CMAKE_OSX_SYSROOT', '')
        expected_sdk = subprocess.check_output(['xcrun', '--sdk', args.sdk, '--show-sdk-path'], text=True).strip()
        if values.get('CMAKE_HOME_DIRECTORY') != str(root) or values.get('CMAKE_OSX_ARCHITECTURES') != args.arch or values.get('CMAKE_OSX_DEPLOYMENT_TARGET') != args.minimum or cached_sdk not in (args.sdk, expected_sdk):
            parser.error('Use a separate build directory for each source/SDK/architecture slice')
    env = os.environ.copy()
    env['SDKROOT'] = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip()
    subprocess.run(['cmake', '--build', str(host), '--target', 'smc-envelope', '-j', str(args.jobs)], env=env, check=True)
    subprocess.run(['cmake', '-S', str(root), '-B', str(target), '-G', 'Ninja', '-DCMAKE_SYSTEM_NAME=iOS',
                    f'-DCMAKE_OSX_SYSROOT={args.sdk}', f'-DCMAKE_OSX_ARCHITECTURES={args.arch}',
                    f'-DCMAKE_OSX_DEPLOYMENT_TARGET={args.minimum}', '-DCMAKE_BUILD_TYPE=Release',
                    '-DTOS_ONLY_TOSLIB=ON', '-DTOS_ARCH=', '-DUSE_QUIC=OFF'], check=True)
    sources = list((host / 'crypto/smartcont/auto').glob('*.cpp'))
    if not sources:
        raise RuntimeError('Public contract generation produced no sources')
    destination = target / 'crypto/smartcont/auto'
    destination.mkdir(parents=True, exist_ok=True)
    for source in sources:
        shutil.copy2(source, destination / source.name)
    subprocess.run(['cmake', '--build', str(target), '--target', 'tos-proof-embedded', '-j', str(args.jobs)], check=True)
    library = target / 'lite-client/proof-verify/libtosproofverify.dylib'
    metadata = subprocess.check_output(['xcrun', 'vtool', '-show-build', str(library)], text=True)
    expected = 'IOSSIMULATOR' if args.sdk == 'iphonesimulator' else 'IOS'
    platform = [line.split()[-1] for line in metadata.splitlines() if line.strip().startswith('platform ')]
    if platform != [expected]:
        raise RuntimeError('Proof library has an unexpected Apple platform')
    print(metadata)


if __name__ == '__main__':
    main()
