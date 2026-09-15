"""Record a paired native C0 certificate measurement and its build identity."""
import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def source():
    paths = ['crypto/validator-auth', 'validator/auth',
             'test/validator-auth-implementation', 'crypto/CMakeLists.txt']
    files = git('ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', *paths)
    return {
        'head': git('rev-parse', 'HEAD').decode().strip(),
        'tracked_diff_sha256': hashlib.sha256(git('diff', 'HEAD', '--binary')).hexdigest(),
        'files': {name.decode(): digest(ROOT / name.decode()) for name in files.split(b'\0') if name},
    }


def run(args):
    build = args.build.resolve()
    binary = build / 'test/validator-auth-implementation/benchmark-p0-c0'
    cache = {}
    for line in (build / 'CMakeCache.txt').read_text().splitlines():
        if not line or line.startswith(('#', '//')) or '=' not in line or ':' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.split(':', 1)[0]
        if key.startswith(('CMAKE_CXX_', 'CMAKE_BUILD_TYPE', 'TOS_ARCH', 'OPENSSL_', 'SODIUM_')):
            cache[key] = value
    identity = source()
    binary_hash = digest(binary)
    compiler = subprocess.check_output([cache['CMAKE_CXX_COMPILER'], '--version'], text=True)
    measured = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
    timing = json.loads(measured.stdout)
    if source() != identity or digest(binary) != binary_hash:
        raise RuntimeError('source or binary changed during measurement')
    governors = {str(p): p.read_text().strip()
                 for p in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/cpufreq/scaling_governor')}
    evidence = {
        'source': identity, 'binary_sha256': binary_hash, 'compiler': compiler,
        'build': cache, 'host': platform.platform(),
        'governors': governors or {'available': False},
        'measurement': timing,
        'scope_limits': ['certificate verification only', 'allocation counts not instrumented',
                         'native propagation and session integration not measured'],
    }
    args.out.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps(timing))
    return 0 if not args.enforce or timing['within_budget'] else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--enforce', action='store_true')
    raise SystemExit(run(parser.parse_args()))
