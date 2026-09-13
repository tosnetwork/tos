"""Archive exact committed inputs needed to reproduce the profile reference CI checks (native dependencies are pinned by source commit)."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    baseline = json.loads((ROOT/'test/validator-auth-p0/production-baseline.json').read_text())
    paths = set(baseline['source_sha256']) | {
        'doc/validator-auth-p0', 'doc/validator-auth-p0-freeze.json', 'test/validator-auth-p0', 'third-party/tl-parser',
        'doc/validator-auth-p0-native-insertions.json',
        'tl/generate/scheme', 'validator/consensus', 'AGENTS.md',
        '.github/workflows/validator-auth-p0-profile.yml'}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('wb') as output:
        subprocess.run(['git', 'archive', '--format=tar', 'HEAD', *sorted(paths)], cwd=ROOT,
                       stdout=output, check=True, timeout=60)


if __name__ == '__main__':
    main()
