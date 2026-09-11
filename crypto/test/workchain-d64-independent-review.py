#!/usr/bin/env python3
"""Replay B's independent matrix review on a pinned isolated source snapshot.
Not a production guard, proof-soundness audit or Native Withdrawal test.
"""
import argparse
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import os

REV = '5f628635d6afebbc11e9ccec8065ec1691c4e850'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, required=True)
    args = p.parse_args()
    archive = subprocess.check_output(['git', '-C', str(args.repo), 'archive', REV, 'uno/crypto'])
    with tempfile.TemporaryDirectory(prefix='uno-d64-independent-') as directory:
        root = Path(directory)
        with tarfile.open(fileobj=io.BytesIO(archive)) as t:
            t.extractall(root, filter='data')
        crate = root / 'uno/crypto'
        lib = crate / 'src/lib.rs'
        lib.write_text(lib.read_text() + '\n#[cfg(test)] mod independent_d64_review;\n')
        (crate / 'src/independent_d64_review.rs').write_bytes(Path(__file__).with_suffix('.rs').read_bytes())
        env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()))
        def run(label, expected):
            r = subprocess.run(['cargo', 'test', '--manifest-path', str(crate/'Cargo.toml'),
                '--locked', '--offline', '--lib', 'independent_d64', '--', '--nocapture'],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            print(label, 'exit', r.returncode)
            if r.returncode != expected or (expected == 0 and '2 passed; 0 failed' not in r.stdout) or (
                    expected != 0 and 'independent_d64_matrix_every_coefficient_target_and_range ... FAILED' not in r.stdout):
                print(r.stdout)
                raise RuntimeError('unexpected review/control result')
        run('baseline', 0)
        relation = crate / 'src/relation.rs'
        original = relation.read_text()
        mutations = [
            ('witness-index-control', 'push(&[(2, g), (3, h)], p[6])?;',
             'push(&[(1, g), (3, h)], p[6])?;'),
            ('range-object-control', 'p[6] - g, vmax - p[6]', 'p[4] - g, vmax - p[6]'),
        ]
        for label, old, new in mutations:
            if original.count(old) != 1:
                raise RuntimeError('mutation anchor mismatch')
            relation.write_text(original.replace(old, new))
            run(label, 101)
            relation.write_text(original)
        run('restored', 0)
        print('PINNED_D64_REVIEW_PASS: static/dense-matrix checks only; no proof or host execution')


if __name__ == '__main__':
    main()
