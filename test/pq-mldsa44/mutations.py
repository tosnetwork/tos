#!/usr/bin/env python3
"""Remove one protection at a time; compilation failure is not a killed mutation."""
import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(build: Path, vectors: Path):
    def rebuild():
        subprocess.run(['cmake', '--build', str(build), '--target', 'test-pq-mldsa44', '-j2'], check=True)

    def check(output: Path):
        return subprocess.run([str(build / 'crypto/pq/test-pq-mldsa44'), str(vectors), str(output)],
                              text=True, capture_output=True, timeout=180)

    cases = [
        ('verification', ROOT / 'crypto/pq/mldsa44.cpp',
         'if (result == 0) {', 'if (result == 0 || result == MLD_ERR_INVALID_SIGNATURE) {'),
        ('version', ROOT / 'crypto/vm/pqops.cpp',
         '->require_version(pq_mldsa44_min_version)', '->require_version(15)'),
        ('base-gas', ROOT / 'crypto/vm/pqops.cpp',
         'st->consume_gas_chk(pq_mldsa44_base_gas);', 'st->consume_gas_chk(0);'),
        ('byte-gas', ROOT / 'crypto/vm/pqops.cpp',
         'st->consume_gas_chk(static_cast<long long>(size) * pq_mldsa44_byte_gas);',
         'st->consume_gas_chk(0);'),
        ('message-bound', ROOT / 'crypto/pq/mldsa44.cpp',
         'message.size() > mldsa44_max_message_bytes || ', ''),
        ('context', ROOT / 'crypto/pq/mldsa44.cpp',
         'm, message.size(), c, context.size(),', 'm, message.size(), c, 0,'),
        ('canonical-chunks', ROOT / 'crypto/vm/pqops.cpp',
         '(cs.size_refs() && size != 127)', '(false)'),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / 'result.tsv'
        baseline = check(out)
        if baseline.returncode:
            raise RuntimeError('baseline is not green: ' + baseline.stderr)
        for name, path, before, after in cases:
            original = path.read_text()
            if original.count(before) != 1:
                raise RuntimeError('mutation anchor must match exactly once: ' + name)
            try:
                path.write_text(original.replace(before, after))
                rebuild()
                result = check(out)
                if result.returncode != 1 or 'FAIL:' not in result.stderr:
                    raise RuntimeError(f'{name}: test must report an assertion failure, not success/crash: {result}')
                print('KILLED', name, result.stderr.strip(), flush=True)
            finally:
                path.write_text(original)
                rebuild()
            result = check(out)
            if result.returncode:
                raise RuntimeError('restored baseline failed: ' + result.stderr)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--vectors', type=Path, required=True)
    a = p.parse_args()
    run(a.build.resolve(), a.vectors.resolve())
