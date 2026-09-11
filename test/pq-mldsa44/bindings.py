#!/usr/bin/env python3
"""Compile the public FunC binding and execute its BOC in the native VM."""
import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(build: Path, vectors: Path, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        source = d / 'verify.fc'
        source.write_text(f'#include "{ROOT}/crypto/smartcont/pq.fc";\n'
            'int main(cell message, cell context, cell signature, cell public_key) {\n'
            '  return pq_check_mldsa44(message, context, signature, public_key);\n}\n')
        asm = d / 'verify.fif'
        subprocess.run([str(build / 'crypto/func'), '-SPA', '-o', str(asm),
                        str(ROOT / 'crypto/smartcont/stdlib.fc'), str(source)], check=True)
        boc = output / 'verify.boc'
        script = d / 'assemble.fif'
        script.write_text(f'"PQ.fif" include\n"{asm}" include\n2 boc+>B "{boc}" B>file\n')
        subprocess.run([str(build / 'crypto/fift'), '-I', str(ROOT / 'crypto/fift/lib'),
                        '-s', str(script)], check=True)
        subprocess.run([str(build / 'crypto/pq/test-pq-mldsa44'), str(vectors),
                        str(output / 'func-transcript.tsv'), '--code', str(boc)], check=True)
        script.write_text('"PQ.fif" include\n<{ PQCHECKSIG_MLDSA44 }>c <s 24 u@\n'
                          '0xf93100 <> abort"wrong PQ opcode encoding"\n')
        subprocess.run([str(build / 'crypto/fift'), '-I', str(ROOT / 'crypto/fift/lib'),
                        '-s', str(script)], check=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--vectors', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    run(a.build.resolve(), a.vectors.resolve(), a.out.resolve())
