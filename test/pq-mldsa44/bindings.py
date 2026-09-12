#!/usr/bin/env python3
"""Compile both public bindings and execute every vector in the native VM.

FunC inputs are separate source files (its #include resolution is relative to
its including file). Tol imports a byte-identical copy of the public binding.
Neither test defines its own replacement for the public PQ declaration.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(build: Path, vectors: Path, output: Path, execute: bool = True) -> None:
    """Compile both public bindings; execute the corpus through them unless asked not to.

    The differential driver needs the compiled programs alone, and compiles them
    the same way the shipped bindings are compiled rather than a second way.
    """
    output.mkdir(parents=True, exist_ok=True)
    tools = [build / 'crypto/func', build / 'crypto/fift', build / 'tol/tol']
    if execute:
        tools.append(build / 'crypto/pq/test-pq-mldsa44')
    for tool in tools:
        if not tool.is_file():
            raise FileNotFoundError(f'required binding test tool: {tool}')
    env = dict(os.environ, TOL_STDLIB=str(ROOT / 'crypto/smartcont/tol-stdlib'))
    with tempfile.TemporaryDirectory(prefix='tos-pq-bindings-') as tmp:
        directory = Path(tmp)
        func = directory / 'verify.fc'
        func.write_text(
            'int main(cell message, cell context, cell signature, cell public_key) {\n'
            '  return pq_check_mldsa44(message, context, signature, public_key);\n}\n',
            encoding='utf-8')
        func_asm = directory / 'func.fif'
        subprocess.run([str(build / 'crypto/func'), '-SPA', '-o', str(func_asm),
                        str(ROOT / 'crypto/smartcont/stdlib.fc'),
                        str(ROOT / 'crypto/smartcont/pq.fc'), str(func)], check=True)

        shutil.copyfile(ROOT / 'crypto/smartcont/pq.tol', directory / 'pq.tol')
        tol = directory / 'verify.tol'
        tol.write_text(
            'import "pq"\n'
            'fun main(message: cell, context: cell, signature: cell, publicKey: cell): bool {\n'
            '    return pqCheckMldsa44(message, context, signature, publicKey);\n}\n',
            encoding='utf-8')
        tol_asm = directory / 'tol.fif'
        subprocess.run([str(build / 'tol/tol'), '-o', str(tol_asm), str(tol)],
                       env=env, check=True)

        for language, assembly in (('func', func_asm), ('tol', tol_asm)):
            boc = output / f'{language}-verify.boc'
            script = directory / f'{language}-assemble.fif'
            script.write_text(f'"PQ.fif" include\n"{assembly}" include\n'
                              f'2 boc+>B "{boc}" B>file\n', encoding='utf-8')
            subprocess.run([str(build / 'crypto/fift'), '-I', str(ROOT / 'crypto/fift/lib'),
                            '-s', str(script)], check=True)
            if execute:
                subprocess.run([str(build / 'crypto/pq/test-pq-mldsa44'), str(vectors),
                                str(output / f'{language}-transcript.tsv'), '--code', str(boc)],
                               check=True)

        script = directory / 'encoding.fif'
        script.write_text('"PQ.fif" include\n<{ PQCHECKSIG_MLDSA44 }>c <s 24 u@\n'
                          '0xf93100 <> abort"wrong PQ opcode encoding"\n', encoding='utf-8')
        subprocess.run([str(build / 'crypto/fift'), '-I', str(ROOT / 'crypto/fift/lib'),
                        '-s', str(script)], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--vectors', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--programs-only', action='store_true',
                        help='compile the bindings without executing the corpus')
    args = parser.parse_args()
    run(args.build.resolve(), args.vectors.resolve(), args.out.resolve(),
        execute=not args.programs_only)
