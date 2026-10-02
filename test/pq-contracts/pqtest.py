"""Shared helpers for the post-quantum contract suites, NOT a production SDK.

Contracts run on the real C++ executor through test/auth-extensions/native.py, at global
version 16 unless a test says otherwise. Signatures come from the TEST ONLY signer in this
directory, whose keys 0..255 are public.
"""

import functools
import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import (  # noqa: E402,F401 (re-exported for the suites)
    Cell,
    from_boc,
    make_dict,
    read_dict,
)

MLDSA44 = 1
KEY_BYTES = 1312
SIGNATURE_BYTES = 2420


def configure(build, signer):
    """Point native.py at a build tree and this suite at a signer; returns the native module."""
    build = Path(build).resolve()
    for name in ("libemulator.so", "libemulator.dylib", "emulator.dll"):
        if (build / "emulator" / name).exists():
            os.environ["EMULATOR_PATH"] = str(build / "emulator" / name)
            break
    else:
        raise SystemExit(f"no emulator library under {build / 'emulator'}")
    os.environ["FUNC_PATH"] = str(build / "crypto/func")
    os.environ["FIFT_PATH"] = str(build / "crypto/fift")
    os.environ["TOL_PATH"] = str(build / "tol/tol")
    os.environ["PQ_TEST_SIGNER"] = str(Path(signer).resolve())
    import native

    return native


def compile_source(source, output):
    """Compile a FunC or Tol source with PQ.fif loaded, as PQCHECKSIG_MLDSA44 requires."""
    source, output = Path(source).resolve(), Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    asm = output.with_suffix(".fif")
    if source.suffix == ".fc":
        cmd = [
            os.environ["FUNC_PATH"],
            "-SPA",
            "-o",
            str(asm),
            str(ROOT / "crypto/smartcont/stdlib.fc"),
            str(source),
        ]
        subprocess.run(cmd, check=True, capture_output=True)
    else:
        env = dict(os.environ, TOL_STDLIB=str(ROOT / "crypto/smartcont/tol-stdlib"))
        subprocess.run(
            [os.environ["TOL_PATH"], "-o", str(asm), str(source)],
            check=True,
            env=env,
            capture_output=True,
        )
    run = output.with_suffix(".run.fif")
    run.write_text(
        f'"Asm.fif" include\n"PQ.fif" include\n"{asm}" include\n2 boc+>B "{output}" B>file\n'
    )
    subprocess.run(
        [
            os.environ["FIFT_PATH"],
            "-I",
            f"{ROOT}/crypto/fift/lib:{ROOT}/crypto/smartcont",
            "-s",
            str(run),
        ],
        check=True,
        capture_output=True,
    )
    return from_boc(output.read_bytes())


def chain(data):
    """Canonical byte chain: 127 bytes per non-final cell, one continuation each."""
    parts = [data[i : i + 127] for i in range(0, len(data), 127)] or [b""]
    tail = None
    for part in reversed(parts):
        node = Cell().raw(part)
        if tail is not None:
            node.ref(tail)
        tail = node
    return tail


def stored(data):
    """pq-bytes.fc's stored shape for a key or a signature: len:uint32 ^chain."""
    return Cell().uint(len(data), 32).ref(chain(data))


def key_id(public_key):
    """pq::key_id: SHA-256("TOS-PQ-CONSENSUS-KEY-v1" || u16_le(1) || key bytes)."""
    return int.from_bytes(
        hashlib.sha256(b"TOS-PQ-CONSENSUS-KEY-v1" + bytes([MLDSA44, 0]) + public_key).digest(),
        "big",
    )


@functools.lru_cache(maxsize=None)
def _sign(key, message, context):
    line = f"{key} {message.hex() or '-'} {context.hex() or '-'}\n"
    result = subprocess.run(
        [os.environ["PQ_TEST_SIGNER"]], input=line, text=True, capture_output=True, check=True
    )
    public_key, signature = (bytes.fromhex(x) for x in result.stdout.split())
    assert len(public_key) == KEY_BYTES and len(signature) == SIGNATURE_BYTES
    return public_key, signature


def public_key(key):
    return _sign(key, b"", b"")[0]


def sign(key, message, context):
    return _sign(key, bytes(message), bytes(context))[1]


def details_of(result):
    """The transaction outcome, or an assertion if the emulator refused to run it."""
    assert result["success"], f"emulator refused the message: {result.get('error')}"
    return result["details"]
