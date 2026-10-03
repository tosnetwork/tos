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


def run(report, argv, results_path=None, report_path=None):
    """Runs the calling module's tests and writes, besides the measurements in `report`,
    a structured result for mutations.py: how many tests ran, and which failed an assertion
    (failures) as opposed to breaking (errors). Returns the process exit status."""
    import json
    import unittest

    outcome = unittest.main(argv=argv, exit=False, verbosity=2).result
    if results_path:
        Path(results_path).write_text(
            json.dumps(
                {
                    "testsRun": outcome.testsRun,
                    "failures": [test.id() for test, _ in outcome.failures],
                    "errors": [test.id() for test, _ in outcome.errors],
                },
                indent=2,
            )
            + "\n"
        )
    if report_path:
        Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if outcome.wasSuccessful() else 1


def _method_id(name):
    crc = 0
    for byte in name.encode():
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc | 0x10000


def _stack_value(value):
    if -(1 << 63) <= value < (1 << 63):
        return Cell().uint(0x01, 8).sint(value, 64)
    # vm_stk_int#0201_: the trailing "_" drops the final 1 bit, leaving 15 bits.
    return Cell().uint(0x0201 >> 1, 15).sint(value, 257)


def _encode_stack(values):
    """VmStack of integers, the last value on top."""
    rest = Cell()
    for value in values:
        node = _stack_value(value)
        rest = Cell(node.bits, [rest] + node.refs)
    return (
        Cell().uint(len(values), 24)
        if not values
        else Cell(Cell().uint(len(values), 24).bits + rest.bits, rest.refs)
    )


def _decode_stack(cell):
    s = cell.slice()
    depth = s.uint(24)
    values = []
    for _ in range(depth):
        rest = s.ref()
        tag = s.uint(8)
        if tag == 0x01:
            values.append(s.sint(64))
        elif tag == 0x02 and s.uint(7) == 0:
            values.append(s.sint(257))
        elif tag == 0x00:
            values.append(None)
        else:
            values.append(("unsupported", tag))
        s = rest.slice()
    return list(reversed(values))


def get_method(
    code, data, address, method, args=(), global_version=16, unixtime=None, balance=10**9
):
    """Runs a get-method on the real TVM emulator, with c7 built from the test configuration
    at `global_version`. Returns (exit code, values bottom to top)."""
    import ctypes
    import json

    import native

    lib = ctypes.CDLL(os.environ["EMULATOR_PATH"])
    lib.tvm_emulator_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    lib.tvm_emulator_create.restype = ctypes.c_void_p
    lib.tvm_emulator_set_c7.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_uint32,
        ctypes.c_uint64,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    lib.tvm_emulator_set_c7.restype = ctypes.c_bool
    lib.tvm_emulator_run_get_method.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
    lib.tvm_emulator_run_get_method.restype = ctypes.c_void_p
    lib.tvm_emulator_destroy.argtypes = [ctypes.c_void_p]
    lib.string_destroy.argtypes = [ctypes.c_void_p]
    lib.emulator_set_verbosity_level(0)
    emulator = lib.tvm_emulator_create(code.b64(), data.b64(), 0)
    assert emulator, "the TVM emulator must load the code and data"
    try:
        assert lib.tvm_emulator_set_c7(
            emulator,
            f"{address[0]}:{address[1]:064x}".encode(),
            native.NOW if unixtime is None else unixtime,
            balance,
            b"00" * 32,
            native.config(global_version).b64(),
        )
        raw = lib.tvm_emulator_run_get_method(
            emulator, _method_id(method), _encode_stack(list(args)).b64()
        )
        try:
            result = json.loads(ctypes.string_at(raw))
        finally:
            lib.string_destroy(raw)
    finally:
        lib.tvm_emulator_destroy(emulator)
    assert result["success"], result
    return result["vm_exit_code"], _decode_stack(
        from_boc(__import__("base64").b64decode(result["stack"]))
    )
