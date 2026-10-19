#!/usr/bin/env python3
"""Reproduce the SDK's FunC Token code and the related compiler fixtures.

Build func/fift first. Without --check, update the SDK embedding only.
--update-goldens is an explicit operation after independent source review.
No bytecode is modified in-place and no deployment is performed.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = (
    "token-minter/token-minter.fc",
    "token-wallet/token-wallet.fc",
    "tact-examples/token_SampleToken.code.fc",
    "tact-examples/token_TokenDefaultWallet.code.fc",
)
SDK = Path("sdk/js/packages/contracts/src/token/codes.ts")
GOLDEN_JSON = Path("crypto/func/auto-tests/legacy_tests.json")
GOLDEN_PY = Path("crypto/func/auto-tests/legacy_tester.py")


def tool(name: str, build: Path) -> Path:
    path = Path(os.environ.get(name.upper(), build / "crypto" / name)).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"missing executable {name}: {path}")
    return path


def compile_boc(source: Path, work: Path, build: Path) -> bytes:
    work.mkdir(parents=True, exist_ok=True)
    fif, boc = work / "code.fif", work / "code.boc"
    subprocess.run(
        [str(tool("func", build)), "-SPA", "-W", str(boc), "-o", str(fif), str(source)],
        cwd=source.parent,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [str(tool("fift", build)), str(fif)],
        cwd=source.parent,
        env=dict(os.environ, FIFTPATH=str(ROOT / "crypto/fift/lib")),
        check=True,
        capture_output=True,
        text=True,
    )
    result = boc.read_bytes()
    if not result.startswith(bytes.fromhex("b5ee9c72")):
        raise RuntimeError(f"compiler did not produce a standard BOC: {source}")
    return result


def root_hash(boc: bytes, work: Path, build: Path) -> str:
    path, script = work / "hash.boc", work / "hash.fif"
    path.write_bytes(boc)
    script.write_text(f'"{path}" file>B B>boc hashu . cr\n', encoding="utf-8")
    output = subprocess.run(
        [str(tool("fift", build)), str(script)],
        cwd=ROOT,
        env=dict(os.environ, FIFTPATH=str(ROOT / "crypto/fift/lib")),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not re.fullmatch(r"[0-9]+", output) or int(output) >= 2**256:
        raise RuntimeError(f"fift returned an invalid cell hash: {output!r}")
    return output


def render_sdk(master: bytes, wallet: bytes) -> str:
    header = """/**
 * Generated Token contract BOCs. Do not edit the hex manually.
 * Reproduce with: python3 scripts/update-token-code.py --check
 *
 * Sources (FunC reference contract family):
 * crypto/func/auto-tests/legacy_tests/token-minter/token-minter.fc
 * crypto/func/auto-tests/legacy_tests/token-wallet/token-wallet.fc
 *
 * The native TOL contracts are compiled and tested independently. These
 * constants do not silently switch existing SDK users to another code family.
 */

"""
    for name, data in (("TOKEN_MASTER_CODE_HEX", master), ("TOKEN_WALLET_CODE_HEX", wallet)):
        encoded = data.hex().upper()
        chunks = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
        header += (
            f"export const {name} =\n" + " +\n".join(f'  "{chunk}"' for chunk in chunks) + ";\n\n"
        )
    return header.rstrip() + "\n"


def python_goldens(text: str) -> dict[str, str]:
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "tests" for target in node.targets
        ):
            rows = ast.literal_eval(node.value)
            return {name: str(value) for name, value in rows}
    raise RuntimeError("compiler fixture list is missing from the Python runner")


def expected_goldens() -> dict[str, str]:
    from_json = dict(json.loads((ROOT / GOLDEN_JSON).read_text(encoding="utf-8")))
    from_python = python_goldens((ROOT / GOLDEN_PY).read_text(encoding="utf-8"))
    for name in FIXTURES:
        if name not in from_json or name not in from_python:
            raise RuntimeError(f"missing compiler fixture: {name}")
        if str(from_json[name]) != from_python[name]:
            raise RuntimeError(f"compiler fixture manifests disagree: {name}")
    return {name: str(from_json[name]) for name in FIXTURES}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--update-goldens", action="store_true")
    args = parser.parse_args()
    if args.check and args.update_goldens:
        parser.error("--check cannot update compiler goldens")
    build = args.build_dir.resolve()
    expected = expected_goldens()
    actual: dict[str, str] = {}
    compiled: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="token-code-") as directory:
        work = Path(directory)
        for index, name in enumerate(FIXTURES):
            source = ROOT / "crypto/func/auto-tests/legacy_tests" / name
            data = compile_boc(source, work / str(index), build)
            # Two independent compilations must agree before an embedding changes.
            repeated = compile_boc(source, work / f"repeat-{index}", build)
            if data != repeated:
                raise RuntimeError(f"non-deterministic compiler output: {name}")
            compiled[name] = data
            actual[name] = root_hash(data, work / str(index), build)
    stale = [name for name in FIXTURES if actual[name] != expected[name]]
    sdk = render_sdk(compiled[FIXTURES[0]], compiled[FIXTURES[1]])
    sdk_changed = (ROOT / SDK).read_text(encoding="utf-8") != sdk
    print(
        json.dumps(
            {
                "fixture_cell_hashes": actual,
                "stale_goldens": stale,
                "sdk_embedding_stale": sdk_changed,
            },
            sort_keys=True,
        )
    )
    if args.check:
        return 1 if stale or sdk_changed else 0
    if stale and not args.update_goldens:
        raise RuntimeError(
            "compiler goldens differ; review the source diff before explicitly updating them"
        )
    if args.update_goldens:
        json_text = (ROOT / GOLDEN_JSON).read_text(encoding="utf-8")
        py_text = (ROOT / GOLDEN_PY).read_text(encoding="utf-8")
        for name in stale:
            old, new = expected[name], actual[name]
            if json_text.count(f'"{old}"') != 1 or len(re.findall(rf"\b{old}\b", py_text)) != 1:
                raise RuntimeError(f"expected hash is not uniquely pinned: {name}")
            json_text = json_text.replace(f'"{old}"', f'"{new}"')
            py_text = re.sub(rf"\b{old}\b", new, py_text)
        (ROOT / GOLDEN_JSON).write_text(json_text, encoding="utf-8")
        (ROOT / GOLDEN_PY).write_text(py_text, encoding="utf-8")
    (ROOT / SDK).write_text(sdk, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Token code reproduction failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stdout or "", file=sys.stderr)
            print(error.stderr or "", file=sys.stderr)
        raise SystemExit(2) from error
