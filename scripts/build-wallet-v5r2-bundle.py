#!/usr/bin/env python3
"""Build or reproduce a reviewable V5R2 candidate from an explicit chain config.

The bundle contains ordinary, self-contained code, its exact source and public
wire/crypto/KDF vectors. It is not a reviewed release, a wallet enrollment, a
custody backup, or authorization to activate the candidate configuration.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import from_boc, read_dict  # noqa: E402
from native import compile_contract  # noqa: E402

FORMAT = "tos-wallet-v5r2-review-bundle/1"
SMARTCONT = ROOT / "crypto/smartcont"
ENTRYPOINTS = ("wallet-v5r2-fee-vault.fc", "wallet-v5r2-module.fc", "wallet-v5r2-code.fc")
PUBLIC_FILES = (
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "crypto/smartcont/wallet-v5r2-rescue.tlb",
    "crypto/block/block.tlb",
    "crypto/vm/pqops.h",
    "crypto/vm/pqops.cpp",
    "crypto/vm/excno.hpp",
    "crypto/pq/lms-fee.h",
    "crypto/pq/lms-fee.cpp",
    "crypto/pq/wallet-pq-signer-c.h",
    "crypto/fift/lib/Asm.fif",
    "crypto/fift/lib/Fift.fif",
    "test/auth-extensions/native.py",
    "test/auth-extensions/cells.py",
    "doc/tvm-lms-fee-hash.md",
    "doc/auth-policy-v1.md",
    "test/rescue-fee-gate/suite-scenarios.tsv",
    "test/rescue-fee-gate/suite-expected.tsv",
    "test/rescue-fee-gate/fee-kdf-vectors.json",
    "test/pq-mldsa44/fixtures.json",
    "test/pq-falcon512/vectors.json",
    "tosctl/src/wallet-pq-signer/tests/fixtures/dual-root-kdf.json",
    "tosctl/src/wallet-pq-signer/tests/fixtures/lms-fee-signature.json",
    "tosctl/src/wallet-pq-signer/tests/fixtures/native-fee-recovery.json",
    "tosctl/src/tos-native-mnemonic/tests/fixtures/native-pq.json",
    "tosctl/src/vm/src/executor/pq.rs",
    "tosctl/src/vm/src/executor/lms_fee.rs",
    "tosctl/src/vm/src/executor/engine/handlers.rs",
)


def digest(raw):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def config_identity(raw):
    root = from_boc(raw)
    if len(root.bits) != 256 or len(root.refs) != 1:
        raise ValueError("a complete ConfigParams BOC is required")
    params = read_dict(root.refs[0], 32)
    version = params[8].refs[0].slice()
    if version.uint(8) != 0xC4 or version.uint(32) != 18:
        raise ValueError("bundle requires the explicit version-18 candidate")
    version.uint(64)
    version.end()
    global_id = params[19].refs[0].slice()
    network_id = global_id.sint(32)
    global_id.end()
    policy = params[48].refs[0].slice()
    if policy.uint(8) != 0xA1:
        raise ValueError("candidate lacks the expected AUTH policy")
    network = policy.uint(256)
    gas = {}
    for parameter, expected_credit in ((20, 10000), (21, 20000)):
        prices = params[parameter].refs[0].slice()
        tag = prices.uint(8)
        if tag == 0xD1:
            prices.uint(128)
            tag = prices.uint(8)
        if tag not in (0xDD, 0xDE):
            raise ValueError("invalid gas-price constructor")
        prices.uint(64)
        gas_limit = prices.uint(64)
        if tag == 0xDE:
            prices.uint(64)
        credit = prices.uint(64)
        block_limit = prices.uint(64)
        prices.uint(128)
        prices.end()
        if credit != expected_credit or (
            parameter == 21 and (gas_limit, block_limit) != (30000000, 60000000)
        ):
            raise ValueError("configuration is not the explicit admission candidate")
        gas[str(parameter)] = {
            "gas_limit": gas_limit,
            "block_gas_limit": block_limit,
            "gas_credit": credit,
        }
    return {
        "version": 18,
        "global_id": network_id,
        "network": f"{network:064x}",
        "gas": gas,
        **digest(raw),
    }


def source_files():
    found = set()

    def visit(name):
        path = (SMARTCONT / name).resolve()
        if not path.is_relative_to(SMARTCONT) or not path.is_file():
            raise ValueError("contract include escaped its source directory")
        if path in found:
            return
        found.add(path)
        for include in re.findall(r'#include\s+"([^"]+)"\s*;', path.read_text()):
            visit(str(path.parent.relative_to(SMARTCONT) / include))

    for name in (*ENTRYPOINTS, "stdlib.fc"):
        visit(name)
    return sorted(found)


def public_files():
    files = [ROOT / name for name in PUBLIC_FILES]
    files += sorted((ROOT / "tosctl/src/node-control/contracts/tests/fixtures/v5r2").glob("*.json"))
    files += sorted((ROOT / "tosctl/src/node-control/contracts/src").glob("wallet_v5r2*.rs"))
    files += [ROOT / "tosctl/src/wallet-pq-signer/src/kdf.rs"]
    return files


def build_bundle(config, output):
    identity = config_identity(config)
    sources = source_files()
    inputs = {
        path.relative_to(ROOT).as_posix(): path.read_bytes() for path in [*sources, *public_files()]
    }
    inputs["scripts/build-wallet-v5r2-bundle.py"] = Path(__file__).read_bytes()
    files = {}

    def put(relative, raw):
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        files[relative] = digest(raw)

    put("config.boc", config)
    for name, raw in inputs.items():
        put("repository/" + name, raw)
    with tempfile.TemporaryDirectory(prefix="v5r2-bundle-build-") as directory:
        work = Path(directory)
        for path in sources:
            target = work / path.relative_to(SMARTCONT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(inputs[path.relative_to(ROOT).as_posix()])
        codes = {}
        vault = compile_contract(str(work / ENTRYPOINTS[0]), work / "vault.boc")
        embed = f'cell embedded_vault() asm "B{{{vault.boc().hex()}}} B>boc PUSHREF";\n'
        wrappers = {
            "module": '#include "wallet-v5r2-module.fc";\n'
            + embed
            + "cell r2module_vault_code() inline { return embedded_vault(); }\n"
        }
        (work / "module.fc").write_text(wrappers["module"])
        module = compile_contract(str(work / "module.fc"), work / "module.boc")
        wrappers["wallet"] = (
            '#include "wallet-v5r2-code.fc";\n'
            + embed
            + f"int r2wallet_network() inline {{ return 0x{identity['network']}; }}\n"
            + f"int r2wallet_module_hash() inline {{ return 0x{module.hash.hex()}; }}\n"
            + "cell r2wallet_vault_code() inline { return embedded_vault(); }\n"
        )
        (work / "wallet.fc").write_text(wrappers["wallet"])
        wallet = compile_contract(str(work / "wallet.fc"), work / "wallet.boc")
        for name, cell in (("vault", vault), ("module", module), ("wallet", wallet)):
            raw = (work / f"{name}.boc").read_bytes()
            # The ordinary-cell decoder rejects library/exotic cells at any depth.
            decoded = from_boc(raw)
            if decoded.hash != cell.hash:
                raise ValueError("compiled code representation hash mismatch")
            nodes, pending = set(), [decoded]
            while pending:
                node = pending.pop()
                if node.hash in nodes:
                    continue
                nodes.add(node.hash)
                pending.extend(node.refs)
            put(f"code/{name}.boc", raw)
            codes[name] = {
                "code_hash": cell.hash.hex(),
                "cells": len(nodes),
                "depth": cell.depth,
                "external_libraries": 0,
                **digest(raw),
            }
        for name, text in wrappers.items():
            put(f"wrappers/{name}.fc", text.encode())
        for name in ("module", "wallet"):
            assembly = (work / f"{name}.fif").read_text()
            if "CHKSIGN" in assembly:
                raise ValueError("classical signature opcode in PQ wallet candidate")
    constants = {}
    literal_errors = {}
    for path in sources:
        name = path.relative_to(ROOT).as_posix()
        text = inputs[name].decode()
        constants[name] = dict(re.findall(r"const\s+int\s+([\w:]+)\s*=\s*([^;]+);", text))
        literal_errors[name] = sorted(
            {int(value) for value in re.findall(r"\bthrow(?:_if|_unless)?\s*\(\s*(\d+)", text)}
        )
    put(
        "abi/contract-constants.json",
        json_bytes(
            {
                "constant_expressions": constants,
                "literal_error_codes": literal_errors,
                "scope": "Source expressions and numeric throw operands; canonical wire schemas and SDK codecs are included verbatim.",
            }
        ),
    )
    for name, raw in inputs.items():
        if (ROOT / name).read_bytes() != raw:
            raise RuntimeError("source changed during bundle build: " + name)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = subprocess.run(["git", "diff", "--quiet", "HEAD"], cwd=ROOT).returncode
    if dirty not in (0, 1):
        raise RuntimeError("cannot identify the source tree state")
    tools = {
        name: digest(Path(os.environ[name]).read_bytes()) for name in ("FUNC_PATH", "FIFT_PATH")
    }
    manifest = {
        "format": FORMAT,
        "status": "unapproved-review-candidate",
        "source_revision": revision,
        "tracked_working_tree_changes": bool(dirty),
        "config": identity,
        "code": codes,
        "compiler_binaries": tools,
        "files": files,
        "scope": __doc__,
        "remaining_release_gates": [
            "independent source/crypto review",
            "complete ACVP and adversarial acceptance corpus",
            "mobile and real-network recovery",
            "hardware admission calibration",
            "final-head CI and activation approval",
        ],
    }
    (output / "manifest.json").write_bytes(json_bytes(manifest))
    return manifest


def check_bundle(bundle, fresh):
    stored = json.loads((bundle / "manifest.json").read_text())
    if stored.get("format") != FORMAT or stored.get("status") != "unapproved-review-candidate":
        raise ValueError("unknown bundle format or acceptance status")
    if fresh.get("format") != FORMAT or fresh.get("status") != "unapproved-review-candidate":
        raise ValueError("unknown expected bundle format or acceptance status")
    for key in ("config", "code", "files"):
        if stored.get(key) != fresh[key]:
            raise ValueError("bundle differs from current sources: " + key)
    expected = set(fresh["files"]) | {"manifest.json"}
    actual = {path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file()}
    if actual != expected:
        raise ValueError("bundle file set differs")
    for name, expected_digest in fresh["files"].items():
        path = bundle / name
        if path.is_symlink() or digest(path.read_bytes()) != expected_digest:
            raise ValueError("bundle file digest differs: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--output-dir", type=Path)
    selection.add_argument("--check", type=Path)
    parser.add_argument(
        "--config", type=Path, help="Explicit generated ConfigParams; required for a new bundle"
    )
    parser.add_argument(
        "--expected-manifest",
        type=Path,
        help="Independently retained candidate config/code/source identities to require",
    )
    args = parser.parse_args()
    os.environ.setdefault("FUNC_PATH", str(ROOT / "build/crypto/func"))
    os.environ.setdefault("FIFT_PATH", str(ROOT / "build/crypto/fift"))
    if args.output_dir:
        if args.config is None:
            parser.error("--output-dir requires --config")
        config = args.config.read_bytes()
        config_identity(config)  # Refuse missing/old profiles before creating the output.
        args.output_dir.mkdir(parents=True, exist_ok=False)
        manifest = build_bundle(config, args.output_dir)
    else:
        config = (args.config or (args.check / "config.boc")).read_bytes()
        with tempfile.TemporaryDirectory(prefix="v5r2-bundle-check-") as directory:
            manifest = build_bundle(config, Path(directory))
            check_bundle(args.check, manifest)
    if args.expected_manifest is not None:
        expected = json.loads(args.expected_manifest.read_text())
        check_bundle(args.output_dir or args.check, expected)
    print(
        json.dumps(
            {
                "status": "candidate_bundle_reproduced"
                if args.check
                else "candidate_bundle_created",
                "code": manifest["code"],
                "config": manifest["config"],
                "files": len(manifest["files"]),
            }
        )
    )


if __name__ == "__main__":
    main()
