#!/usr/bin/env python3
"""Compile the public inspection registry. No runtime compiler or remote ABI lookup."""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from native import compile_contract  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--func", required=True)
    parser.add_argument("--fift", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--network-tag", default="4242424242424242424242424242424242424242424242424242424242424242"
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.network_tag):
        parser.error("network-tag must be 32 lowercase hex bytes")
    os.environ.update(FUNC_PATH=args.func, FIFT_PATH=args.fift)
    args.output = args.output.resolve()
    out = args.output.parent
    out.mkdir(parents=True, exist_ok=True)
    source_dir = out / "source"
    source_dir.mkdir(exist_ok=True)
    for source in (ROOT / "crypto/smartcont").glob("*.fc"):
        shutil.copyfile(source, source_dir / source.name)
    compiled = []
    for family, source in (
        ("pq_highload_mldsa44_v1", "pq-highload-wallet-code.fc"),
        ("mldsa44_auth_module_v1", "mldsa44-auth-module.fc"),
        ("falcon512_padded_auth_module_v1", "falcon512-auth-module.fc"),
        ("quantum_fee_vault_v3", "wallet-quantum-fee-vault.fc"),
    ):
        cell = compile_contract(source, out / (family + ".boc"))
        compiled.append((family, cell))
    vault = compiled[-1][1]
    embed = f'cell compiled_vault() asm "B{{{vault.boc().hex()}}} B>boc PUSHREF";\n'
    wrapper = source_dir / "module.fc"
    wrapper.write_text(
        '#include "wallet-quantum-module.fc";\n'
        + embed
        + "cell quantummodule_vault_code() inline { return compiled_vault(); }\n"
    )
    module = compile_contract(str(wrapper), out / "quantum_module_v1.boc")
    compiled.append(("quantum_module_v1", module))
    wrapper = source_dir / "wallet.fc"
    wrapper.write_text(
        '#include "wallet-quantum-code.fc";\n'
        + embed
        + f"int quantumwallet_network() inline {{ return 0x{args.network_tag}; }}\n"
        + f"int quantumwallet_module_hash() inline {{ return 0x{module.hash.hex()}; }}\n"
        + "cell quantumwallet_vault_code() inline { return compiled_vault(); }\n"
    )
    wallet = compile_contract(str(wrapper), out / "quantum_wallet_v4.boc")
    compiled.append(("quantum_wallet_v4", wallet))
    sources = {
        p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((ROOT / "crypto/smartcont").glob("*.fc"))
    }
    sources["scripts/build-explorer-pq-registry.py"] = hashlib.sha256(
        Path(__file__).read_bytes()
    ).hexdigest()
    manifest = {
        "format": "tos-explorer-pq-registry/1",
        "decoder_revision": 1,
        "release_status": "review_candidate",
        "quantum_wallet_network_tag": args.network_tag,
        "sources": sources,
        "compilers": {
            name: hashlib.sha256(Path(value).read_bytes()).hexdigest()
            for name, value in (("func", args.func), ("fift", args.fift))
        },
        "codes": [
            {
                "family": family,
                "code_hash": cell.hash.hex(),
                "boc_sha256": hashlib.sha256(cell.boc()).hexdigest(),
            }
            for family, cell in compiled
        ],
    }
    revision = hashlib.sha256(
        json.dumps(
            {"codes": manifest["codes"], "decoder_revision": 1, "network_tag": args.network_tag},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    manifest["registry_revision"] = revision
    args.output.with_suffix(".json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    text = 'static constexpr char kRegistryRevision[] = "' + revision + '";\n'
    text += 'static constexpr char kQuantumNetwork[] = "' + args.network_tag + '";\n'
    text += "static constexpr struct { const char* family; const char* boc; } kRegistryCode[] = {\n"
    text += "".join(
        '{"' + family + '", "' + base64.b64encode(cell.boc()).decode() + '"},\n'
        for family, cell in compiled
    )
    args.output.write_text(text + "};\n")


if __name__ == "__main__":
    main()
