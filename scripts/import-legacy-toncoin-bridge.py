#!/usr/bin/env python3
"""Deterministically import TON's legacy Toncoin bridge into the TOS monorepo.

The importer pins the official TON coin-bridge repositories by commit — the
FunC plane once per supported external network branch and the Solidity plane
from master — removes deployed network artifacts and historical oracle sets,
and keeps the audited contract sources byte-for-byte except for assembler
mnemonic renames required by the TOS toolchain.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT_REL = Path("crosschain/legacy-toncoin-bridge")

UPSTREAMS = {
    "tvm-ethereum": {
        "repository": "https://github.com/ton-blockchain/bridge-func.git",
        "commit": "9b606d5b0c886a7b1bd4732a0ecaf0d5d2351354",
        "branch": "master",
        "license": "GPL-3.0",
    },
    "tvm-bsc": {
        "repository": "https://github.com/ton-blockchain/bridge-func.git",
        "commit": "01b5a05e13b1dd735821dfe2b208ad5c2dd5dec2",
        "branch": "bsc",
        "license": "GPL-3.0",
    },
    "evm": {
        "repository": "https://github.com/ton-blockchain/bridge-solidity.git",
        "commit": "f78adaf8bee30133a6231d7cfe36c9b29dd28613",
        "branch": "master",
        "license": "MIT",
    },
}

NETWORKS = {
    "ethereum": {"upstream": "tvm-ethereum", "config_param": 71, "evm_chain_id": 1},
    "bsc": {"upstream": "tvm-bsc", "config_param": 72, "evm_chain_id": 56},
}

GENERATED_PATHS = (
    Path("upstream"),
    Path("tvm"),
    Path("evm/contracts"),
    Path("evm/test"),
    Path("evm/migrations"),
    Path("evm/package.json"),
    Path("evm/truffle-config.js"),
    Path("UPSTREAM.lock.json"),
    Path("SOURCE_MANIFEST.sha256"),
)


def run(argv: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(argv, cwd=cwd, check=True)


def checkout(name: str, target: Path) -> None:
    spec = UPSTREAMS[name]
    target.mkdir(parents=True)
    run(["git", "init", "--quiet"], cwd=target)
    run(["git", "remote", "add", "origin", spec["repository"]], cwd=target)
    run(["git", "fetch", "--quiet", "--depth=1", "origin", spec["commit"]], cwd=target)
    run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=target)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    if head != spec["commit"]:
        raise RuntimeError(f"{name}: expected {spec['commit']}, checked out {head}")


def excluded(kind: str, rel: Path) -> bool:
    parts = rel.parts
    name = rel.name
    if ".git" in parts or "node_modules" in parts:
        return True
    if name in {".DS_Store", ".env"}:
        return True
    if kind.startswith("tvm"):
        if rel.as_posix() in {"build.txt", "build-testnet.txt"}:
            return True
        if name.endswith((".boc", ".addr")):
            return True
        if name.startswith("uf_public_keys"):
            return True
        # Committed upstream compile output; the TOS tree rebuilds it from source.
        if rel.as_posix() == "func/multisig-code.fif":
            return True
    return False


def copy_filtered(kind: str, source: Path, destination: Path) -> None:
    for path in sorted(source.rglob("*")):
        rel = path.relative_to(source)
        if excluded(kind, rel):
            continue
        if any(excluded(kind, Path(*rel.parts[:i])) for i in range(1, len(rel.parts) + 1)):
            continue
        output = destination / rel
        if path.is_dir():
            output.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, output)


def tos_asm_mnemonics(text: str) -> str:
    # The TOS assembler renamed the coin-amount mnemonics; the opcode bytes
    # (0xFA00/0xFA02) are unchanged, so generated code cells stay identical.
    return text.replace('"STGRAMS"', '"STTOMIS"').replace('"LDGRAMS"', '"LDTOMIS"')


def make_active_tvm(project: Path) -> None:
    for network, values in NETWORKS.items():
        source = project / "upstream" / values["upstream"] / "func"
        destination = project / "tvm" / network
        destination.mkdir(parents=True, exist_ok=True)
        for path in sorted(source.iterdir()):
            if path.suffix not in {".fc", ".fif"}:
                continue
            text = path.read_text(encoding="utf-8")
            if path.suffix == ".fc":
                text = tos_asm_mnemonics(text)
            (destination / path.name).write_text(text, encoding="utf-8")


def normalize_eth_sign_v(text: str) -> str:
    # The upstream harness assumes eth_sign returns v as 0/1 (ganache 6) and
    # unconditionally adds 27; current dev chains already return 27/28. This
    # test-only change normalizes either form and does not touch contracts.
    old = (
        "    signature = signature.slice(0, 2+2*64)"
        "+(parseInt(signature.slice(130),16)+27).toString(16);"
    )
    new = (
        "    let v = parseInt(signature.slice(130), 16);\n"
        "    if (v < 27) { v += 27; }\n"
        "    signature = signature.slice(0, 2+2*64)+v.toString(16);"
    )
    if old not in text:
        raise RuntimeError("upstream eth_sign v fix-up not found; re-audit the test harness patch")
    return text.replace(old, new)


def make_active_evm(project: Path) -> None:
    source = project / "upstream/evm"
    destination = project / "evm"
    for rel in ("contracts", "test", "migrations"):
        src = source / rel
        if src.exists():
            shutil.copytree(src, destination / rel, dirs_exist_ok=True)
    for name in ("package.json", "truffle-config.js"):
        src = source / name
        if src.exists():
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, destination / name)
    utils = destination / "test/utils/utils.js"
    utils.write_text(normalize_eth_sign_v(utils.read_text(encoding="utf-8")), encoding="utf-8")


def iter_manifest_files(project: Path) -> Iterable[Path]:
    for rel in GENERATED_PATHS:
        if rel.name in {"UPSTREAM.lock.json", "SOURCE_MANIFEST.sha256"}:
            continue
        root = project / rel
        if root.is_file():
            yield root
        elif root.is_dir():
            for path in sorted(root.rglob("*")):
                if path.is_file() and not {"node_modules", "artifacts", "build"} & set(path.parts):
                    yield path


def write_manifest(project: Path) -> None:
    lines = []
    for path in iter_manifest_files(project):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(project).as_posix()}")
    (project / "SOURCE_MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_lock(project: Path) -> None:
    payload = {
        "schema": 1,
        "mode": "legacy-oracle-toncoin-bridge",
        "production_status": "disabled-until-independent-audit-and-governance-activation",
        "upstreams": UPSTREAMS,
        "tos_networks": {
            name: {"config_param": values["config_param"], "evm_chain_id": values["evm_chain_id"]}
            for name, values in NETWORKS.items()
        },
        "excluded_upstream_artifacts": [
            "prebuilt BOCs, compiled Fift outputs, and generated addresses",
            "historical mainnet/testnet oracle key sets",
            "historical mainnet deployment command files",
            "local environment files",
        ],
    }
    (project / "UPSTREAM.lock.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def populate(repo_root: Path) -> None:
    project = repo_root / PROJECT_REL
    project.mkdir(parents=True, exist_ok=True)
    for rel in GENERATED_PATHS:
        path = project / rel
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()

    with tempfile.TemporaryDirectory(prefix="tos-toncoin-upstream-") as temp:
        temp_root = Path(temp)
        for kind in UPSTREAMS:
            checkout(kind, temp_root / kind)
            copy_filtered(kind, temp_root / kind, project / "upstream" / kind)

    make_active_tvm(project)
    make_active_evm(project)
    write_lock(project)
    write_manifest(project)


def tree_hashes(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    project = root / PROJECT_REL
    for rel in GENERATED_PATHS:
        path = project / rel
        if path.is_file():
            result[rel.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file():
                    key = child.relative_to(project).as_posix()
                    result[key] = hashlib.sha256(child.read_bytes()).hexdigest()
    return result


def check(repo_root: Path) -> None:
    actual = tree_hashes(repo_root)
    if not actual:
        raise RuntimeError("bridge sources are not imported; run without --check first")
    with tempfile.TemporaryDirectory(prefix="tos-toncoin-check-") as temp:
        expected_root = Path(temp)
        (expected_root / PROJECT_REL).mkdir(parents=True)
        populate(expected_root)
        expected = tree_hashes(expected_root)
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        changed = sorted(k for k in set(actual) & set(expected) if actual[k] != expected[k])
        raise RuntimeError(
            "import drift detected\n"
            f"missing={missing}\nextra={extra}\nchanged={changed}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="re-import in a temporary tree and compare")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    if args.check:
        check(repo_root)
        print("legacy Toncoin bridge import is reproducible")
    else:
        populate(repo_root)
        print(f"imported legacy Toncoin bridge into {repo_root / PROJECT_REL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
