#!/usr/bin/env python3
"""Deterministically import TON's legacy jUSDT bridge into the TOS monorepo.

The importer pins the two official TON repositories by commit, removes deployed
network artifacts and old oracle sets, preserves the audited contract sources,
and creates a TOS-facing build tree without changing the bridge state machine.
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
PROJECT_REL = Path("crosschain/legacy-jusdt-bridge")

UPSTREAMS = {
    "tvm": {
        "repository": "https://github.com/ton-blockchain/token-bridge-func.git",
        "commit": "4e7ec44a651e6b455ce5a09ed1383535fae3a637",
        "license": "GPL-3.0",
    },
    "evm": {
        "repository": "https://github.com/ton-blockchain/token-bridge-solidity.git",
        "commit": "ac5f58a6d28857d7b653d8f76f7d8ca58811a1c3",
        "license": "GPL-3.0",
    },
}

NETWORKS = {
    "ethereum": {"config_param": 79, "evm_chain_id": 1},
    "bsc": {"config_param": 81, "evm_chain_id": 56},
    "polygon": {"config_param": 82, "evm_chain_id": 137},
}

TVM_DEPLOYMENT_SOURCES = {
    "build-collector.fif",
    "build-config79.fif",
    "max-varint.fif",
    "new-bridge.fif",
    "new-collector.fif",
    "new-multisig.fif",
}

GENERATED_PATHS = (
    Path("upstream"),
    Path("tvm/contracts"),
    Path("tvm/params"),
    Path("evm/contracts"),
    Path("evm/test"),
    Path("evm/scripts"),
    Path("evm/package.json"),
    Path("evm/package-lock.json"),
    Path("evm/hardhat.config.ts"),
    Path("evm/tsconfig.json"),
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
    if kind == "tvm":
        if rel.as_posix() in {"build-mainnet.txt", "build-testnet.txt"}:
            return True
        if name.endswith((".boc", ".addr")):
            return True
        if name.startswith("uf_public_keys_"):
            return True
    if kind == "evm" and rel.as_posix() == "scripts/deploy-mainnet-bridge.ts":
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


def tos_branding(text: str) -> str:
    # These substitutions are presentation-only. Opcodes, state layout, fee
    # checks, quorum rules, and signed payloads remain byte-for-byte equivalent.
    return (
        text.replace("https://bridge.ton.org/token/", "https://tos.network/bridge/token/")
        .replace("Toncoins", "TOS")
        .replace("TON->EVM", "TOS->EVM")
        .replace("EVM->TON", "EVM->TOS")
        .replace("TON Jetton", "TOS Jetton")
    )


def tos_asm_mnemonics(text: str) -> str:
    # The TOS assembler renamed the coin-amount mnemonics; the opcode bytes
    # (0xFA00/0xFA02) are unchanged, so generated code cells stay identical.
    return text.replace('"STGRAMS"', '"STTOMIS"').replace('"LDGRAMS"', '"LDTOMIS"')


def params_source(config_param: int, evm_chain_id: int) -> str:
    return f""";; Generated from the pinned TON token bridge params.fc.
;; TOS masterchain ConfigParam {config_param} selects EVM chain {evm_chain_id}.
const int CONFIG_PARAM_ID = {config_param};
const int MY_CHAIN_ID = {evm_chain_id};
const int LOG_BURN = 0xc0470ccf;
const int LOG_SWAP_PAID = 0xc0550ccf;
const int LOG_MINT_ON_MINTER = 0xc0660ccf;
const int LOG_BURN_ON_MINTER = 0xc0770ccf;

const int WORKCHAIN = 0;

() force_chain(slice addr) impure {{
  (int wc, _) = parse_std_addr(addr);
  throw_unless(333, wc == WORKCHAIN);
}}
"""


def make_active_tvm(project: Path) -> None:
    source = project / "upstream/tvm/src/func/jetton-bridge"
    destination = project / "tvm/contracts"
    destination.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.iterdir()):
        if path.suffix == ".fc" or path.name in TVM_DEPLOYMENT_SOURCES:
            text = tos_branding(path.read_text(encoding="utf-8"))
            if path.suffix == ".fc":
                text = tos_asm_mnemonics(text)
            (destination / path.name).write_text(text, encoding="utf-8")

    params_dir = project / "tvm/params"
    params_dir.mkdir(parents=True, exist_ok=True)
    for network, values in NETWORKS.items():
        (params_dir / f"{network}.fc").write_text(
            params_source(values["config_param"], values["evm_chain_id"]),
            encoding="utf-8",
        )
    shutil.copy2(params_dir / "ethereum.fc", destination / "params.fc")


def make_active_evm(project: Path) -> None:
    source = project / "upstream/evm"
    destination = project / "evm"
    for rel in ("contracts", "test", "scripts"):
        src = source / rel
        if src.exists():
            shutil.copytree(src, destination / rel, dirs_exist_ok=True)
    for name in ("package.json", "package-lock.json", "hardhat.config.ts", "tsconfig.json"):
        src = source / name
        if src.exists():
            (destination / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, destination / name)


def iter_manifest_files(project: Path) -> Iterable[Path]:
    roots = [project / "upstream", project / "tvm", project / "evm"]
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file() and "node_modules" not in path.parts and "artifacts" not in path.parts:
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
        "mode": "legacy-oracle-jusdt-bridge",
        "production_status": "disabled-until-independent-audit-and-governance-activation",
        "upstreams": UPSTREAMS,
        "tos_networks": NETWORKS,
        "excluded_upstream_artifacts": [
            "prebuilt BOCs and generated addresses",
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

    with tempfile.TemporaryDirectory(prefix="tos-jusdt-upstream-") as temp:
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
    with tempfile.TemporaryDirectory(prefix="tos-jusdt-check-") as temp:
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
        print("legacy jUSDT bridge import is reproducible")
    else:
        populate(repo_root)
        print(f"imported legacy jUSDT bridge into {repo_root / PROJECT_REL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
