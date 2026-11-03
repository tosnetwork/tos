"""Deploy the ceremony-key local pool that `local_ceremony_pool` built.

The generator is run here so the deployed StateInit, the manifest and the
client's profile all come from one invocation of one recorded binary; the
genesis wallet then funds the pool's reserve floor with the StateInit
attached. The deployment is read back through the node and held against the
manifest: the code hash, the configuration cell and the getters must say what
the generator said. This is for an isolated local network only.

The generator is deterministic, so the same parameters give the same StateInit
and the same address. When that address is already active, the pool on the
chain is the one this generator describes, byte for byte; it is adopted after
the same read-back rather than deployed again, and the record says so.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import chain
from localnet_common import (
    Localnet,
    LocalnetError,
    get_method,
    run_measured,
    sha256_file,
    utc_now,
    write_private_json,
)

JSON = dict[str, Any]
DEPLOY_VALUE = 100 * 10**9


def generate(net: Localnet, out: Path) -> JSON:
    completed = run_measured(
        [
            str(net.local_ceremony_pool),
            str(net.tos_root),
            str(net.ceremony_dir),
            str(net.phase1_dir),
            str(out),
        ],
        timeout=1800,
    )
    if not completed.ok():
        raise LocalnetError(f"the generator refused: {completed.stderr.strip()[-2000:]}")
    manifest = json.loads((out / "pool.json").read_text())
    if manifest.get("development_verifying_key") is not False or manifest.get("global_id") != 3:
        raise LocalnetError("the generator did not produce an isolated ceremony-key pool")
    return manifest


def read_back(net: Localnet, manifest: JSON, *, fresh: bool) -> JSON:
    address = str(manifest["address"])
    info = chain.wait_active(net, address)
    observed = {
        "state": info.get("state"),
        "balance": int(info.get("balance", 0)),
        "code_hash": chain.code_hash_hex(info),
        "commitment_root": str(get_method(net.rpc_url, address, "commitment_root")),
        "commitment_next_index": get_method(net.rpc_url, address, "commitment_next_index"),
        "nullifier_root": str(get_method(net.rpc_url, address, "nullifier_root")),
        "reserve_floor": get_method(net.rpc_url, address, "reserve_floor"),
        "recovery_charge": get_method(net.rpc_url, address, "recovery_charge"),
    }
    expected = {
        "code_hash": manifest["code_hash"],
        "reserve_floor": int(manifest["reserve_floor_nanotos"]),
    }
    if fresh:
        expected["commitment_root"] = manifest["commitment_root"]
        expected["nullifier_root"] = manifest["nullifier_root"]
    for key, value in expected.items():
        if observed[key] != value:
            raise LocalnetError(f"deployed pool {key} {observed[key]!r} is not {value!r}")
    if fresh and observed["commitment_next_index"] != 0:
        raise LocalnetError("the pool already holds notes")
    first = chain.transactions(net, address, limit=1)
    observed["last_transaction_lt"] = int(first[0]["transaction_id"]["lt"]) if first else 0
    return observed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--localnet", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="new directory for the pool")
    args = parser.parse_args()
    net = Localnet.load(args.localnet)
    out: Path = args.out
    if out.exists():
        raise SystemExit(f"{out} exists; a pool is deployed once")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.mkdir(mode=0o700)
    generated = out / "generated"
    manifest = generate(net, generated)
    address = str(manifest["address"])
    adopted = chain.account_state(net, address) == "active"
    if adopted:
        # The account at the generator's address holds exactly this StateInit:
        # the address is the StateInit's hash. Nothing is sent.
        (out / "adopted").write_text("active before this run; same StateInit by address\n")
    else:
        init_boc = (generated / "state-init.boc").read_bytes()
        chain.fund(
            net, address, DEPLOY_VALUE, init_boc=init_boc, marker=out / "deploy-send-started"
        )
    observed = read_back(net, manifest, fresh=not adopted)
    record = {
        "schema": "tos.shield.localnet.pool-deployment.v1",
        "utc": utc_now(),
        "adopted": adopted,
        "generator": {
            "path": str(net.local_ceremony_pool),
            "sha256": sha256_file(net.local_ceremony_pool),
        },
        "state_init_sha256": sha256_file(generated / "state-init.boc"),
        "deploy_value_nanotos": None if adopted else str(DEPLOY_VALUE),
        "manifest": manifest,
        "observed": observed,
    }
    write_private_json(out / "deployed.json", record)
    print(json.dumps({"address": address, "code_hash": manifest["code_hash"], "adopted": adopted}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
