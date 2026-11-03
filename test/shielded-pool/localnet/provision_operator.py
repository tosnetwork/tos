"""Provision one relayer operator on the isolated network with an onion endpoint.

The provider's own `--provision` writes the operator's keys, Bond StateInit and
configuration; this script gives it the pool the local deployment recorded and
the onion name the SOCKS stand-in will admit, funds the operator's wallet once
from the genesis wallet, deploys and activates the Bond through the provider's
own bootstrap, writes the service configuration with `onion_endpoint` and the
relayer profile the shielded client reads, and runs the service's own check.

Fee and funding cap follow the earlier local operators (0.3 and 0.5 TOS).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import chain
from localnet_common import (
    Localnet,
    LocalnetError,
    run_measured,
    sha256_file,
    utc_now,
    write_private_json,
)

JSON = dict[str, Any]
FEE = 300_000_000
FUNDING_CAP = 500_000_000
FUNDING = 20 * 10**9
RELAYER_PROFILE_SCHEMA = "tos.shield.relayer-profile.v1"


def provision_input(net: Localnet, deployed: JSON, operator_dir: Path) -> JSON:
    manifest = deployed["manifest"]
    network = net.network()
    return {
        "schema": "tos.br1.provision.v1",
        "global_id": 3,
        "genesis_root": network["zerostate_root"],
        "genesis_file": network["zerostate_file"],
        "pool": manifest["address"],
        "pool_code_hash": manifest["code_hash"],
        "pool_config_hash": manifest["pool_config_hash"],
        "execution_domain": manifest["execution_domain"],
        "endpoint": f"http://{net.onion}",
        "fee": FEE,
        "funding_cap": FUNDING_CAP,
        "rpc_url": net.rpc_url,
        "proof_verifier": {
            "executable": str(net.proof_verify),
            "anchor_file": str(net.anchor_file),
            "liteserver_config": str(net.liteserver_config),
            "material_dir": None,
            "live_state_file": str(operator_dir / "proof-state.json"),
            "live_max_age_seconds": 30,
            "timeout_seconds": 12,
            "min_interval_ms": 0,
        },
        "proof_verifier_sha256": sha256_file(net.proof_verify),
    }


def provider(net: Localnet, operator_dir: Path, *args: str) -> JSON:
    completed = run_measured([str(net.provider), *args], cwd=operator_dir, timeout=600)
    if not completed.ok():
        raise LocalnetError(f"provider {' '.join(args)}: {completed.stderr.strip()[-2000:]}")
    return json.loads(completed.stdout.strip().splitlines()[-1])


def bootstrap(net: Localnet, operator_dir: Path, bond: str) -> list[JSON]:
    """Deploy then activate the Bond, each exactly once, waiting for the chain."""
    records: list[JSON] = []
    marker = operator_dir / "bond-deploy-started"
    if not marker.exists():
        marker.write_text("one bootstrap; reconcile on unknown outcome\n")
        records.append(provider(net, operator_dir, "--bootstrap", "deploy-bond"))
    chain.wait_active(net, bond)
    marker = operator_dir / "bond-activate-started"
    if not marker.exists():
        marker.write_text("one bootstrap; reconcile on unknown outcome\n")
        records.append(provider(net, operator_dir, "--bootstrap", "activate-bond"))
    return records


def service_config(net: Localnet, operator_dir: Path, config: JSON) -> JSON:
    return {
        "schema": "tos.br1.localnet.config.v1",
        "mode": "localnet",
        "release": config["release"],
        "backend": str(net.provider),
        "backend_sha256": sha256_file(net.provider),
        "state_dir": str(operator_dir),
        "journal": str(operator_dir / "journal.db"),
        "port": net.operator_port,
        "fee": FEE,
        "funding_cap": FUNDING_CAP,
        "max_reserved": 1_000_000_000,
        "max_pending": 2,
        "onion_endpoint": f"http://{net.onion}",
    }


def relayer_profile(operator_dir: Path, config: JSON) -> JSON:
    return {
        "schema": RELAYER_PROFILE_SCHEMA,
        "release": config["release"],
        "bond_init_b64": base64.b64encode((operator_dir / "bond-init.boc").read_bytes()).decode(),
    }


def check(net: Localnet, service_json: Path, attempts: int = 30) -> JSON:
    """`br1.py --check` verifies the Bond and its endpoint on chain; the Bond's
    activation takes a few blocks to land, so the check is retried."""
    last = ""
    for _ in range(attempts):
        completed = run_measured(
            [str(net.python), str(net.br1_py), "--config", str(service_json), "--check"],
            timeout=120,
        )
        if completed.ok():
            return json.loads(completed.stdout.strip().splitlines()[-1])
        last = completed.stderr.strip()[-500:]
        time.sleep(3)
    raise LocalnetError(f"the service check kept refusing: {last}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--localnet", type=Path, required=True)
    parser.add_argument("--pool", type=Path, required=True, help="the deploy_pool output directory")
    parser.add_argument("--out", type=Path, required=True, help="new private operator directory")
    args = parser.parse_args()
    net = Localnet.load(args.localnet)
    deployed = json.loads((args.pool / "deployed.json").read_text())
    operator_dir: Path = args.out
    if operator_dir.exists():
        raise SystemExit(f"{operator_dir} exists; an operator is provisioned once")
    operator_dir.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)

    template = operator_dir.parent / f"{operator_dir.name}-provision.json"
    write_private_json(template, provision_input(net, deployed, operator_dir))
    provisioned = provider(
        net, operator_dir.parent, "--provision", str(template), str(operator_dir)
    )
    config = json.loads((operator_dir / "provider.json").read_text())
    funding_wallet = str(config["funding_wallet"])
    bond = str(config["release"]["bond"])

    if chain.account_state(net, funding_wallet) != "active":
        chain.fund(
            net,
            funding_wallet,
            FUNDING,
            init_boc=(operator_dir / "funding-init.boc").read_bytes(),
            marker=operator_dir / "funding-send-started",
        )
        chain.wait_active(net, funding_wallet)
    bootstrapped = bootstrap(net, operator_dir, bond)

    service_json = operator_dir / "service.json"
    write_private_json(service_json, service_config(net, operator_dir, config))
    profile_path = operator_dir / "relayer-profile.json"
    write_private_json(profile_path, relayer_profile(operator_dir, config))
    checked = check(net, service_json)

    record = {
        "schema": "tos.shield.localnet.operator.v1",
        "utc": utc_now(),
        "provisioned": provisioned,
        "bootstrap": bootstrapped,
        "check": checked,
        "release": config["release"],
        "funding_wallet": funding_wallet,
        "endpoint": f"http://{net.onion}",
        "port": net.operator_port,
        "fee": FEE,
        "funding_cap": FUNDING_CAP,
        "provider_sha256": sha256_file(net.provider),
        "relayer_profile_sha256": sha256_file(profile_path),
        "start": [
            str(net.python),
            str(net.br1_py),
            "--config",
            str(service_json),
        ],
    }
    write_private_json(operator_dir / "operator.json", record)
    print(json.dumps({"bond": bond, "funding_wallet": funding_wallet, "check": checked}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
