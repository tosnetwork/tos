#!/usr/bin/env python3
# Copyright (C) 2025-2026 TOS Network.
"""Provision a small, real on-chain Agent Economy for local TOSCAN use.

The script is safe to re-run. Names and deployment addresses are retained in
the supplied tosctl config, while the genesis root prevents an old manifest
from being mistaken for data on a newly reset chain.
"""

import argparse
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from pytosiq_core import Address

REPO = Path(__file__).resolve().parents[1]
DEFAULT_TOSCTL = REPO / "tosctl/src/target/debug/tosctl"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000007"
NANO = 1_000_000_000
POLICY_HASH = "55" * 32


class Seeder:
    def __init__(self, args):
        self.rpc = args.rpc.rstrip("/")
        self.control = args.control.rstrip("/")
        self.config = Path(args.config).resolve()
        self.manifest = Path(args.manifest).resolve()
        self.tosctl = Path(args.tosctl).resolve()
        self.env = dict(os.environ)
        self.env["VAULT_URL"] = (
            f"file://{self.config.parent}/seed-vault.json?master_key={MASTER_KEY}"
        )

    def rpc_call(self, method: str, **params):
        payload = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        }).encode()
        request = urllib.request.Request(
            f"{self.rpc}/jsonRPC",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            value = json.loads(response.read().decode())
        if "error" in value:
            raise RuntimeError(f"{method}: {value['error']}")
        return value["result"]

    def run(self, *arguments: str, json_output: bool = False):
        command = [str(self.tosctl), *arguments]
        if json_output:
            command.extend(["--format", "json"])
        command.extend(["-c", str(self.config)])
        result = subprocess.run(
            command,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"{' '.join(command)} failed\n{result.stdout}\n{result.stderr}"
            )
        return json.loads(result.stdout) if json_output else result.stdout

    def config_data(self):
        return json.loads(self.config.read_text())

    def ensure_config(self):
        self.config.parent.mkdir(parents=True, exist_ok=True)
        if not self.config.exists():
            subprocess.run(
                [
                    str(self.tosctl), "config", "generate", "-o", str(self.config),
                    "--force",
                ],
                check=True,
                env=self.env,
            )
        config = self.config_data()
        config["chain_rpc"] = {"urls": [f"{self.rpc}/"], "api_key": None}
        config["elections"] = None
        config["voting"] = None
        config["master_wallet"] = None
        config["log"] = None
        self.config.write_text(json.dumps(config, indent=2) + "\n")

    def chain_id(self):
        return self.rpc_call("getMasterchainInfo")["init"]["root_hash"]

    def wait_for(self, predicate, label: str, timeout: float = 90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except Exception:
                pass
            time.sleep(1)
        raise TimeoutError(f"timed out waiting for {label}")

    def address_active(self, address: str):
        return self.rpc_call("getAddressState", address=address) == "active"

    def wallet_address(self, name: str):
        wallets = self.run("wallet", "ls", json_output=True)
        address = next(item["address"] for item in wallets if item["name"] == name)
        return Address(address).to_str(is_user_friendly=False).lower()

    def fund(self, address: str, minimum_tos: float):
        balance = int(self.rpc_call("getAddressInformation", address=address)["balance"])
        minimum = int(minimum_tos * NANO)
        if balance >= minimum:
            return
        amount = max(1.0, (minimum - balance) / NANO + 1.0)
        payload = json.dumps({"address": address, "amount": amount}).encode()
        request = urllib.request.Request(
            f"{self.control}/transfer",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=70) as response:
            result = json.loads(response.read().decode())
        if "error" in result:
            raise RuntimeError(result["error"])

    def ensure_wallet(self, name: str, minimum_tos: float = 50):
        if name not in self.config_data().get("wallets", {}):
            self.run("wallet", "create", "-n", name, "-v", "V3R2", "-w", "0")
        address = self.wallet_address(name)
        self.fund(address, minimum_tos)
        if not self.address_active(address):
            self.run("wallet", "activate", "-n", name)
            self.wait_for(lambda: self.address_active(address), f"wallet {name}")
        print(f"  wallet {name}: {address}")
        return address

    def ensure_deploy(self, section: str, name: str, command: list[str]):
        existing = self.config_data().get(section, {}).get(name)
        if existing and existing.get("address") and self.address_active(existing["address"]):
            print(f"  {name}: {existing['address']} (existing)")
            return existing["address"]
        output = self.run(*command, json_output=True)
        address = output["address"]
        self.wait_for(lambda: self.address_active(address), name)
        print(f"  {name}: {address}")
        return address

    def seed(self):
        self.ensure_config()
        chain_id = self.chain_id()
        if self.manifest.exists():
            existing = json.loads(self.manifest.read_text())
            addresses = existing.get("addresses", {})
            if (
                existing.get("chain_id") == chain_id
                and addresses
                and all(self.address_active(address) for address in addresses.values())
            ):
                print("TOSCAN Agent Economy seed already present:")
                print(json.dumps(existing, indent=2))
                return

        print("Provisioning real Agent Economy contracts ...")
        planner = self.ensure_wallet("alice-planner", 100)
        verifier = self.ensure_wallet("victor-verifier", 50)
        provider = self.ensure_wallet("nova-provider", 50)
        owner = self.ensure_wallet("atlas-owner", 50)
        reviewer = self.ensure_wallet("rhea-reviewer", 50)

        config = self.config_data()
        agent = config.get("agent_wallets", {}).get("atlas-research")
        if agent is None:
            self.run(
                "agent", "wallet", "create", "--name", "atlas-research",
                "-v", "V3R2", "-w", "0", "--max-per-tx", "2",
                "--daily-limit", "10",
            )
            agent = self.config_data()["agent_wallets"]["atlas-research"]
        agent_address = agent.get("agent_account_address")
        if not agent_address or not self.address_active(agent_address):
            output = self.run(
                "agent", "account", "deploy", "--wallet", "atlas-research",
                "--from", "alice-planner", "-w", "0", "--amount", "2", "--yes",
                json_output=True,
            )
            agent_address = output["address"]
            self.wait_for(lambda: self.address_active(agent_address), "Atlas Agent Account")
        print(f"  Atlas Research Agent: {agent_address}")

        registry = self.ensure_deploy(
            "capability_registries",
            "nova-capabilities",
            [
                "agent", "registry", "deploy", "--name", "nova-capabilities",
                "--owner", provider, "--verifier", verifier,
                "--task-categories-hash", "11" * 32,
                "--pricing-hash", "22" * 32,
                "--metadata-hash", "33" * 32,
                "--verification-method-hash", "44" * 32,
                "--bond", "1", "--from", "nova-provider", "--amount", "1.2",
                "-w", "0", "--yes",
            ],
        )
        service = self.ensure_deploy(
            "service_actors",
            "nova-inference",
            [
                "agent", "service", "deploy", "--name", "nova-inference",
                "--owner", provider, "--open-access", "--price-per-call", "0.05",
                "--storage-fee", "0.2", "--cleanup-bounty", "0.1",
                "--response-sla", "3600", "--refund-claim-window", "3600",
                "--rate-limit-per-day", "1000", "--metadata-hash", "33" * 32,
                "--proof-scheme-hash", "44" * 32, "--from", "nova-provider",
                "--amount", "2", "-w", "0", "--yes",
            ],
        )
        deadline = int(time.time()) + 30 * 24 * 3600
        task = self.ensure_deploy(
            "agent_tasks",
            "market-research",
            [
                "agent", "task", "create", "--name", "market-research",
                "--creator", planner, "--agent", agent_address, "--verifier", verifier,
                "--budget", "5", "--deadline", str(deadline), "--review-period", "3600",
                "--policy-hash", POLICY_HASH, "--from", "alice-planner",
                "--amount", "5.2", "-w", "0", "--yes",
            ],
        )
        dispute = self.ensure_deploy(
            "disputes",
            "quality-review",
            [
                "agent", "dispute", "deploy", "--name", "quality-review",
                "--claimant", planner, "--respondent", owner, "--reviewer", reviewer,
                "--deadline", str(deadline), "--subject-hash", "66" * 32,
                "--claimant-evidence-hash", "77" * 32,
                "--from", "alice-planner", "--amount", "0.2", "-w", "0", "--yes",
            ],
        )

        value = {
            "chain_id": chain_id,
            "seeded_at": int(time.time()),
            "addresses": {
                "agent_account": agent_address,
                "capability_registry": registry,
                "service_actor": service,
                "task_escrow": task,
                "dispute": dispute,
            },
        }
        self.manifest.parent.mkdir(parents=True, exist_ok=True)
        self.manifest.write_text(json.dumps(value, indent=2) + "\n")
        print("TOSCAN Agent Economy seed complete:")
        print(json.dumps(value, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc", default="http://127.0.0.1:8011")
    parser.add_argument("--control", default="http://127.0.0.1:8012")
    parser.add_argument("--config", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--tosctl", default=str(DEFAULT_TOSCTL))
    args = parser.parse_args()
    if not Path(args.tosctl).exists():
        parser.error(f"tosctl binary not found: {args.tosctl}")
    Seeder(args).seed()


if __name__ == "__main__":
    main()
