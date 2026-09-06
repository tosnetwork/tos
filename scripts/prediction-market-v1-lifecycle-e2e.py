#!/usr/bin/env python3
"""Run the direct-wallet PredictionMarket V1 lifecycle on three local nodes.

This is an opt-in acceptance harness.  It owns a fresh local validator network,
an owner-private temporary file Vault, and every wallet used by the run.  The
Agent Account signed-match scenario additionally proves the checked-call V2
source and destination recovery boundaries through a three-observer tosctl
resolver.  The OpenFox gate remains an independent verifier of that evidence.

Each normal-outcome scenario proves the complete contract exit path:

deploy -> register/deposit -> split -> normal quorum -> finalize -> claim ->
withdraw.  Every post-transition view must agree byte-for-byte across all
three JSON-RPC nodes.  All files, the encrypted local Vault, and validator
databases are removed when the process exits.

The reporter outcome is a deliberately controlled protocol input.  These
scenarios prove that the on-chain YES, NO, and INVALID accounting branches
execute over real nodes; they do not claim to prove an external fact.  The
separate real-entropy Oracle acceptance scenario must bind reporters to a
target fixed only after the wager is made.

Run from the TOS repository with an available validator build:

  TOS_BUILD_DIR=/absolute/path/to/build \
    /path/to/python scripts/prediction-market-v1-lifecycle-e2e.py
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
TOS = 1_000_000_000
OPERATION_BUDGET = TOS
WALLET_NAMES = ("owner", "normal_one", "normal_two", "appeal_one", "appeal_two", "reserve")
NORMAL_SCENARIO_FUNDED_WALLETS = ("owner", "normal_one", "normal_two", "reserve")
MATCH_SCENARIO_FUNDED_WALLETS = NORMAL_SCENARIO_FUNDED_WALLETS
CHALLENGED_SCENARIO_FUNDED_WALLETS = WALLET_NAMES
TRADING_PUBLIC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


class LocalnetFailed(RuntimeError):
    """A child validator process exited; retrying cannot make it healthy."""


def rpc(url: str, method: str, **params: Any) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{url}/jsonRPC",
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode())


def wait_until(predicate, description: str, timeout: float = 90.0) -> Any:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except LocalnetFailed:
            raise
        except Exception as error:  # network startup and block inclusion are expected races
            last_error = error
        time.sleep(1)
    suffix = f": {last_error}" if last_error else ""
    raise RuntimeError(f"timed out waiting for {description}{suffix}")


def canonical_raw_address(value: str) -> str:
    """Convert a user-friendly TOS address to its canonical raw form."""
    if value.count(":") == 1:
        workchain, account = value.split(":", 1)
        if workchain in ("-1", "0") and len(account) == 64 and all(item in "0123456789abcdef" for item in account):
            return value
        raise RuntimeError("raw wallet address is not canonical")
    encoded = value.strip().replace("-", "+").replace("_", "/")
    raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    if len(raw) != 36:
        raise RuntimeError("wallet address has invalid friendly-address length")
    workchain = int.from_bytes(raw[1:2], "big", signed=True)
    return f"{workchain}:{raw[2:34].hex()}"


class Lifecycle:
    def __init__(self, workdir: Path, tosctl: Path, rpc_urls: list[str], control_url: str,
                 evidence_dir: Path | None = None, openfox_root: Path | None = None):
        self.workdir = workdir
        self.tosctl = tosctl
        self.rpc_urls = rpc_urls
        self.control_url = control_url
        self.config = workdir / "tosctl.json"
        self.definition = workdir / "market.json"
        self.vault_dir = workdir / "vault"
        self.vault_dir.mkdir(mode=0o700)
        self.vault_dir.chmod(0o700)
        self.vault_url = (
            f"file://{self.vault_dir / 'vault.json'}?master_key={secrets.token_hex(32)}"
        )
        self.env = dict(os.environ)
        self.env["VAULT_URL"] = self.vault_url
        self.addresses: dict[str, str] = {}
        self.agent_authority_seed = secrets.token_bytes(32)
        self.agent_authority_public_key = self.ed25519_public_key(self.agent_authority_seed)
        self.agent_account_address: str | None = None
        self.agent_account_code_hash: str | None = None
        self.match_source_address: str | None = None
        self.match_source_code_hash: str | None = None
        self.evidence_dir = evidence_dir
        self.openfox_root = openfox_root

    def write_config(self, rpc_url: str | None = None) -> None:
        endpoint = rpc_url or self.rpc_urls[0]
        self.config.write_text(json.dumps({
            "nodes": {}, "wallets": {}, "pools": {}, "bindings": {},
            "chain_rpc": {"urls": [endpoint], "operator_provenance": "sha256:" + hashlib.sha256(
                f"tos.prediction.local-observer.v1\\0{endpoint}".encode()).hexdigest()},
            "http": {}, "master_wallet": None, "tick_interval": 40, "log": None,
        }, indent=2))
        self.config.chmod(0o600)

    def relay_quorum_configs(self) -> list[Path]:
        """Write the two additional owner-pinned observer configs for tosctl recovery."""
        paths: list[Path] = []
        for index, endpoint in enumerate(self.rpc_urls[1:], 2):
            path = self.workdir / f"prediction-relay-node-{index}.json"
            path.write_text(json.dumps({
                "nodes": {}, "wallets": {}, "pools": {}, "bindings": {},
                "chain_rpc": {"urls": [endpoint], "operator_provenance": "sha256:" + hashlib.sha256(
                    f"tos.prediction.local-observer.v1\\0{endpoint}".encode()).hexdigest()},
                "http": {}, "master_wallet": None, "tick_interval": 40, "log": None,
            }, indent=2))
            path.chmod(0o600)
            paths.append(path)
        if len(paths) != 2:
            raise RuntimeError("Prediction recovery requires exactly three local observers")
        return paths

    def relay_observer_profile(self, network: dict[str, Any], quorum_configs: list[Path]) -> dict[str, Any]:
        result = json.loads(self.tosctl_call(
            "agent", "account", "prediction-relay-profile",
            "--network-id", str(network["network_id"]), "--global-id", str(network["global_id"]),
            "--zero-state-root-hash", str(network["zero_state_root_hash"]),
            "--zero-state-file-hash", str(network["zero_state_file_hash"]),
            "--workchain-id", str(network["workchain_id"]), "--quorum-config",
            *(str(path) for path in quorum_configs),
        ))
        if (result.get("schema") != "tosctl.prediction-relay-observer-profile.v1"
                or not isinstance(result.get("network_domain_hash"), str)
                or not isinstance(result.get("observer_ids"), list)
                or result.get("quorum_threshold") != 2):
            raise RuntimeError(f"invalid pinned Prediction observer profile: {result}")
        return result

    def tosctl_call(self, *args: str, stdin: bytes | None = None) -> str:
        command = [str(self.tosctl), *args, "-c", str(self.config)]
        completed = subprocess.run(
            command, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self.env, timeout=180, check=False,
        )
        if completed.returncode:
            raise RuntimeError(
                f"tosctl {' '.join(args)} failed ({completed.returncode}):\n"
                f"{completed.stdout.decode()}\n{completed.stderr.decode()}"
            )
        return completed.stdout.decode()

    def tosctl_must_fail(self, *args: str) -> None:
        command = [str(self.tosctl), *args, "-c", str(self.config)]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=self.env, timeout=180, check=False)
        if completed.returncode == 0:
            raise RuntimeError(f"tosctl unexpectedly accepted negative test: {' '.join(args)}")

    def tosctl_kill_at_prediction_checkpoint(self, checkpoint: Path, phase: str,
                                              *args: str) -> dict[str, Any]:
        """Kill the actual tosctl process after its durable checkpoint write.

        The command itself opts into a short, bounded checkpoint pause.  This
        avoids treating an ordinary fast exit as a crash and gives the parent
        a deterministic point at which SIGKILL is delivered.
        """
        if checkpoint.exists():
            raise RuntimeError(f"Prediction crash checkpoint already exists: {checkpoint}")
        command = [str(self.tosctl), *args, "--checkpoint-file", str(checkpoint),
                   "--checkpoint-pause-ms", "30000", "-c", str(self.config)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)

        def checkpoint_written() -> dict[str, Any] | None:
            if checkpoint.exists():
                metadata = checkpoint.stat()
                if not checkpoint.is_file() or checkpoint.is_symlink() or metadata.st_size > 4096:
                    raise RuntimeError("Prediction crash checkpoint is not a bounded regular file")
                if metadata.st_mode & 0o077:
                    raise RuntimeError("Prediction crash checkpoint is not owner-private")
                marker = json.loads(checkpoint.read_text())
                if marker.get("schema") != "tosctl.prediction-recovery-checkpoint.v1" or marker.get("phase") != phase:
                    raise RuntimeError(f"unexpected Prediction crash checkpoint: {marker}")
                return marker
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                raise RuntimeError(
                    f"tosctl exited before {phase} checkpoint ({process.returncode}):\n"
                    f"{stdout.decode()}\n{stderr.decode()}"
                )
            return None

        marker = wait_until(checkpoint_written, f"Prediction {phase} durable checkpoint", 30)
        process.send_signal(signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=30)
        if process.returncode != -signal.SIGKILL:
            raise RuntimeError(
                f"tosctl did not die from SIGKILL at {phase}: {process.returncode}\n"
                f"{stdout.decode()}\n{stderr.decode()}"
            )
        if stdout:
            raise RuntimeError(f"tosctl emitted output after {phase} checkpoint before SIGKILL: {stdout.decode()}")
        return marker

    def json_call(self, *args: str) -> Any:
        return json.loads(self.tosctl_call(*args, "--format", "json"))

    def provision_wallets(self, funded_wallets: tuple[str, ...]) -> None:
        for name in WALLET_NAMES:
            self.tosctl_call("wallet", "create", "-n", name, "-v", "V3R2", "-w", "0")
        listing = self.json_call("wallet", "ls")
        self.addresses = {entry["name"]: entry["address"] for entry in listing if entry["name"] in WALLET_NAMES}
        if set(self.addresses) != set(WALLET_NAMES):
            raise RuntimeError("wallet creation did not return every lifecycle address")
        # The local faucet is deliberately minimal and has no durable
        # multi-send scheduler. Fund only the owner from it, then use normal
        # owner-signed transfers for every other principal.
        request = urllib.request.Request(
            self.control_url + "/transfer",
            data=json.dumps({"address": self.addresses["owner"], "amount": 150}).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=70) as response:
                result = json.loads(response.read().decode())
        except urllib.error.HTTPError as error:
            detail = error.read(4096).decode(errors="replace")
            raise RuntimeError(f"faucet funding owner failed: {detail}") from error
        if "error" in result:
            raise RuntimeError(f"faucet funding owner failed: {result['error']}")
        self.tosctl_call("wallet", "activate", "-n", "owner")
        for name in funded_wallets:
            if name == "owner":
                continue
            self.tosctl_call(
                "wallet", "send", "--from", "owner", "--to", self.addresses[name],
                "--amount-nanotos", str(25 * TOS), "--yes",
            )
            wait_until(
                lambda a=self.addresses[name]: int(rpc(self.rpc_urls[0], "getAddressInformation", address=a)["result"]["balance"]) >= 24 * TOS,
                f"owner funding {name}",
            )
            time.sleep(5)
        for name in funded_wallets:
            if name != "owner":
                self.tosctl_call("wallet", "activate", "-n", name)
        for name in funded_wallets:
            address = self.addresses[name]
            wait_until(
                lambda a=address: rpc(self.rpc_urls[0], "getAddressState", address=a).get("result") == "active",
                f"active wallet {name}",
            )

    def provision_prediction_agent_account(self) -> str:
        """Create the production checked-call source with an owner-pinned authority."""
        journal = self.workdir / "prediction-agent-custody"
        journal.mkdir(mode=0o700)
        journal.chmod(0o700)
        self.tosctl_call(
            "agent", "wallet", "create", "--name", "prediction-solver", "-v", "V5R1", "-w", "0",
            "--max-per-tx", "2", "--daily-limit", "10",
        )
        self.tosctl_call(
            "agent", "wallet", "bind-runtime", "--name", "prediction-solver",
            "--runner-id", "local-prediction-acceptance", "--endpoint", "local://prediction-acceptance",
            "--economic-authority-id", "local-prediction-authority",
            "--economic-authority-public-key", self.agent_authority_public_key,
            "--economic-custody-journal-directory", str(journal),
        )
        deployed = self.json_call(
            "agent", "account", "deploy", "--wallet", "prediction-solver", "--from", "owner",
            "-w", "0", "--amount", "4", "--yes",
        )
        address = canonical_raw_address(str(deployed["address"]))
        wait_until(
            lambda: rpc(self.rpc_urls[0], "getAddressState", address=address).get("result") == "active",
            "active Prediction Agent Account",
        )
        view = self.json_call("agent", "account", "show", "--address", address)
        code_hash = view.get("code_hash")
        if isinstance(code_hash, str) and len(code_hash) == 64 and all(item in "0123456789abcdef" for item in code_hash):
            code_hash = "tvm-cell-sha256:" + code_hash
        if not isinstance(code_hash, str) or not code_hash.startswith("tvm-cell-sha256:"):
            raise RuntimeError(f"Prediction Agent Account code hash is not canonical: {view}")
        self.agent_account_address, self.agent_account_code_hash = address, code_hash
        return address

    def prediction_custody_authorization(self, *, market: str, market_id: str,
                                         market_config_hash: str, market_code_hash: str,
                                         amount: int, body_hash: str, valid_until: int) -> dict[str, Any]:
        """Build the exact V1 PCEA preimage specified by the shared protocol."""
        if self.agent_account_address is None or self.agent_account_code_hash is None:
            raise RuntimeError("Prediction Agent Account has not been provisioned")
        master = rpc(self.rpc_urls[0], "getMasterchainInfo")["result"]
        initial = master["init"]
        network = {
            "network_id": "tos:local-three-node", "global_id": 3,
            "zero_state_root_hash": self._rpc_hash_to_digest(initial["root_hash"]),
            "zero_state_file_hash": self._rpc_hash_to_digest(initial["file_hash"]), "workchain_id": 0,
        }
        market_raw = canonical_raw_address(market)
        action_id = self._sha256_digest("prediction-agent-match-action")
        authorization: dict[str, Any] = {
            "schema_version": 1, "profile": "tos.prediction.checked-call.v1",
            "authority_id": "local-prediction-authority", "owner_id": "local-owner",
            "agent_id": "local-prediction-solver", "source_account": self.agent_account_address,
            "network_domain": network, "action_kind": "prediction.match.submit",
            "effect_kind": "prediction.match.submit", "stable_action_id": action_id,
            "exact_request_digest": self._sha256_digest("prediction-agent-match-request"),
            "writer_generation": 1, "writer_fence_digest": self._sha256_digest("prediction-agent-match-fence"),
            "policy_revision": 1, "mandate_digest": self._sha256_digest("prediction-agent-match-mandate"),
            "approval_digest_or_zero": "sha256:" + "0" * 64,
            "market_id": market_id, "market_address": market_raw, "destination": market_raw,
            "market_config_hash": market_config_hash, "market_code_hash": market_code_hash,
            "amount_nanotos": amount, "body_hash": body_hash, "expires_at_unix": valid_until,
            "source_agent_account_code_hash": self.agent_account_code_hash,
            "public_key": "", "proof": "",
        }
        output = bytearray(b"TOS-PCEA\0")
        output.extend(struct.pack(">H", authorization["schema_version"]))
        for field in ("profile", "authority_id", "owner_id", "agent_id", "source_account", "source_agent_account_code_hash"):
            output.extend(self._lp32(authorization[field]))
        output.extend(self._lp32(network["network_id"]))
        output.extend(struct.pack(">i", network["global_id"]))
        output.extend(self._lp32(network["zero_state_root_hash"]))
        output.extend(self._lp32(network["zero_state_file_hash"]))
        output.extend(struct.pack(">i", network["workchain_id"]))
        for field in ("action_kind", "effect_kind", "stable_action_id", "exact_request_digest"):
            output.extend(self._lp32(authorization[field]))
        output.extend(struct.pack(">Q", authorization["writer_generation"]))
        output.extend(self._lp32(authorization["writer_fence_digest"]))
        output.extend(struct.pack(">Q", authorization["policy_revision"]))
        for field in ("mandate_digest", "approval_digest_or_zero", "market_id", "market_address", "market_config_hash", "market_code_hash"):
            output.extend(self._lp32(authorization[field]))
        output.extend(struct.pack(">Q", amount))
        output.extend(self._lp32(body_hash))
        output.extend(struct.pack(">Q", valid_until))
        authorization["public_key"] = "ed25519:" + self.agent_authority_public_key
        authorization["proof"] = "ed25519:" + self.sign_ed25519_digest(hashlib.sha256(output).digest())
        return authorization

    def write_definition(self) -> dict[str, Any]:
        now = int(time.time())
        value = {
            # localnet-jsonrpc fixes its development network domain to 3.
            # Keep this explicit: tosctl must reject a StateInit for any other
            # global ID before it can be signed or broadcast.
            "global_id": 3, "workchain_id": 0, "deployment_salt": "31" * 32,
            "rules_hash": "32" * 32, "metadata_hash": "33" * 32,
            "reserve_recipient": self.addresses["reserve"],
            # The protocol minima are deliberately short only in this local
            # harness. Leave enough real time for three independent nodes to
            # converge on deploy/register/split before the normal report
            # window, and preserve a positive post-schedule claim window.
            "trade_close": now + 180, "resolve_not_before": now + 240,
            "oracle_vote_deadline": now + 600, "challenge_period": 60,
            "appeal_review_delay": 60, "appeal_period": 120, "claim_deadline": now + 840,
            "lot_value": TOS, "min_price_tick": 100, "min_fill_lots": 1,
            "max_order_lots": 10, "max_locked_collateral": 10 * TOS,
            "max_account_free_balance": 10 * TOS, "max_total_free_balance": 20 * TOS,
            "max_total_liability": 50 * TOS, "max_participants": 8,
            "max_orders_per_participant": 16, "max_live_order_records": 32,
            "participant_entry_fee": 1_000_000, "account_cleanup_bounty": 1_000_000,
            "order_entry_fee": 1_000_000, "order_cleanup_bounty": 1_000_000,
            "operating_reserve_floor": 100_000_000, "terminal_tombstone_reserve": 10_000_000,
            "challenge_bond": 10_000_000, "challenge_processing_fee": 1_000_000,
            "normal_oracle_policy": {
                "threshold": 2,
                "reporters": [self.addresses["normal_one"], self.addresses["normal_two"]],
            },
            "appellate_oracle_policy": {
                "threshold": 2,
                "reporters": [self.addresses["appeal_one"], self.addresses["appeal_two"]],
            },
        }
        self.definition.write_text(json.dumps(value, indent=2))
        self.definition.chmod(0o600)
        return value

    def broadcast_file(self, path: Path) -> None:
        raw = path.read_bytes()
        self.tosctl_call(
            "wallet", "broadcast-prepared", "--message-boc-stdin", "--yes",
            "--acknowledge-unpinned-manual-broadcast", stdin=base64.b64encode(raw),
        )

    def wallet_seqno(self, name: str) -> int:
        for entry in self.json_call("wallet", "ls"):
            if entry["name"] == name and entry.get("seqno") is not None:
                return int(entry["seqno"])
        raise RuntimeError(f"active wallet {name} has no observable seqno")

    def prepare_and_send(self, sender: str, operation: dict[str, Any], amount: int, sequence: int) -> Path:
        op_path = self.workdir / f"operation-{sequence}.json"
        boc_path = self.workdir / f"message-{sequence}.boc"
        op_path.write_text(json.dumps(operation))
        op_path.chmod(0o600)
        try:
            self.tosctl_call(
                "agent", "prediction", "prepare", "--definition", str(self.definition),
                "--operation", str(op_path), "--from", sender,
                "--amount-nanotos", str(amount), "--output-boc", str(boc_path),
            )
        except RuntimeError as error:
            raise RuntimeError(
                f"prepare PredictionMarket operation {sequence} input={json.dumps(operation, sort_keys=True)}\n{error}"
            ) from error
        prior_seqno = self.wallet_seqno(sender)
        self.broadcast_file(boc_path)
        wait_until(
            lambda: self.wallet_seqno(sender) > prior_seqno,
            f"source wallet {sender} seqno advancement for operation {sequence}",
        )
        return boc_path

    def prepare_and_send_agent(self, operation: dict[str, Any], amount: int, sequence: int,
                               market_state: dict[str, Any], crash_recovery: bool = False,
                               defer_broadcast: bool = False) -> Path | tuple[Path, dict[str, Any], Path]:
        """Use tosctl's real custody journal to prepare one checked-call V2 BOC."""
        if self.agent_account_address is None:
            raise RuntimeError("Prediction Agent Account is unavailable")
        operation_path = self.workdir / f"agent-operation-{sequence}.json"
        body_path = self.workdir / f"agent-operation-{sequence}.boc"
        authorization_path = self.workdir / f"agent-authorization-{sequence}.json"
        boc_path = self.workdir / f"agent-message-{sequence}.boc"
        operation_path.write_text(json.dumps(operation))
        operation_path.chmod(0o600)
        self.tosctl_call(
            "agent", "prediction", "build-operation", "--definition", str(self.definition),
            "--operation", str(operation_path), "--output-boc", str(body_path),
        )
        artifact = json.loads(self.tosctl_call(
            "agent", "prediction", "build-operation", "--definition", str(self.definition),
            "--operation", str(operation_path),
        ))
        body_hash = artifact.get("body_hash")
        if not isinstance(body_hash, str) or not body_hash.startswith("tvm-cell-sha256:"):
            raise RuntimeError(f"Prediction operation artifact has no canonical body hash: {artifact}")
        valid_until = int(time.time()) + 300
        authorization = self.prediction_custody_authorization(
            market=str(market_state["address"]), market_id=str(market_state["market_id"]),
            market_config_hash=str(market_state["market_config_hash"]), market_code_hash=str(market_state["code_hash"]),
            amount=amount, body_hash=body_hash, valid_until=valid_until,
        )
        authorization_path.write_text(json.dumps(authorization))
        authorization_path.chmod(0o600)
        rejected_path = self.workdir / f"agent-rejected-message-{sequence}.boc"
        rejected = dict(authorization)
        # This red test is deliberately performed through the production
        # parser and custody journal. A proof that differs by one nibble must
        # not reserve a controller sequence or leave an executable BOC.
        rejected["proof"] = rejected["proof"][:-1] + ("0" if rejected["proof"][-1] != "0" else "1")
        rejected_authorization_path = self.workdir / f"agent-rejected-authorization-{sequence}.json"
        rejected_authorization_path.write_text(json.dumps(rejected))
        rejected_authorization_path.chmod(0o600)
        self.tosctl_must_fail(
            "agent", "prediction", "prepare-agent", "--definition", str(self.definition),
            "--operation", str(operation_path), "--wallet", "prediction-solver",
            "--amount-nanotos", str(amount), "--fee-reserve-nanotos", str(100_000_000),
            "--valid-until", str(valid_until), "--authorization-file", str(rejected_authorization_path),
            "--output-boc", str(rejected_path), "--yes",
        )
        if rejected_path.exists():
            raise RuntimeError("rejected Prediction custody authorization wrote an executable BOC")
        prepare_args = (
            "agent", "prediction", "prepare-agent", "--definition", str(self.definition),
            "--operation", str(operation_path), "--wallet", "prediction-solver",
            "--amount-nanotos", str(amount), "--fee-reserve-nanotos", str(100_000_000),
            "--valid-until", str(valid_until), "--authorization-file", str(authorization_path),
            "--output-boc", str(boc_path), "--yes",
        )
        signed_marker: dict[str, Any] | None = None
        if crash_recovery:
            checkpoint = self.workdir / f"prediction-signed-{sequence}.checkpoint.json"
            signed_marker = self.tosctl_kill_at_prediction_checkpoint(checkpoint, "signed", *prepare_args)
            if boc_path.exists():
                raise RuntimeError("killed signed preparer wrote an executable BOC output file")
        prepared = json.loads(self.tosctl_call(*prepare_args))
        if crash_recovery and (
                signed_marker is None
                or signed_marker.get("stable_action_id") != prepared["stable_action_id"]
                or signed_marker.get("evidence_digest") != prepared["exact_signed_boc_digest"]):
            raise RuntimeError(f"signed crash checkpoint does not bind the recovered BOC: {signed_marker}")
        # The first process has now exited with the signed BOC only in the
        # durable custody journal and the owner-private output file. A fresh
        # process must resume that exact record rather than sign a new
        # controller sequence or reconstruct the payload.
        retry_path = self.workdir / f"agent-retry-message-{sequence}.boc"
        retried = json.loads(self.tosctl_call(
            *prepare_args[:-3], "--output-boc", str(retry_path), "--yes",
        ))
        if boc_path.read_bytes() != retry_path.read_bytes():
            raise RuntimeError("Prediction custody retry rebuilt a different signed BOC")
        for field in ("stable_action_id", "submitted_external_message_hash",
                      "pre_broadcast_source_cursor", "pre_broadcast_masterchain_checkpoint"):
            if prepared.get(field) != retried.get(field):
                raise RuntimeError(f"Prediction custody retry changed durable {field}")
        if (prepared.get("schema") != "tosctl.prediction-agent-effect-prepared.v1"
                or not isinstance(prepared.get("submitted_external_message_hash"), str)
                or not prepared["submitted_external_message_hash"].startswith("tvm-cell-sha256:")
                or prepared.get("journal_state") != "broadcasting" or prepared.get("broadcast") is not False):
            raise RuntimeError(f"prepared Prediction effect omitted exact external cell hash: {prepared}")
        if defer_broadcast:
            # A caller may deliberately change only the destination's chain
            # state before broadcasting this already durable BOC. It must not
            # reconstruct the operation or create a second custody action.
            return boc_path, prepared, body_path
        self.broadcast_agent_effect(prepared, body_path, sequence, crash_recovery)
        return boc_path

    def broadcast_agent_effect(self, prepared: dict[str, Any], body_path: Path, sequence: int,
                               crash_recovery: bool = False) -> None:
        """Submit one previously durable Agent effect, then prove its relay outcome."""
        if self.agent_account_address is None:
            raise RuntimeError("Prediction Agent Account is unavailable")
        before = self.json_call("agent", "account", "show", "--address", self.agent_account_address)
        prior_seqno = int(before["seqno"])
        if crash_recovery:
            checkpoint = self.workdir / f"prediction-broadcast-{sequence}.checkpoint.json"
            marker = self.tosctl_kill_at_prediction_checkpoint(
                checkpoint, "broadcasting", "agent", "account", "economic-effect-broadcast",
                "--wallet", "prediction-solver", "--stable-action-id", prepared["stable_action_id"], "--yes",
            )
            if (marker.get("stable_action_id") != prepared["stable_action_id"]
                    or marker.get("evidence_digest") != prepared["exact_signed_boc_digest"]):
                raise RuntimeError(f"broadcast crash checkpoint does not bind the prepared BOC: {marker}")
            after_kill = self.json_call("agent", "account", "show", "--address", self.agent_account_address)
            if int(after_kill["seqno"]) != prior_seqno:
                raise RuntimeError("killed pre-submission broadcaster advanced Agent Account seqno")
        broadcast = json.loads(self.tosctl_call(
            "agent", "account", "economic-effect-broadcast", "--wallet", "prediction-solver",
            "--stable-action-id", prepared["stable_action_id"], "--yes",
        ))
        if (broadcast.get("schema") != "tosctl.agent-account.economic-effect-broadcast.v1"
                or broadcast.get("stable_action_id") != prepared["stable_action_id"]
                or broadcast.get("state") != "broadcasting"):
            raise RuntimeError(f"Prediction custody broadcaster did not submit the prepared action: {broadcast}")
        wait_until(
            lambda: int(self.json_call("agent", "account", "show", "--address", self.agent_account_address)["seqno"]) > prior_seqno,
            f"Prediction Agent Account seqno advancement for operation {sequence}",
        )
        if crash_recovery:
            self.run_openfox_destination_crash_gate(prepared, body_path)
            return
        self.resolve_agent_prediction_relay(prepared, body_path, crash_recovery)

    def run_openfox_destination_crash_gate(self, prepared: dict[str, Any], body_path: Path) -> None:
        """Run OpenFox's actual three-node destination-process-death release gate."""
        if self.openfox_root is None:
            raise RuntimeError("agent-crash-recovery requires --openfox-root for the OpenFox destination gate")
        quorum_configs = self.relay_quorum_configs()
        observer = self.relay_observer_profile(prepared["network_domain"], quorum_configs)
        profile = {
            "network_domain_hash": observer["network_domain_hash"],
            "source_agent_account": prepared["source"],
            "source_agent_account_code_hash": prepared["source_agent_account_code_hash"],
            "market_address": prepared["destination"], "market_id": prepared["market_id"],
            "market_code_hash": prepared["market_code_hash"], "market_config_hash": prepared["market_config_hash"],
            "observer_ids": observer["observer_ids"], "quorum_threshold": observer["quorum_threshold"],
            "maximum_outstanding": 8, "maximum_signed_boc_bytes": 64 << 10,
            "minimum_no_bounce_masterchain_blocks": 8,
        }
        trusted_dir = Path(tempfile.mkdtemp(prefix=".tos-prediction-relay-crash-", dir="/home/tomi"))
        trusted_dir.chmod(0o700)
        try:
            trusted_tosctl = trusted_dir / "tosctl"
            shutil.copyfile(self.tosctl, trusted_tosctl)
            subprocess.run(["strip", "--strip-unneeded", str(trusted_tosctl)], check=True, timeout=60)
            trusted_tosctl.chmod(0o700)
            input_path = self.workdir / "openfox-prediction-relay-crash-input.json"
            input_path.write_text(json.dumps({
                "profile": profile, "prepared": prepared, "network": prepared["network_domain"],
                "body_boc_path": str(body_path), "tosctl": str(trusted_tosctl),
                "primary_config": str(self.config), "quorum_configs": [str(path) for path in quorum_configs],
                "vault_url": self.vault_url,
            }))
            input_path.chmod(0o600)
            env = dict(self.env)
            env.update({
                "GOWORK": "off", "OPENFOX_PREDICTION_RELAY_CRASH_THREE_NODE_E2E": "1",
                "OPENFOX_PREDICTION_RELAY_CRASH_THREE_NODE_INPUT": str(input_path),
            })
            completed = subprocess.run(
                ["go", "test", "./pkg/earning", "-run",
                 "TestPredictionRelayDestinationThreeNodeProcessDeathReleaseGate", "-count=1", "-v"],
                cwd=self.openfox_root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=300, check=False,
            )
            if completed.returncode:
                raise RuntimeError(f"OpenFox three-node destination crash gate failed:\n{completed.stdout.decode()}")
        finally:
            shutil.rmtree(trusted_dir, ignore_errors=False)

    def resolve_agent_prediction_relay(self, prepared: dict[str, Any], body_path: Path,
                                       crash_recovery: bool = False) -> None:
        """Prove one exact V2 source and destination path through tosctl's durable resolver."""
        required = ("stable_action_id", "source", "source_agent_account_code_hash", "destination",
                    "market_id", "market_code_hash", "market_config_hash", "amount_nanotos", "body_hash",
                    "network_domain", "submitted_external_message_hash", "pre_broadcast_source_cursor",
                    "pre_broadcast_masterchain_checkpoint")
        if any(name not in prepared for name in required):
            raise RuntimeError(f"prepared Prediction effect lacks recovery input: {prepared}")
        quorum_configs = self.relay_quorum_configs()
        observer = self.relay_observer_profile(prepared["network_domain"], quorum_configs)
        profile = {
            "network_domain_hash": observer["network_domain_hash"], "source_agent_account": prepared["source"],
            "source_agent_account_code_hash": prepared["source_agent_account_code_hash"],
            "market_address": prepared["destination"], "market_id": prepared["market_id"],
            "market_code_hash": prepared["market_code_hash"], "market_config_hash": prepared["market_config_hash"],
            "observer_ids": observer["observer_ids"], "quorum_threshold": observer["quorum_threshold"],
            "maximum_outstanding": 8, "maximum_signed_boc_bytes": 64 << 10,
            "minimum_no_bounce_masterchain_blocks": 8,
        }
        source_request = {
            "schema": "tosctl.prediction-relay-source-request.v1", "action_id": prepared["stable_action_id"],
            "profile": profile, "submitted_external_message_hash": prepared["submitted_external_message_hash"],
            "pre_broadcast_source_cursor": prepared["pre_broadcast_source_cursor"],
            "pre_broadcast_masterchain_checkpoint": prepared["pre_broadcast_masterchain_checkpoint"],
        }
        source_path = self.workdir / "prediction-relay-source-request.json"
        source_path.write_text(json.dumps(source_request))
        source_path.chmod(0o600)
        source_args = (
            "agent", "account", "prediction-relay-source-resolve", "--wallet", "prediction-solver",
            "--stable-action-id", prepared["stable_action_id"], "--relay-request", str(source_path),
            "--max-transactions", "1000", "--quorum-config", *(str(path) for path in quorum_configs),
        )
        if crash_recovery:
            checkpoint = self.workdir / "prediction-source-finalized.checkpoint.json"
            marker = self.tosctl_kill_at_prediction_checkpoint(checkpoint, "source_finalized", *source_args)
            if marker.get("stable_action_id") != prepared["stable_action_id"]:
                raise RuntimeError(f"source crash checkpoint binds another action: {marker}")
        source = json.loads(self.tosctl_call(
            *source_args,
        ))
        if source.get("schema") != "tosctl.prediction-relay-source-evidence.v1" or source.get("state") != "source_finalized":
            raise RuntimeError(f"Prediction source resolver did not prove the checked call: {source}")
        evidence = source.get("source_evidence")
        if not isinstance(evidence, dict) or len(evidence.get("outbound_messages", [])) != 1:
            raise RuntimeError(f"Prediction source resolver did not bind one exact outbound: {source}")
        actual = evidence["outbound_messages"][0]
        source_masterchain = evidence.get("block", {}).get("masterchain_sequence_number")
        if not isinstance(source_masterchain, int) or source_masterchain <= 0:
            raise RuntimeError(f"Prediction source evidence omitted a finalized masterchain anchor: {source}")
        # The source transaction only creates the internal message.  Wait for
        # all local observers to advance beyond that finalized source block
        # before asking the destination resolver to search the destination
        # shard; otherwise a correct resolver would have to report an honest
        # temporary absence as an ambiguous terminal outcome.
        wait_until(
            lambda: min(int(rpc(url, "getMasterchainInfo")["result"]["last"]["seqno"])
                        for url in self.rpc_urls) >= source_masterchain + 2,
            "Prediction destination delivery after source finality",
        )
        opcode = 0x504D0009  # PredictionMarketV1 match_pair, frozen in the contract wrapper.
        predicate = "TOS-PREDICTION-CALL-SUCCESS\0{}\0{}\0{}\0{}\0{}\0{}\0{}".format(
            prepared["action_kind"], prepared["stable_action_id"], prepared["destination"],
            prepared["amount_nanotos"], prepared["body_hash"], 3, opcode)
        expected = {
            "action_kind": prepared["action_kind"], "stable_action_id": prepared["stable_action_id"],
            "target_address": prepared["destination"], "value_nanotos": prepared["amount_nanotos"],
            "body_boc_base64": base64.b64encode(body_path.read_bytes()).decode(), "body_hash": prepared["body_hash"],
            "state_init_boc_base64": "", "state_init_hash": "", "bounce": True, "extra_flags": 3,
            "opcode": opcode, "success_predicate_digest": "sha256:" + hashlib.sha256(predicate.encode()).hexdigest(),
        }
        destination_request = {
            "schema": "tosctl.prediction-relay-destination-request.v1", "action_id": prepared["stable_action_id"],
            "profile": profile, "expected": expected,
            "pre_broadcast_source_cursor": prepared["pre_broadcast_source_cursor"],
            "pre_broadcast_masterchain_checkpoint": prepared["pre_broadcast_masterchain_checkpoint"],
            "source_evidence": evidence, "actual_outbound": actual,
        }
        destination_path = self.workdir / "prediction-relay-destination-request.json"
        destination_path.write_text(json.dumps(destination_request))
        destination_path.chmod(0o600)
        destination = json.loads(self.tosctl_call(
            "agent", "account", "prediction-relay-destination-resolve", "--wallet", "prediction-solver",
            "--stable-action-id", prepared["stable_action_id"], "--relay-request", str(destination_path),
            "--max-masterchain-blocks", "1000", "--max-transactions", "1000", "--quorum-config",
            *(str(path) for path in quorum_configs),
        ))
        if (destination.get("schema") != "tosctl.prediction-relay-destination-evidence.v1"
                or destination.get("state") != "destination_committed"):
            raise RuntimeError(f"Prediction destination resolver did not prove market execution: {destination}")

    def export_match_evidence(self, external_boc: Path, operation: dict[str, Any], scan_start: int) -> None:
        """Export bounded public inputs for the OpenFox live acceptance gate."""
        if self.evidence_dir is None:
            return
        self.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.evidence_dir.chmod(0o700)
        body_path = self.evidence_dir / "match-body.boc"
        operation_path = self.workdir / "match-operation.json"
        operation_path.write_text(json.dumps(operation))
        operation_path.chmod(0o600)
        self.tosctl_call("agent", "prediction", "build-operation", "--definition", str(self.definition),
                         "--operation", str(operation_path), "--output-boc", str(body_path))
        for source, name in ((self.definition, "market.json"), (external_boc, "match-external.boc")):
            destination = self.evidence_dir / name
            shutil.copyfile(source, destination)
            destination.chmod(0o600)
        for index, endpoint in enumerate(self.rpc_urls, 1):
            path = self.evidence_dir / f"node-{index}.json"
            path.write_text(json.dumps({"nodes": {}, "wallets": {}, "pools": {}, "bindings": {},
                                        "chain_rpc": {"urls": [endpoint + "/"]}, "http": {},
                                        "master_wallet": None, "tick_interval": 40, "log": None}, indent=2))
            path.chmod(0o600)
        manifest = {"schema": "tos.prediction-match-evidence.v1", "source_address": self.match_source_address or canonical_raw_address(self.addresses["owner"]),
                    "scan_start_masterchain_seqno": scan_start}
        (self.evidence_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
        (self.evidence_dir / "manifest.json").chmod(0o600)

    def run_openfox_accepted_wager_gate(self) -> None:
        if self.openfox_root is None or self.evidence_dir is None:
            return
        report_dir = self.workdir / "openfox-evidence"
        report_dir.mkdir(mode=0o700)
        trusted_dir = Path(tempfile.mkdtemp(prefix=".tos-prediction-gate-", dir="/home/tomi"))
        trusted_dir.chmod(0o700)
        trusted_tosctl = trusted_dir / "tosctl"
        shutil.copyfile(self.tosctl, trusted_tosctl)
        subprocess.run(["strip", "--strip-unneeded", str(trusted_tosctl)], check=True, timeout=60)
        trusted_tosctl.chmod(0o700)
        info = rpc(self.rpc_urls[0], "getMasterchainInfo")["result"]
        initial = info["init"]
        env = dict(os.environ)
        env.update({
            "GOWORK": "off", "OPENFOX_PREDICTION_ACCEPTED_WAGER_CONTRACT_THREE_NODE_E2E": "1",
            "OPENFOX_PREDICTION_TOSCTL": str(trusted_tosctl),
            "OPENFOX_PREDICTION_MARKET_DEFINITION": str(self.evidence_dir / "market.json"),
            "OPENFOX_PREDICTION_MATCH_EXTERNAL_BOC": str(self.evidence_dir / "match-external.boc"),
            "OPENFOX_PREDICTION_MATCH_BODY_BOC": str(self.evidence_dir / "match-body.boc"),
            "OPENFOX_PREDICTION_MATCH_SOURCE_ADDRESS": self.match_source_address or canonical_raw_address(self.addresses["owner"]),
            "OPENFOX_PREDICTION_MATCH_SCAN_START_MC_SEQNO": str(json.loads((self.evidence_dir / "manifest.json").read_text())["scan_start_masterchain_seqno"]),
            "OPENFOX_PREDICTION_TOSCTL_CONFIG_1": str(self.evidence_dir / "node-1.json"),
            "OPENFOX_PREDICTION_TOSCTL_CONFIG_2": str(self.evidence_dir / "node-2.json"),
            "OPENFOX_PREDICTION_TOSCTL_CONFIG_3": str(self.evidence_dir / "node-3.json"),
            "OPENFOX_PREDICTION_NETWORK_ID": "tos:local-three-node", "OPENFOX_PREDICTION_GLOBAL_ID": "3",
            "OPENFOX_PREDICTION_WORKCHAIN_ID": "0", "OPENFOX_PREDICTION_ZERO_STATE_ROOT_HASH": initial["root_hash"],
            "OPENFOX_PREDICTION_ZERO_STATE_FILE_HASH": initial["file_hash"],
            "OPENFOX_PREDICTION_EVIDENCE_DIRECTORY": str(report_dir),
        })
        if self.match_source_code_hash is not None:
            env["OPENFOX_PREDICTION_SUBMISSION_PROFILE"] = "agent-account-checked-call-v2"
            env["OPENFOX_PREDICTION_SOURCE_AGENT_CODE_HASH"] = self.match_source_code_hash
        try:
            completed = subprocess.run(["go", "test", "./pkg/earning", "-run",
                                       "TestPredictionAcceptedWagerAndFutureRevealThreeNodeContractGate", "-count=1", "-v"],
                                      cwd=self.openfox_root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      timeout=300, check=False)
            if completed.returncode:
                raise RuntimeError(f"OpenFox accepted-wager gate failed:\n{completed.stdout.decode()}")
            exported = self.evidence_dir / "openfox-reports"
            exported.mkdir(mode=0o700, exist_ok=True)
            if not exported.is_dir() or exported.is_symlink():
                raise RuntimeError("OpenFox report export root is not a directory")
            exported.chmod(0o700)
            for prefix in ("accepted-wager-", "future-block-lock-", "future-block-reveal-"):
                reports = sorted(report_dir.glob(prefix + "*.json"))
                if len(reports) != 1 or reports[0].stat().st_size <= 0 or reports[0].stat().st_size > 2 << 20:
                    raise RuntimeError(f"OpenFox did not produce one bounded {prefix} report")
                destination = exported / reports[0].name
                shutil.copyfile(reports[0], destination)
                destination.chmod(0o600)
        finally:
            shutil.rmtree(trusted_dir, ignore_errors=False)

    def signed_order(self, order: dict[str, Any], label: str, seed: bytes) -> str:
        """Build and verify one canonical signed order using an ephemeral key."""
        order_path = self.workdir / f"order-{label}.json"
        unsigned_path = self.workdir / f"order-{label}-unsigned.boc"
        signed_path = self.workdir / f"order-{label}-signed.boc"
        order_path.write_text(json.dumps(order))
        order_path.chmod(0o600)
        artifact = json.loads(self.tosctl_call(
            "agent", "prediction", "build-order", "--definition", str(self.definition),
            "--order", str(order_path), "--output-boc", str(unsigned_path),
        ))
        digest = artifact["digest"].removeprefix("tvm-cell-sha256:")
        if len(digest) != 64:
            raise RuntimeError(f"canonical order digest has invalid shape for {label}")
        # Node's RFC 8032 implementation accepts a raw 32-byte seed when it
        # is wrapped in the standard PKCS#8 Ed25519 prefix. The seed stays in
        # this owner-private process environment only; tosctl independently
        # verifies the resulting signature before writing the signed BOC.
        signer = (
            "const c=require('crypto');"
            "const seed=Buffer.from(process.env.PREDICTION_TEST_SEED,'hex');"
            "const msg=Buffer.from(process.env.PREDICTION_TEST_DIGEST,'hex');"
            "const key=c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});"
            "const pub=c.createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32);"
            "process.stdout.write(JSON.stringify({public_key:pub.toString('hex'),signature:c.sign(null,msg,key).toString('hex')}));"
        )
        signer_env = dict(self.env)
        signer_env.update({"PREDICTION_TEST_SEED": seed.hex(), "PREDICTION_TEST_DIGEST": digest})
        completed = subprocess.run(
            ["node", "-e", signer], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=signer_env, check=False, timeout=30,
        )
        if completed.returncode:
            raise RuntimeError(f"ephemeral Ed25519 signer failed for {label}: {completed.stderr.decode()}")
        signature = json.loads(completed.stdout)
        self.tosctl_call(
            "agent", "prediction", "build-order", "--definition", str(self.definition),
            "--order", str(order_path), "--public-key", signature["public_key"],
            "--signature", signature["signature"], "--output-boc", str(signed_path),
        )
        return base64.b64encode(signed_path.read_bytes()).decode()

    def ed25519_public_key(self, seed: bytes) -> str:
        script = (
            "const c=require('crypto');const s=Buffer.from(process.env.PREDICTION_TEST_SEED,'hex');"
            "const k=c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),s]),format:'der',type:'pkcs8'});"
            "process.stdout.write(c.createPublicKey(k).export({format:'der',type:'spki'}).subarray(-32).toString('hex'));"
        )
        env = dict(self.env)
        env["PREDICTION_TEST_SEED"] = seed.hex()
        return subprocess.check_output(["node", "-e", script], env=env, timeout=30).decode()

    def sign_ed25519_digest(self, digest: bytes) -> str:
        if len(digest) != 32:
            raise RuntimeError("Prediction authority digest must be 32 bytes")
        script = (
            "const c=require('crypto');const s=Buffer.from(process.env.PREDICTION_TEST_SEED,'hex');"
            "const d=Buffer.from(process.env.PREDICTION_TEST_DIGEST,'hex');"
            "const k=c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),s]),format:'der',type:'pkcs8'});"
            "process.stdout.write(c.sign(null,d,k).toString('hex'));"
        )
        env = dict(self.env)
        env["PREDICTION_TEST_SEED"] = self.agent_authority_seed.hex()
        env["PREDICTION_TEST_DIGEST"] = digest.hex()
        result = subprocess.check_output(["node", "-e", script], env=env, timeout=30).decode()
        if len(result) != 128:
            raise RuntimeError("Prediction authority signature is not canonical Ed25519")
        return result

    @staticmethod
    def _lp32(value: str) -> bytes:
        encoded = value.encode()
        return struct.pack(">I", len(encoded)) + encoded

    @staticmethod
    def _sha256_digest(label: str) -> str:
        return "sha256:" + hashlib.sha256(label.encode()).hexdigest()

    @staticmethod
    def _rpc_hash_to_digest(value: str) -> str:
        if value.startswith("sha256:"):
            encoded = value.removeprefix("sha256:")
            if len(encoded) == 64 and all(item in "0123456789abcdef" for item in encoded):
                return value
            raise RuntimeError("RPC zero-state digest is not canonical lowercase SHA-256")
        encoded = value.replace("-", "+").replace("_", "/")
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
        if len(raw) != 32:
            raise RuntimeError("RPC zero-state hash is not 32 bytes")
        return "sha256:" + raw.hex()

    def show_quorum(self) -> dict[str, Any]:
        original = self.config.read_text()
        def semantic_view(value: dict[str, Any]) -> dict[str, Any]:
            # A node's latest masterchain checkpoint is observer-local progress,
            # not market state. All contract-derived fields must still match.
            normalized = dict(value)
            normalized.pop("checkpoint", None)
            return normalized

        def converged() -> dict[str, Any] | None:
            values = []
            try:
                for endpoint in self.rpc_urls:
                    config = json.loads(original)
                    config["chain_rpc"]["urls"] = [endpoint + "/"]
                    self.config.write_text(json.dumps(config))
                    values.append(json.loads(self.tosctl_call(
                        "agent", "prediction", "show", "--definition", str(self.definition)
                    )))
            finally:
                self.config.write_text(original)
            canonical = json.dumps(semantic_view(values[0]), sort_keys=True)
            if all(json.dumps(semantic_view(value), sort_keys=True) == canonical for value in values[1:]):
                return values[0]
            return None

        return wait_until(converged, "three-node PredictionMarket state convergence", 90)

    def wait_status(self, status: str) -> dict[str, Any]:
        return wait_until(lambda: (view := self.show_quorum()).get("status") == status and view,
                          f"market status {status}")

    def run_normal_lifecycle(self, outcome: int) -> None:
        outcome_names = {0: "yes", 1: "no", 2: "invalid"}
        outcome_name = outcome_names[outcome]
        definition = self.write_definition()
        deploy = self.workdir / "deploy.boc"
        self.tosctl_call(
            "agent", "prediction", "prepare-deploy", "--definition", str(self.definition),
            "--from", "owner", "--amount-nanotos", str(2 * TOS), "--output-boc", str(deploy),
        )
        prior_seqno = self.wallet_seqno("owner")
        self.broadcast_file(deploy)
        wait_until(lambda: self.wallet_seqno("owner") > prior_seqno, "deploy source wallet seqno advancement")
        self.wait_status("trading")

        register_amount = 2 * TOS + definition["participant_entry_fee"] + definition["account_cleanup_bounty"] + OPERATION_BUDGET
        self.prepare_and_send("owner", {
            "operation": "register_and_deposit", "query_id": 1,
            "credited_amount": 2 * TOS, "trading_pubkey": TRADING_PUBLIC_KEY,
        }, register_amount, 1)
        self.prepare_and_send("owner", {"operation": "split", "query_id": 2, "quantity_lots": 1}, OPERATION_BUDGET, 2)
        view = self.show_quorum()
        if view["complete_sets"] != 1 or view["locked"] != TOS or view["total_free"] != TOS:
            raise RuntimeError(f"split did not create one fully collateralized set: {view}")

        wait_until(lambda: int(time.time()) >= definition["resolve_not_before"], "resolve_not_before", 320)
        self.prepare_and_send("owner", {"operation": "advance_phase", "query_id": 3}, OPERATION_BUDGET, 3)
        self.wait_status("reporting")
        # advance_phase intentionally performs at most one stored transition.
        # The first call closes trading; this second call opens the normal
        # round and makes its nonce-bound context observable.
        self.prepare_and_send("owner", {"operation": "advance_phase", "query_id": 4}, OPERATION_BUDGET, 4)
        reporting = self.wait_status("reporting")
        context = reporting["current_context_hash"]
        created_at = int(time.time())
        if (
            not isinstance(context, str)
            or len(context) != 64
            or context == "00" * 32
            or created_at >= definition["oracle_vote_deadline"]
        ):
            raise RuntimeError(
                "normal report inputs are invalid before signing: "
                f"context={context} created_at={created_at} "
                f"expiry={definition['oracle_vote_deadline']}"
            )
        for sequence, reporter in ((5, "normal_one"), (6, "normal_two")):
            self.prepare_and_send(reporter, {
                "operation": "report_result", "query_id": sequence, "round": 0,
                "expected_round_context_hash": context, "outcome": outcome,
                "evidence_root": f"{0x44 + outcome:02x}" * 32, "statement_created_at": created_at,
                "statement_expiry": definition["oracle_vote_deadline"],
            }, OPERATION_BUDGET, sequence)
        proposed = self.wait_status("proposed")
        if proposed["proposed_statement_hash"] == "00" * 32:
            raise RuntimeError("normal quorum did not persist a proposal")

        wait_until(
            lambda: int(time.time()) >= definition["oracle_vote_deadline"] + definition["challenge_period"],
            "normal finalization deadline", 500,
        )
        self.prepare_and_send("owner", {"operation": "finalize_uncontested", "query_id": 7}, OPERATION_BUDGET, 7)
        finalized = self.wait_status("finalized")
        if finalized["final_outcome"] != outcome_name or finalized["remaining_payout"] != TOS:
            raise RuntimeError(f"normal finalization accounting is invalid: {finalized}")

        self.prepare_and_send("owner", {
            "operation": "claim", "query_id": 8, "owner": self.addresses["owner"],
        }, OPERATION_BUDGET, 8)
        claimed = self.show_quorum()
        if claimed["remaining_payout"] != 0 or claimed["claimed"] != TOS:
            raise RuntimeError(f"claim did not exhaust the payout liability: {claimed}")
        self.prepare_and_send("owner", {"operation": "withdraw", "query_id": 9, "amount": 2 * TOS}, OPERATION_BUDGET, 9)
        withdrawn = self.show_quorum()
        if withdrawn["total_free"] != 0:
            raise RuntimeError(f"withdraw did not exhaust the owner's free collateral: {withdrawn}")

    def run_signed_match_lifecycle(self, agent_source: bool = False, crash_recovery: bool = False) -> None:
        """Prove a two-owner complementary BUY match from exact signed BOCs."""
        definition = self.write_definition()
        state = json.loads(self.tosctl_call(
            "agent", "prediction", "build-state", "--definition", str(self.definition),
        ))
        market = state["address"]
        config_hash = state["market_config_hash"].removeprefix("tvm-cell-sha256:")
        deploy = self.workdir / "deploy.boc"
        self.tosctl_call("agent", "prediction", "prepare-deploy", "--definition", str(self.definition),
                         "--from", "owner", "--amount-nanotos", str(2 * TOS), "--output-boc", str(deploy))
        prior = self.wallet_seqno("owner")
        self.broadcast_file(deploy)
        wait_until(lambda: self.wallet_seqno("owner") > prior, "match deploy seqno advancement")
        self.wait_status("trading")
        if agent_source:
            self.provision_prediction_agent_account()
        credited = TOS
        contribution = definition["participant_entry_fee"] + definition["account_cleanup_bounty"]
        seeds = {"normal_one": bytes([1]) * 32, "normal_two": bytes([2]) * 32}
        for sequence, wallet in ((1, "normal_one"), (2, "normal_two")):
            key = self.ed25519_public_key(seeds[wallet])
            self.prepare_and_send(wallet, {
                "operation": "register_and_deposit", "query_id": sequence,
                "credited_amount": credited, "trading_pubkey": key,
            }, credited + contribution + OPERATION_BUDGET, sequence)
        valid_after = int(time.time())
        common = {
            "global_id": 3, "workchain_id": 0, "market_address": market,
            "market_config_hash": config_hash, "key_epoch": 0, "nonce": 1,
            "quantity_lots": 1, "min_fill_lots": 1, "allow_partial": False,
            "valid_after": valid_after, "valid_until": definition["trade_close"],
            "optional_counterparty": None,
        }
        yes = self.signed_order({**common, "owner_address": self.addresses["normal_one"],
                                 "salt": "71" * 32, "action": "buy", "outcome": "yes",
                                 "liquidity_role": "maker", "limit_price_tick": 6_000}, "yes", seeds["normal_one"])
        no = self.signed_order({**common, "owner_address": self.addresses["normal_two"],
                                "salt": "72" * 32, "action": "buy", "outcome": "no",
                                "liquidity_role": "taker", "limit_price_tick": 4_000}, "no", seeds["normal_two"])
        order_contribution = 2 * (definition["order_entry_fee"] + definition["order_cleanup_bounty"])
        match_operation = {"operation": "match_pair", "query_id": 3, "quantity_lots": 1,
                           "left_signed_order_boc": yes, "right_signed_order_boc": no}
        scan_start = int(rpc(self.rpc_urls[0], "getMasterchainInfo")["result"]["last"]["seqno"])
        amount = order_contribution + OPERATION_BUDGET
        if agent_source:
            external_boc = self.prepare_and_send_agent(
                match_operation, amount, 3, state, crash_recovery,
            )
            self.match_source_address = self.agent_account_address
            self.match_source_code_hash = self.agent_account_code_hash
        else:
            external_boc = self.prepare_and_send("owner", match_operation, amount, 3)
            self.match_source_address = canonical_raw_address(self.addresses["owner"])
            self.match_source_code_hash = None
        matched = self.show_quorum()
        if matched["complete_sets"] != 1 or matched["locked"] != TOS or matched["fill_count"] != 1:
            raise RuntimeError(f"signed match did not create one conserved complete set: {matched}")
        self.export_match_evidence(external_boc, match_operation, scan_start)
        self.run_openfox_accepted_wager_gate()

    def run_challenged_lifecycle(self, appellate_outcome: int | None) -> None:
        """Exercise appellate uphold, overturn, or timeout after a hash-bound challenge."""
        definition = self.write_definition()
        deploy = self.workdir / "deploy.boc"
        self.tosctl_call(
            "agent", "prediction", "prepare-deploy", "--definition", str(self.definition),
            "--from", "owner", "--amount-nanotos", str(2 * TOS), "--output-boc", str(deploy),
        )
        prior_seqno = self.wallet_seqno("owner")
        self.broadcast_file(deploy)
        wait_until(lambda: self.wallet_seqno("owner") > prior_seqno, "deploy source wallet seqno advancement")
        self.wait_status("trading")

        register_amount = 2 * TOS + definition["participant_entry_fee"] + definition["account_cleanup_bounty"] + OPERATION_BUDGET
        self.prepare_and_send("owner", {
            "operation": "register_and_deposit", "query_id": 1,
            "credited_amount": 2 * TOS, "trading_pubkey": TRADING_PUBLIC_KEY,
        }, register_amount, 1)
        self.prepare_and_send("owner", {"operation": "split", "query_id": 2, "quantity_lots": 1}, OPERATION_BUDGET, 2)
        split = self.show_quorum()
        if split["complete_sets"] != 1 or split["locked"] != TOS:
            raise RuntimeError(f"challenged scenario split accounting is invalid: {split}")

        wait_until(lambda: int(time.time()) >= definition["resolve_not_before"], "resolve_not_before", 320)
        self.prepare_and_send("owner", {"operation": "advance_phase", "query_id": 3}, OPERATION_BUDGET, 3)
        self.wait_status("reporting")
        self.prepare_and_send("owner", {"operation": "advance_phase", "query_id": 4}, OPERATION_BUDGET, 4)
        reporting = self.wait_status("reporting")
        normal_context = reporting["current_context_hash"]
        normal_created_at = int(time.time())
        if not isinstance(normal_context, str) or len(normal_context) != 64 or normal_context == "00" * 32:
            raise RuntimeError(f"normal context was not opened for challenged scenario: {reporting}")
        for sequence, reporter in ((5, "normal_one"), (6, "normal_two")):
            self.prepare_and_send(reporter, {
                "operation": "report_result", "query_id": sequence, "round": 0,
                "expected_round_context_hash": normal_context, "outcome": 0,
                "evidence_root": "44" * 32, "statement_created_at": normal_created_at,
                "statement_expiry": definition["oracle_vote_deadline"],
            }, OPERATION_BUDGET, sequence)
        proposed = self.wait_status("proposed")
        proposal_hash = proposed["proposed_statement_hash"]
        if not isinstance(proposal_hash, str) or proposal_hash == "00" * 32:
            raise RuntimeError(f"normal proposal is not bound before challenge: {proposed}")

        challenge_amount = (
            OPERATION_BUDGET + definition["challenge_bond"] + definition["challenge_processing_fee"]
        )
        self.prepare_and_send("owner", {
            "operation": "challenge_result", "query_id": 7,
            "expected_proposed_statement_hash": proposal_hash, "counter_outcome": 1,
            "counter_evidence_root": "55" * 32,
        }, challenge_amount, 7)
        reviewing = self.wait_status("reviewing")
        review_base = reviewing["review_base_context_hash"]
        appeal_deadline = reviewing["next_deadline"]
        if not isinstance(review_base, str) or review_base == "00" * 32:
            raise RuntimeError(f"challenge did not freeze review provenance: {reviewing}")
        if not isinstance(appeal_deadline, int) or appeal_deadline <= int(time.time()):
            raise RuntimeError(f"challenge did not expose a future appeal deadline: {reviewing}")

        if appellate_outcome is None:
            # A challenged valid normal proposal is still authoritative if
            # the appellate set is unavailable. Do not open a review round:
            # the stable base context alone authorizes the timeout finalizer.
            wait_until(
                lambda: int(time.time()) >= appeal_deadline,
                "appellate Oracle deadline", definition["appeal_period"] + 90,
            )
            self.prepare_and_send("owner", {
                "operation": "finalize_review_timeout", "query_id": 8,
                "expected_review_base_context_hash": review_base,
            }, OPERATION_BUDGET, 8)
            finalized = self.wait_status("finalized")
            if finalized["final_outcome"] != "yes" or finalized["remaining_payout"] != TOS:
                raise RuntimeError(f"appellate timeout did not preserve normal proposal: {finalized}")
            claim_query, bond_query, withdraw_query = 9, 10, 11
        else:
            # The phase getter exposes the terminal appeal deadline, not the
            # earlier review-vote opening time. The challenge is already
            # observed in all three nodes; wait beyond the frozen delay before
            # the separate opening transaction.
            review_entered_at = int(time.time())
            wait_until(
                lambda: int(time.time()) >= review_entered_at + definition["appeal_review_delay"] + 2,
                "appeal review vote opening time", definition["appeal_review_delay"] + 90,
            )
            self.prepare_and_send("owner", {"operation": "advance_phase", "query_id": 8}, OPERATION_BUDGET, 8)
            review_round = self.wait_status("reviewing")
            appeal_context = review_round["current_context_hash"]
            appeal_created_at = int(time.time())
            if not isinstance(appeal_context, str) or appeal_context == "00" * 32:
                raise RuntimeError(f"appellate round was not opened after delay: {review_round}")
            for sequence, reporter in ((9, "appeal_one"), (10, "appeal_two")):
                self.prepare_and_send(reporter, {
                    "operation": "report_result", "query_id": sequence, "round": 1,
                    "expected_round_context_hash": appeal_context, "outcome": appellate_outcome,
                    "evidence_root": "66" * 32, "statement_created_at": appeal_created_at,
                    "statement_expiry": appeal_deadline,
                }, OPERATION_BUDGET, sequence)
            finalized = self.wait_status("finalized")
            expected_outcome = ("yes", "no", "invalid")[appellate_outcome]
            if (finalized["final_outcome"] != expected_outcome
                    or finalized["remaining_payout"] != TOS):
                raise RuntimeError(f"appellate quorum did not select its reported outcome: {finalized}")
            claim_query, bond_query, withdraw_query = 11, 12, 13

        self.prepare_and_send("owner", {
            "operation": "claim", "query_id": claim_query, "owner": self.addresses["owner"],
        }, OPERATION_BUDGET, claim_query)
        claimed = self.show_quorum()
        if claimed["remaining_payout"] != 0 or claimed["claimed"] != TOS:
            raise RuntimeError(f"challenged claim did not exhaust payout liability: {claimed}")
        self.prepare_and_send("owner", {
            "operation": "withdraw_challenge_bond", "query_id": bond_query,
        }, OPERATION_BUDGET, bond_query)
        refunded = self.show_quorum()
        if refunded["challenge_bond"] != 0:
            raise RuntimeError(f"challenge bond was not refunded under fixed timeout rules: {refunded}")
        self.prepare_and_send("owner", {
            "operation": "withdraw", "query_id": withdraw_query, "amount": 2 * TOS,
        }, OPERATION_BUDGET, withdraw_query)
        withdrawn = self.show_quorum()
        if withdrawn["total_free"] != 0:
            raise RuntimeError(f"challenged withdrawal did not exhaust free collateral: {withdrawn}")

    def run_double_timeout_lifecycle(self) -> None:
        """Prove that only two frozen Oracle timeouts yield terminal INVALID."""
        definition = self.write_definition()
        deploy = self.workdir / "deploy.boc"
        self.tosctl_call(
            "agent", "prediction", "prepare-deploy", "--definition", str(self.definition),
            "--from", "owner", "--amount-nanotos", str(2 * TOS), "--output-boc", str(deploy),
        )
        prior_seqno = self.wallet_seqno("owner")
        self.broadcast_file(deploy)
        wait_until(lambda: self.wallet_seqno("owner") > prior_seqno, "deploy source wallet seqno advancement")
        self.wait_status("trading")

        register_amount = 2 * TOS + definition["participant_entry_fee"] + definition["account_cleanup_bounty"] + OPERATION_BUDGET
        self.prepare_and_send("owner", {
            "operation": "register_and_deposit", "query_id": 1,
            "credited_amount": 2 * TOS, "trading_pubkey": TRADING_PUBLIC_KEY,
        }, register_amount, 1)
        self.prepare_and_send("owner", {"operation": "split", "query_id": 2, "quantity_lots": 1}, OPERATION_BUDGET, 2)
        split = self.show_quorum()
        if split["complete_sets"] != 1 or split["locked"] != TOS:
            raise RuntimeError(f"double-timeout split accounting is invalid: {split}")

        # Deliberately do not open or report a normal round. A late keeper
        # first records TRADING -> REPORTING, then the next independent call
        # must enter REVIEWING(NORMAL_TIMEOUT) without manufacturing a stale
        # normal vote context.
        wait_until(
            lambda: int(time.time()) >= definition["oracle_vote_deadline"],
            "normal Oracle deadline", 700,
        )
        self.prepare_and_send("owner", {"operation": "advance_phase", "query_id": 3}, OPERATION_BUDGET, 3)
        reporting = self.wait_status("reporting")
        if reporting["current_context_hash"] != "00" * 32:
            raise RuntimeError(f"late normal transition opened a stale round: {reporting}")
        self.prepare_and_send("owner", {"operation": "advance_phase", "query_id": 4}, OPERATION_BUDGET, 4)
        reviewing = self.wait_status("reviewing")
        review_base = reviewing["review_base_context_hash"]
        appeal_deadline = reviewing["next_deadline"]
        if not isinstance(review_base, str) or review_base == "00" * 32:
            raise RuntimeError(f"normal timeout did not freeze review base context: {reviewing}")
        if reviewing["current_context_hash"] != "00" * 32:
            raise RuntimeError(f"normal timeout unexpectedly opened appellate round: {reviewing}")
        if not isinstance(appeal_deadline, int) or appeal_deadline <= int(time.time()):
            raise RuntimeError(f"normal timeout did not expose future appeal deadline: {reviewing}")

        # Do not open the appellate round and do not report. The base context
        # remains the sole authorization input for the timeout finalizer.
        wait_until(
            lambda: int(time.time()) >= appeal_deadline,
            "appellate Oracle deadline", definition["appeal_period"] + 90,
        )
        self.prepare_and_send("owner", {
            "operation": "finalize_review_timeout", "query_id": 5,
            "expected_review_base_context_hash": review_base,
        }, OPERATION_BUDGET, 5)
        finalized = self.wait_status("finalized")
        if finalized["final_outcome"] != "invalid" or finalized["remaining_payout"] != TOS:
            raise RuntimeError(f"double timeout did not produce INVALID accounting: {finalized}")

        self.prepare_and_send("owner", {
            "operation": "claim", "query_id": 6, "owner": self.addresses["owner"],
        }, OPERATION_BUDGET, 6)
        claimed = self.show_quorum()
        if claimed["remaining_payout"] != 0 or claimed["claimed"] != TOS:
            raise RuntimeError(f"double-timeout claim did not exhaust payout liability: {claimed}")
        self.prepare_and_send("owner", {"operation": "withdraw", "query_id": 7, "amount": 2 * TOS}, OPERATION_BUDGET, 7)
        withdrawn = self.show_quorum()
        if withdrawn["total_free"] != 0:
            raise RuntimeError(f"double-timeout withdrawal did not exhaust free collateral: {withdrawn}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, help="optional private parent for temporary state")
    parser.add_argument("--tosctl", type=Path, default=REPO / "tosctl/src/target/debug/tosctl")
    parser.add_argument("--base-port", type=int, default=21600)
    parser.add_argument("--evidence-dir", type=Path, help="owner-private export for OpenFox match acceptance")
    parser.add_argument("--openfox-root", type=Path, help="run OpenFox accepted-wager gate before localnet teardown")
    parser.add_argument(
        "--normal-outcome", choices=("yes", "no", "invalid"), default="yes",
        help="controlled normal-oracle outcome to exercise (not an external-fact assertion)",
    )
    parser.add_argument(
        "--scenario", choices=("normal", "signed-match", "agent-signed-match", "agent-crash-recovery", "challenged-appellate", "challenged-uphold", "challenged-timeout", "double-timeout"), default="normal",
        help="lifecycle branch to exercise",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.openfox_root and not args.evidence_dir and args.scenario != "agent-crash-recovery":
        raise RuntimeError("--openfox-root requires --evidence-dir for exact match inputs")
    if args.scenario == "agent-crash-recovery" and not args.openfox_root:
        raise RuntimeError("agent-crash-recovery requires --openfox-root")
    if not args.tosctl.is_file() or not os.access(args.tosctl, os.X_OK):
        raise RuntimeError(f"tosctl binary is not executable: {args.tosctl}")
    parent = args.workdir.resolve() if args.workdir else Path(tempfile.gettempdir())
    parent.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="tos-prediction-lifecycle-", dir=parent))
    workdir.chmod(0o700)
    rpc_port = args.base_port + 545
    control_port = args.base_port + 745
    rpc_urls = [f"http://127.0.0.1:{rpc_port + index}" for index in range(3)]
    command = [
        sys.executable, str(REPO / "scripts/localnet-jsonrpc.py"), "--validators", "3",
        "--rpc", f"127.0.0.1:{rpc_port}", "--control", f"127.0.0.1:{control_port}",
        "--base-port", str(args.base_port), "--workdir", str(workdir / "network"),
        "--boot-timeout", "180",
    ]
    localnet = subprocess.Popen(command, cwd=REPO, env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        def three_nodes_ready() -> bool:
            if localnet.poll() is not None:
                output = localnet.stdout.read().decode(errors="replace") if localnet.stdout else ""
                raise LocalnetFailed(f"localnet exited before readiness:\n{output}")
            return all(rpc(url, "getMasterchainInfo").get("result") for url in rpc_urls)

        wait_until(three_nodes_ready, "three-node RPC readiness", 210)
        control_url = f"http://127.0.0.1:{control_port}"
        wait_until(
            lambda: json.loads(urllib.request.urlopen(control_url + "/readyz", timeout=5).read())["ok"],
            "localnet faucet readiness",
            60,
        )
        lifecycle = Lifecycle(workdir, args.tosctl.resolve(), rpc_urls, control_url,
                              args.evidence_dir.resolve() if args.evidence_dir else None,
                              args.openfox_root.resolve() if args.openfox_root else None)
        lifecycle.write_config()
        if args.scenario == "normal":
            lifecycle.provision_wallets(NORMAL_SCENARIO_FUNDED_WALLETS)
            outcome = {"yes": 0, "no": 1, "invalid": 2}[args.normal_outcome]
            lifecycle.run_normal_lifecycle(outcome)
            print(
                "PredictionMarket normal "
                f"{args.normal_outcome.upper()} direct-wallet three-node lifecycle: PASS"
            )
        elif args.scenario == "signed-match":
            lifecycle.provision_wallets(MATCH_SCENARIO_FUNDED_WALLETS)
            lifecycle.run_signed_match_lifecycle()
            print("PredictionMarket two-party signed-order match three-node lifecycle: PASS")
        elif args.scenario == "agent-signed-match":
            lifecycle.provision_wallets(MATCH_SCENARIO_FUNDED_WALLETS)
            lifecycle.run_signed_match_lifecycle(agent_source=True)
            print("PredictionMarket Agent Account signed-order match three-node lifecycle: PASS")
        elif args.scenario == "agent-crash-recovery":
            lifecycle.provision_wallets(MATCH_SCENARIO_FUNDED_WALLETS)
            lifecycle.run_signed_match_lifecycle(agent_source=True, crash_recovery=True)
            print("PredictionMarket Agent Account crash-recovery three-node lifecycle: PASS")
        elif args.scenario == "challenged-appellate":
            lifecycle.provision_wallets(CHALLENGED_SCENARIO_FUNDED_WALLETS)
            lifecycle.run_challenged_lifecycle(1)
            print("PredictionMarket challenged appellate direct-wallet three-node lifecycle: PASS")
        elif args.scenario == "challenged-uphold":
            lifecycle.provision_wallets(CHALLENGED_SCENARIO_FUNDED_WALLETS)
            lifecycle.run_challenged_lifecycle(0)
            print("PredictionMarket challenged appellate-uphold direct-wallet three-node lifecycle: PASS")
        elif args.scenario == "challenged-timeout":
            lifecycle.provision_wallets(NORMAL_SCENARIO_FUNDED_WALLETS)
            lifecycle.run_challenged_lifecycle(None)
            print("PredictionMarket challenged appellate-timeout direct-wallet three-node lifecycle: PASS")
        else:
            lifecycle.provision_wallets(NORMAL_SCENARIO_FUNDED_WALLETS)
            lifecycle.run_double_timeout_lifecycle()
            print("PredictionMarket double-timeout direct-wallet three-node lifecycle: PASS")
        return 0
    finally:
        if localnet.poll() is None:
            localnet.terminate()
            try:
                localnet.wait(timeout=30)
            except subprocess.TimeoutExpired:
                localnet.kill()
                localnet.wait()
        shutil.rmtree(workdir, ignore_errors=False)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"PredictionMarket lifecycle: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
