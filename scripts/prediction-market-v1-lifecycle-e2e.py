#!/usr/bin/env python3
"""Run the direct-wallet PredictionMarket V1 lifecycle on three local nodes.

This is an opt-in acceptance harness.  It owns a fresh local validator network,
an owner-private temporary file Vault, and every wallet used by the run.  It
does not claim to exercise the Agent Account relay; that boundary is covered by
the OpenFox checked-call V2 acceptance gate.

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
import json
import os
import secrets
import shutil
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


class Lifecycle:
    def __init__(self, workdir: Path, tosctl: Path, rpc_urls: list[str], control_url: str):
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

    def write_config(self, rpc_url: str | None = None) -> None:
        self.config.write_text(json.dumps({
            "nodes": {}, "wallets": {}, "pools": {}, "bindings": {},
            "chain_rpc": {"urls": [rpc_url or self.rpc_urls[0] + "/"]},
            "http": {}, "master_wallet": None, "tick_interval": 40, "log": None,
        }, indent=2))
        self.config.chmod(0o600)

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

    def prepare_and_send(self, sender: str, operation: dict[str, Any], amount: int, sequence: int) -> None:
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

    def run_challenged_lifecycle(self, appellate_outcome: int | None) -> None:
        """Exercise appellate quorum or timeout after a hash-bound challenge."""
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
            if finalized["final_outcome"] != "no" or finalized["remaining_payout"] != TOS:
                raise RuntimeError(f"appellate quorum did not overturn normal proposal: {finalized}")
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
    parser.add_argument(
        "--normal-outcome", choices=("yes", "no", "invalid"), default="yes",
        help="controlled normal-oracle outcome to exercise (not an external-fact assertion)",
    )
    parser.add_argument(
        "--scenario", choices=("normal", "challenged-appellate", "challenged-timeout", "double-timeout"), default="normal",
        help="lifecycle branch to exercise",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
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
        lifecycle = Lifecycle(workdir, args.tosctl.resolve(), rpc_urls, control_url)
        lifecycle.write_config()
        if args.scenario == "normal":
            lifecycle.provision_wallets(NORMAL_SCENARIO_FUNDED_WALLETS)
            outcome = {"yes": 0, "no": 1, "invalid": 2}[args.normal_outcome]
            lifecycle.run_normal_lifecycle(outcome)
            print(
                "PredictionMarket normal "
                f"{args.normal_outcome.upper()} direct-wallet three-node lifecycle: PASS"
            )
        elif args.scenario == "challenged-appellate":
            lifecycle.provision_wallets(CHALLENGED_SCENARIO_FUNDED_WALLETS)
            lifecycle.run_challenged_lifecycle(1)
            print("PredictionMarket challenged appellate direct-wallet three-node lifecycle: PASS")
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
