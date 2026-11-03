"""The shielded client's end-to-end gate on an isolated local network.

Sender S and recipient R are two `tosctl shield` instances on two separate
configuration directories and Vaults. F is S's funded public wallet, G is R's,
W is the public recipient of S's withdrawal. O is the relayer operator that
`provision_operator` stood up with an onion endpoint; the only route to O is a
gated SOCKS peer standing in for the Tor client, which admits O's onion name
and nothing else.

The amount vector forces what the gate must see: two 10 TOS deposits, a
relayed 15 TOS send that needs both as inputs, R's 10 TOS withdrawal to a
never-initialised address that bounces and mints a recovery note, a direct
12 TOS send from R that can only be paid with that recovered leaf plus R's
change, S's 1 TOS public withdrawal to W, and a second relayed send whose
submit response is dropped so that recovery from an ambiguous submission is
exercised on the real path.

Every step writes a receipt with secrets redacted; every negative control
writes a receipt that shows the refusal. The run ends with `VERDICT: PASS` or
`VERDICT: FAIL <step>` and an evidence index that names each receipt by hash.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable

import adjudicate as adj
import chain
import operator_journal as op
from connection_trace import adjudicate_connections, parse_connects, strace_argv
from evidence import INDEX_SCHEMA, RETENTION_SCHEMA
from localnet_common import (
    NANOTOS,
    Completed,
    Localnet,
    LocalnetError,
    Receipts,
    get_method,
    run_measured,
    sha256_bytes,
    sha256_file,
    utc_now,
    write_private_json,
)
from socks_peer import GatedSocksPeer, serve

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
JSON = dict[str, Any]

TOS = NANOTOS
DEPOSIT = 10 * TOS
RELAYED_SEND = 15 * TOS
RELAYED_SEND_SECOND = 1 * TOS
BOUNCED_WITHDRAWAL = 10 * TOS
DIRECT_SEND = 12 * TOS
PUBLIC_WITHDRAWAL = 1 * TOS
FUND_F = 40 * TOS
FUND_G = 5 * TOS
FUND_W = 1 * TOS
OUTPUTS_PER_TRANSACT = 3
FEE_SLOT = 2
CONTRACT_SOURCES = ("crypto/smartcont/tos-shielded-pool-v1.fc", "crypto/smartcont/shielded")


class StepFailed(LocalnetError):
    pass


class Participant:
    """One `tosctl` configuration directory with its own file Vault."""

    def __init__(self, run: Run, label: str) -> None:
        self.run = run
        self.label = label
        self.directory = run.private / label
        self.directory.mkdir(mode=0o700)
        self.config = self.directory / "config.json"
        master_key = secrets.token_hex(32)
        run.receipts.add_secret(f"vault-master-key-{label}", master_key)
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.directory),
            "NO_COLOR": "1",
            "VAULT_URL": f"file://{self.directory}/vault.json?master_key={master_key}",
            "TOSCTL_SHIELD_CEREMONY_DIR": str(run.net.ceremony_dir),
            "TOSCTL_SHIELD_PHASE1_DIR": str(run.net.phase1_dir),
        }
        self.run.tosctl_plain(self, "config", "generate", "--output", str(self.config))
        config = json.loads(self.config.read_text())
        config["chain_rpc"] = {"urls": [run.net.rpc_url], "api_key": None}
        config["proof_verifier"] = {
            "executable": str(run.net.proof_verify),
            "anchor_file": str(run.net.anchor_file),
            "liteserver_config": str(run.net.liteserver_config),
            "live_state_file": str(self.directory / "proof-state.json"),
            "live_max_age_seconds": 30,
            "timeout_seconds": 120,
            "min_interval_ms": 0,
        }
        write_private_json(self.config, config)

    def tosctl(self, *args: str, stdin: bytes | None = None, traced: bool = False) -> Completed:
        return self.run.tosctl(self, *args, stdin=stdin, traced=traced)

    def wallet(self, name: str) -> str:
        """Create a V3R2 wallet in this Vault and return its address."""
        self.run.tosctl_plain(
            self, "wallet", "create", "-c", str(self.config), "-n", name, "-v", "V3R2", "-w", "0"
        )
        listed = self.run.tosctl_plain(
            self, "wallet", "ls", "-c", str(self.config), "--format", "json", "--offline"
        )
        for entry in json.loads(listed.stdout):
            if entry["name"] == name:
                return chain.raw_address(str(entry["address"]))
        raise LocalnetError(f"wallet {name} was not listed")


# Every client command runs in its own transient cgroup with this much memory and no
# swap: a client that grows without bound is killed on its own instead of taking the
# host with it, and the receipts carry its peak resident size.
MEMORY_CAP = "32G"


def capped(argv: list[str]) -> list[str]:
    """`argv` under a transient scope that bounds its memory.

    The scope is created through the user manager, which `systemd-run` finds by
    the runtime directory; the command itself runs with the environment it was
    given and nothing more, so the variable is set around `systemd-run` only.
    """
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    systemd_run = shutil.which("systemd-run")
    if systemd_run is None:
        raise RuntimeError("systemd-run is not installed; the memory cap needs it")
    return [
        "/usr/bin/env",
        f"XDG_RUNTIME_DIR={runtime_dir}",
        systemd_run,
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "-p",
        f"MemoryMax={MEMORY_CAP}",
        "-p",
        "MemorySwapMax=0",
        "/usr/bin/env",
        "-u",
        "XDG_RUNTIME_DIR",
        *argv,
    ]


class Run:
    def __init__(self, args: argparse.Namespace) -> None:
        self.net = Localnet.load(args.localnet)
        self.pool_dir: Path = args.pool
        self.operator_dir: Path = args.operator
        self.run_dir: Path = args.run_dir
        self.index_out: Path = args.index_out
        self.base_commit: str = args.base_commit
        if self.run_dir.exists():
            raise SystemExit(f"{self.run_dir} exists; every run gets a new directory")
        self.run_dir.mkdir(parents=True, mode=0o700)
        self.private = self.run_dir / "private"
        self.private.mkdir(mode=0o700)
        self.traces = self.run_dir / "traces"
        self.traces.mkdir(mode=0o700)
        self.receipts = Receipts(self.run_dir / "receipts")
        self.deployed = json.loads((self.pool_dir / "deployed.json").read_text())
        self.pool = str(self.deployed["manifest"]["address"])
        self.pool_profile = self.pool_dir / "generated" / "pool-profile.json"
        self.operator = json.loads((self.operator_dir / "operator.json").read_text())
        self.relayer_profile = self.operator_dir / "relayer-profile.json"
        self.journal_db = self.operator_dir / "journal.db"
        self.leases_db = self.operator_dir / "leases.db"
        self.steps: list[JSON] = []
        self.controls: list[JSON] = []
        self.proving: list[JSON] = []
        self.failed: str | None = None
        self.peer = GatedSocksPeer(
            ("127.0.0.1", self.net.operator_port), self.net.onion, 80, self.net.socks_port
        )
        self.liteserver_ports = frozenset(
            int(server["port"])
            for server in json.loads(self.net.liteserver_config.read_text())["liteservers"]
        )
        self.rpc_port = int(self.net.rpc_url.split(":")[2].split("/")[0])
        self.trace_count = 0
        self.last_trace: Path | None = None
        self.last_command: Completed | None = None

    # ------------------------------------------------------------ commands ---

    def tosctl_plain(self, who: Participant, *args: str) -> Completed:
        completed = run_measured(capped([str(self.net.tosctl), *args]), env=who.env, timeout=600)
        self.last_command = completed
        if not completed.ok():
            raise LocalnetError(
                f"tosctl {args[0]} {args[1] if len(args) > 1 else ''} failed: "
                f"{self.receipts.redact_text(completed.stderr.strip()[-1500:])}"
            )
        return completed

    def tosctl(
        self, who: Participant, *args: str, stdin: bytes | None = None, traced: bool = False
    ) -> Completed:
        argv = [str(self.net.tosctl), *args]
        trace_file: Path | None = None
        if traced:
            self.trace_count += 1
            trace_file = self.traces / f"{self.trace_count:02d}-connect.strace"
            argv = strace_argv(argv, trace_file)
        argv = capped(argv)
        completed = run_measured(argv, env=who.env, stdin=stdin, timeout=3600)
        self.last_command = completed
        if trace_file is not None:
            completed.argv = [*completed.argv[: len(argv) - len(args) - 1], "<tosctl>", *args]
            self.last_trace = trace_file
        return completed

    def shield(
        self, who: Participant, *args: str, stdin: bytes | None = None, traced: bool = False
    ) -> Completed:
        return self.tosctl(
            who, "shield", args[0], "-c", str(who.config), *args[1:], stdin=stdin, traced=traced
        )

    def trace_text(self) -> str:
        if self.last_trace is None:
            raise LocalnetError("no connection trace was taken")
        return self.last_trace.read_text()

    def connection_verdict(self) -> JSON:
        if self.last_trace is None:
            raise LocalnetError("no connection trace was taken")
        connects = parse_connects(self.last_trace.read_text())
        verdict = adjudicate_connections(
            connects,
            socks_port=self.net.socks_port,
            operator_port=self.net.operator_port,
            permitted_ports=self.liteserver_ports | {self.rpc_port},
        )
        return {
            "trace": self.last_trace.name,
            "trace_sha256": sha256_file(self.last_trace),
            "passed": verdict.passed,
            "reason": verdict.reason,
            "tcp_destinations": verdict.tcp_destinations,
        }

    def record_proving(self, name: str, completed: Completed) -> None:
        self.proving.append(
            {
                "command": name,
                "seconds": round(completed.seconds, 1),
                "max_rss_kib": completed.max_rss_kib,
            }
        )

    # ------------------------------------------------------------ receipts ---

    def step(self, name: str, body: Callable[[], JSON]) -> None:
        if self.failed is not None:
            self.steps.append({"name": name, "outcome": "SKIP", "receipt": None, "sha256": None})
            print(f"SKIP {name}", flush=True)
            return
        print(f"STEP {name} ...", flush=True)
        self.last_command = None
        try:
            facts = body()
            receipt = self.receipts.build(name, facts=facts, outcome="PASS")
            outcome = "PASS"
        except Exception as error:  # noqa: BLE001 - every failure is a FAIL receipt, never a crash
            failure: JSON = {
                "error": self.receipts.redact_text(str(error)),
                "traceback": self.receipts.redact_text(traceback.format_exc()),
            }
            if self.last_command is not None:
                # What the client itself said is the first thing a reader of a
                # failed receipt needs, whatever the adjudicator tripped on.
                failure["last_command"] = self.command_facts(self.last_command)
            receipt = self.receipts.build(name, facts=failure, outcome="FAIL")
            outcome = "FAIL"
            self.failed = name
        path = self.receipts.write(receipt)
        self.steps.append(
            {
                "name": name,
                "outcome": outcome,
                "receipt": str(path.relative_to(self.run_dir)),
                "sha256": sha256_file(path),
            }
        )
        print(f"{outcome} {name}", flush=True)

    def control(self, name: str, body: Callable[[], JSON]) -> None:
        """`body` attempts something the system must refuse and returns the
        refusal's facts; a control that is not refused is GREEN, which fails the run."""
        if self.failed is not None:
            self.controls.append({"name": name, "outcome": "SKIP", "receipt": None, "sha256": None})
            return
        print(f"CONTROL {name} ...", flush=True)
        try:
            facts = body()
            outcome = "RED"
        except Exception as error:  # noqa: BLE001 - a control that is not refused is GREEN, never a crash
            facts = {
                "error": self.receipts.redact_text(str(error)),
                "traceback": self.receipts.redact_text(traceback.format_exc()),
            }
            outcome = "GREEN"
            self.failed = name
        receipt = self.receipts.build(name, facts=facts, outcome=outcome)
        path = self.receipts.write(receipt)
        self.controls.append(
            {
                "name": name,
                "outcome": outcome,
                "receipt": str(path.relative_to(self.run_dir)),
                "sha256": sha256_file(path),
            }
        )
        print(f"{outcome} {name}", flush=True)

    def command_facts(self, completed: Completed, **more: Any) -> JSON:
        facts: JSON = {
            "argv": self.receipts.redact(completed.argv),
            "returncode": completed.returncode,
            "seconds": round(completed.seconds, 3),
            "max_rss_kib": completed.max_rss_kib,
            "stdout": self.receipts.redact_text(adj.strip_ansi(completed.stdout)),
            "stderr": self.receipts.redact_text(adj.strip_ansi(completed.stderr)),
        }
        facts.update(more)
        return facts

    # ------------------------------------------------------------- helpers ---

    def pool_leaves(self) -> int:
        return get_method(self.net.rpc_url, self.pool, "commitment_next_index")

    def wait_leaves(self, count: int) -> int:
        return chain.wait_for(
            lambda: self.pool_leaves() >= count and self.pool_leaves(),
            f"the pool reaching {count} leaves",
        )

    def notes(
        self, who: Participant, name: str
    ) -> tuple[Completed, list[adj.Note], tuple[int, int]]:
        completed = self.shield(who, "balance", "-n", name, "--notes")
        if not completed.ok():
            raise LocalnetError(f"balance: {completed.stderr.strip()[-800:]}")
        return completed, adj.parse_notes(completed.stdout), adj.parse_balance(completed.stdout)

    def sync(self, who: Participant, name: str) -> tuple[Completed, JSON]:
        completed = self.shield(who, "sync", "-n", name)
        if not completed.ok():
            raise LocalnetError(f"sync: {completed.stderr.strip()[-800:]}")
        report = adj.parse_sync(completed.stdout)
        if not report["verified"]:
            raise LocalnetError("the sync was not proof-verified")
        return completed, report

    def wait_job_executed(self, message_hash: str) -> JSON:
        def executed() -> JSON | None:
            job = op.job_for_message(self.journal_db, message_hash)
            return job if job is not None and job["state"] == "executed" else None

        return chain.wait_for(
            executed, "the operator finalizing the relayed spend", timeout=600, interval=3
        )

    def dead_address(self) -> str:
        while True:
            candidate = f"0:{secrets.token_hex(32)}"
            if chain.account_state(self.net, candidate) in ("uninitialized", "uninit", "nonexist"):
                return candidate

    def harness_revisions(self) -> JSON:
        files: JSON = {}
        for path in sorted(HERE.glob("*.py")):
            files[str(path.relative_to(ROOT))] = sha256_file(path)
        files["test/bonded-relayer/test_tor_transport.py"] = sha256_file(
            ROOT / "test/bonded-relayer/test_tor_transport.py"
        )
        for source in CONTRACT_SOURCES:
            path = ROOT / source
            if path.is_dir():
                for child in sorted(path.glob("*.fc")):
                    files[str(child.relative_to(ROOT))] = sha256_file(child)
            else:
                files[source] = sha256_file(path)
        br1 = self.net.br1_py
        files[str(br1.relative_to(ROOT)) if br1.is_relative_to(ROOT) else str(br1)] = sha256_file(
            br1
        )
        return files

    def binaries(self) -> JSON:
        wrapper = self.net.tosctl
        wrapped = wrapper.parent / ".tosctl-wrapped"
        version = run_measured(
            [str(wrapper), "--version"], env={"PATH": "/usr/bin:/bin"}, timeout=60
        )
        strace = shutil.which("strace") or "/bin/false"
        # A digest names a build; the configuration says which commit and
        # source path it was built from, so the build can be redone.
        source = self.net.provenance
        return {
            "tosctl": {
                "path": str(wrapper),
                "sha256": sha256_file(wrapper),
                "wrapped_sha256": sha256_file(wrapped) if wrapped.is_file() else None,
                "version": adj.strip_ansi(version.stdout).strip(),
                "source": source["tosctl"],
            },
            "br1-native-provider": {
                "path": str(self.net.provider),
                "sha256": sha256_file(self.net.provider),
                "source": source["br1-native-provider"],
            },
            "tos-proof-verify": {
                "path": str(self.net.proof_verify),
                "sha256": sha256_file(self.net.proof_verify),
                "source": source["tos-proof-verify"],
            },
            "local_ceremony_pool": {
                "path": str(self.net.local_ceremony_pool),
                "sha256": sha256_file(self.net.local_ceremony_pool),
                "source": source["local_ceremony_pool"],
            },
            "strace": {"path": strace, "sha256": sha256_file(Path(strace))},
        }

    # ------------------------------------------------------------ the gate ---

    def execute(self) -> int:
        thread = serve(self.peer)
        try:
            self.run_steps()
        finally:
            self.peer.shutdown()
            thread.join(timeout=5)
        self.write_index()
        if self.failed is None:
            print("VERDICT: PASS", flush=True)
            return 0
        print(f"VERDICT: FAIL {self.failed}", flush=True)
        return 1

    def run_steps(self) -> None:
        net = self.net
        s = Participant(self, "s")
        r = Participant(self, "r")
        w = Participant(self, "w")
        state: JSON = {}

        def setup() -> JSON:
            network = net.network()
            state["f"] = s.wallet("f")
            state["g"] = r.wallet("g")
            state["w"] = w.wallet("w")
            for address, amount in (
                (state["f"], FUND_F),
                (state["g"], FUND_G),
                (state["w"], FUND_W),
            ):
                chain.fund(net, address, amount)
            for who, name in ((s, "f"), (r, "g"), (w, "w")):
                chain.wait_for(
                    lambda a=who, n=name: chain.balance(net, state[n]) > 0, f"funding of {name}"
                )
                self.tosctl_plain(who, "wallet", "activate", "-c", str(who.config), "-n", name)
                chain.wait_active(net, state[name])
            info = chain.account_information(net, self.pool)
            if chain.code_hash_hex(info) != self.deployed["manifest"]["code_hash"]:
                raise LocalnetError("the pool's code is not the generator's")
            return {
                "chain": {
                    "global_id": network["global_id"],
                    "zerostate_root": network["zerostate_root"],
                    "zerostate_file": network["zerostate_file"],
                    "masterchain_seqno": chain.masterchain_seqno(net),
                },
                "pool": {
                    k: self.deployed["manifest"][k]
                    for k in (
                        "address",
                        "code_hash",
                        "initial_data_hash",
                        "pool_config_hash",
                        "profile_hash",
                        "groth16_vk_hash",
                        "development_verifying_key",
                    )
                },
                "pool_leaves": self.pool_leaves(),
                "bond": self.operator["release"],
                "wallets": {"f": state["f"], "g": state["g"], "w": state["w"]},
                "funding_nanotos": {"f": str(FUND_F), "g": str(FUND_G), "w": str(FUND_W)},
            }

        self.step("setup", setup)

        def audit() -> JSON:
            completed = self.shield(s, "audit-ceremony")
            if not completed.ok():
                raise LocalnetError(completed.stderr[-800:])
            self.record_proving("audit-ceremony", completed)
            return self.command_facts(completed)

        self.step("audit-ceremony", audit)

        def init(who: Participant, name: str) -> Callable[[], JSON]:
            def body() -> JSON:
                generated = self.tosctl_plain(
                    who,
                    "wallet",
                    "mnemonic-generate",
                    "-c",
                    str(who.config),
                    "--words",
                    "24",
                    "-v",
                    "V4R2",
                )
                mnemonic = str(json.loads(generated.stdout)["mnemonic"])
                self.receipts.add_secret(f"mnemonic-{name}", mnemonic)
                completed = self.shield(
                    who,
                    "init",
                    "-n",
                    name,
                    "--profile",
                    str(self.pool_profile),
                    "--mnemonic-fd",
                    "0",
                    stdin=(mnemonic + "\n").encode(),
                )
                if not completed.ok():
                    raise LocalnetError(completed.stderr[-800:])
                return self.command_facts(completed, profile_sha256=sha256_file(self.pool_profile))

            return body

        self.step("init-s", init(s, "s"))
        self.step("init-r", init(r, "r"))

        def tampered_profile() -> JSON:
            profile = json.loads(self.pool_profile.read_text())
            genuine = str(profile["pool_code_hash"])
            planted = "00" * 32
            profile["pool_code_hash"] = planted
            tampered = self.private / "tampered-profile.json"
            write_private_json(tampered, profile)
            generated = self.tosctl_plain(
                s, "wallet", "mnemonic-generate", "-c", str(s.config), "--words", "24", "-v", "V4R2"
            )
            mnemonic = str(json.loads(generated.stdout)["mnemonic"])
            self.receipts.add_secret("mnemonic-tampered", mnemonic)
            completed = self.shield(
                s,
                "init",
                "-n",
                "tampered",
                "--profile",
                str(tampered),
                "--mnemonic-fd",
                "0",
                stdin=(mnemonic + "\n").encode(),
            )
            refusal = adj.require_profile_refusal(
                completed.returncode, completed.stderr, planted=planted, genuine=genuine
            )
            if (s.directory / "shield" / "tampered.json").exists():
                raise LocalnetError("a refused init left an instance behind")
            return self.command_facts(completed, **refusal)

        self.control("control-tampered-profile-refused", tampered_profile)

        def deposit(index: int) -> Callable[[], JSON]:
            def body() -> JSON:
                before = self.pool_leaves()
                completed = self.shield(
                    s, "deposit", "-n", "s", "--amount", "10", "--from", "f", "-y"
                )
                if not completed.ok():
                    raise LocalnetError(completed.stderr[-800:])
                message = adj.parse_message_hash(completed.stdout, adj.DEPOSIT_MESSAGE_LINE)
                after = self.wait_leaves(before + 1)
                return self.command_facts(
                    completed,
                    message_hash=message,
                    pool_leaves_before=before,
                    pool_leaves_after=after,
                )

            return body

        self.step("deposit-1", deposit(1))
        self.step("deposit-2", deposit(2))

        def sync_after_deposits() -> JSON:
            completed, report = self.sync(s, "s")
            balance_cmd, notes, (balance, count) = self.notes(s, "s")
            if report["new_notes"] != 2 or report["notes_in_all"] != 2:
                raise LocalnetError(
                    f"sync imported {report['new_notes']} notes, {report['notes_in_all']} in all"
                )
            if balance != 2 * DEPOSIT or count != 2:
                raise LocalnetError(f"balance {balance} in {count} notes")
            leaves = sorted(note.leaf for note in notes if note.leaf is not None)
            if len(leaves) != 2 or any(note.amount != DEPOSIT for note in notes):
                raise LocalnetError("the two deposits are not two 10 TOS notes at two leaves")
            state["s_notes"] = notes
            return self.command_facts(
                completed,
                sync=report,
                balance=self.command_facts(balance_cmd),
                notes=[n.as_json() for n in notes],
                pool_leaves=self.pool_leaves(),
            )

        self.step("sync-s-after-deposits", sync_after_deposits)

        def address(who: Participant, name: str, key: str) -> Callable[[], JSON]:
            def body() -> JSON:
                completed = self.shield(who, "address", "-n", name)
                if not completed.ok():
                    raise LocalnetError(completed.stderr[-800:])
                lines = [
                    line for line in adj.strip_ansi(completed.stdout).splitlines() if line.strip()
                ]
                descriptor = lines[-1].strip()
                if len(descriptor) < 40:
                    raise LocalnetError("no descriptor line")
                state[key] = descriptor
                self.receipts.add_secret(f"descriptor-{key}", descriptor)
                return self.command_facts(
                    completed, descriptor_sha256=sha256_bytes(descriptor.encode())
                )

            return body

        self.step("address-r", address(r, "r", "r_descriptor"))

        def relayed_send(
            key: str, amount: int, drop: bool, descriptor_key: str
        ) -> Callable[[], JSON]:
            def body() -> JSON:
                _, r_before, _ = self.notes(r, "r")
                _, s_before, _ = self.notes(s, "s")
                fee_before = op.fee_notes(self.leases_db)
                jobs_before = op.jobs(self.journal_db)
                receipts_before = len(self.peer.snapshot())
                self.peer.drop_submit = drop
                try:
                    completed = self.shield(
                        s,
                        "send",
                        "-n",
                        "s",
                        "--relayer",
                        str(self.relayer_profile),
                        "--to",
                        state[descriptor_key],
                        "--amount",
                        str(amount // TOS),
                        "--tor-port",
                        str(net.socks_port),
                        "-y",
                        traced=True,
                    )
                finally:
                    self.peer.drop_submit = False
                self.record_proving(f"send --relayer ({key})", completed)
                connections = self.connection_verdict()
                if not connections["passed"]:
                    raise LocalnetError(f"connection evidence: {connections['reason']}")
                if not drop and not completed.ok():
                    raise LocalnetError(completed.stderr[-1200:])
                plan = adj.parse_spend_plan(completed.stdout)
                facts: JSON = self.command_facts(
                    completed, plan=plan.as_json(), connections=connections
                )
                if drop:
                    if completed.ok() or "no acknowledgement" not in completed.stderr:
                        raise LocalnetError("the dropped submission was not reported as unknown")
                    request_id = completed.stderr.split("the submission of request ", 1)[1].split(
                        " ", 1
                    )[0]
                    facts["ambiguous"] = True
                else:
                    request_id, claimed = adj.parse_request(completed.stdout)
                    facts["claimed"] = claimed
                    adj.require_two_real_inputs(plan, amount, int(self.operator["fee"]))
                state[f"{key}_request"] = request_id
                state[f"{key}_plan"] = plan
                state[f"{key}_before"] = (
                    s_before,
                    r_before,
                    fee_before,
                    jobs_before,
                    receipts_before,
                )
                facts["request_id"] = request_id
                return facts

            return body

        self.step("send-relayed", relayed_send("relayed", RELAYED_SEND, False, "r_descriptor"))

        def settle_relayed(key: str, amount: int, expected_groups: int) -> Callable[[], JSON]:
            def body() -> JSON:
                s_before, r_before, fee_before, jobs_before, receipts_before = state[
                    f"{key}_before"
                ]
                plan: adj.SpendPlan = state[f"{key}_plan"]
                request_id = state[f"{key}_request"]
                # The operator's own journal says when the spend is final; the
                # client is then asked once so that its claim is on record.
                known = {j["id"] for j in jobs_before}
                job = chain.wait_for(
                    lambda: next(
                        (
                            j
                            for j in op.jobs(self.journal_db)
                            if j["id"] not in known and j["state"] == "executed"
                        ),
                        None,
                    ),
                    "the operator finalizing the relayed spend",
                    timeout=900,
                    interval=3,
                )
                if len([j for j in op.jobs(self.journal_db) if j["id"] not in known]) != 1:
                    raise LocalnetError("the operator holds more than one new job for one send")
                status = self.shield(
                    s,
                    "status",
                    "-n",
                    "s",
                    "--relayer",
                    str(self.relayer_profile),
                    "--request",
                    request_id,
                    "--tor-port",
                    str(net.socks_port),
                )
                if not status.ok():
                    raise LocalnetError(status.stderr[-800:])
                parsed_status = adj.parse_status(status.stdout)
                if "executed" not in str(parsed_status["relayer"]):
                    raise LocalnetError(
                        f"the relayer does not claim execution: {parsed_status['relayer']}"
                    )
                sync_s, report_s = self.sync(s, "s")
                _, s_after, _ = self.notes(s, "s")
                adj.require_inputs_spent(s_before, s_after, [leaf for _, leaf in plan.inputs])
                adj.require_exactly_one_import(s_before, s_after, plan.change, "ordinary")
                sync_r, report_r = self.sync(r, "r")
                _, r_after, _ = self.notes(r, "r")
                imported = adj.require_exactly_one_import(r_before, r_after, amount, "ordinary")
                transaction = str(job["evidence"]["fee_credit"]["transaction"])
                quoted_index = op.quoted_note_index(self.journal_db, str(job["id"]))
                if quoted_index is None:
                    raise LocalnetError("the operator holds no quote for the job")
                credit = adj.require_exactly_one_fee_credit(
                    fee_before,
                    op.fee_notes(self.leases_db),
                    op.fee_credits(self.journal_db),
                    note_key_index=quoted_index,
                    slot=FEE_SLOT,
                    amount=int(self.operator["fee"]),
                    transaction_hash=transaction,
                )
                socks = adj.require_socks_boundary(
                    self.peer.snapshot(), expected_groups=expected_groups
                )
                return {
                    "status": self.command_facts(status, parsed=parsed_status),
                    "sync_s": self.command_facts(sync_s, parsed=report_s),
                    "sync_r": self.command_facts(sync_r, parsed=report_r),
                    "recipient_note": imported.as_json(),
                    "job": {
                        "id": job["id"],
                        "state": job["state"],
                        "message_hash": job["message_hash"],
                        "request_id_matches_job_id": job["id"] == request_id,
                    },
                    "fee_credit": credit,
                    "socks": socks,
                    "socks_receipts": self.peer.snapshot()[receipts_before:],
                    "pool_leaves": self.pool_leaves(),
                }

            return body

        self.step("settle-relayed", settle_relayed("relayed", RELAYED_SEND, expected_groups=1))

        def bounced_withdrawal() -> JSON:
            dead = self.dead_address()
            state["dead"] = dead
            _, r_before, _ = self.notes(r, "r")
            leaves_before = self.pool_leaves()
            pool_lt = chain.last_lt(net, self.pool)
            completed = self.shield(
                r, "withdraw", "-n", "r", "--amount", "10", "--to", dead, "--from", "g", "-y"
            )
            self.record_proving("withdraw (bounced)", completed)
            if not completed.ok():
                raise LocalnetError(completed.stderr[-1200:])
            plan = adj.parse_spend_plan(completed.stdout)
            adj.require_withdrawal_plan(
                plan, BOUNCED_WITHDRAWAL, int(self.deployed["manifest"]["withdrawal_fee_nanotos"])
            )
            self.wait_leaves(leaves_before + OUTPUTS_PER_TRANSACT)
            bounce = chain.wait_for(
                lambda: chain.find_bounce(net, self.pool, dead, pool_lt),
                "the payout bouncing back to the pool",
                timeout=300,
            )
            charge = get_method(net.rpc_url, self.pool, "recovery_charge")
            self.wait_leaves(leaves_before + OUTPUTS_PER_TRANSACT + 1)
            sync_r, report_r = self.sync(r, "r")
            _, r_after, _ = self.notes(r, "r")
            adj.require_inputs_spent(r_before, r_after, [leaf for _, leaf in plan.inputs])
            recovery = adj.require_recovery(
                bounce=bounce,
                payout_destination=dead,
                payout_value=BOUNCED_WITHDRAWAL,
                recovery_charge=charge,
                before=r_before,
                after=r_after,
                prior_leaf_count=leaves_before + OUTPUTS_PER_TRANSACT,
            )
            if chain.account_state(net, dead) == "active":
                raise LocalnetError("the payout's destination became active")
            state["recovery_leaf"] = recovery.leaf
            return self.command_facts(
                completed,
                plan=plan.as_json(),
                bounce=bounce.__dict__,
                recovery_charge=charge,
                recovery_note=recovery.as_json(),
                sync_r=self.command_facts(sync_r, parsed=report_r),
                payout_destination=dead,
                pool_leaves=self.pool_leaves(),
            )

        self.step("withdraw-r-bounce-and-recovery", bounced_withdrawal)

        self.step("address-s", address(s, "s", "s_descriptor"))

        def direct_send_with_lock_control() -> JSON:
            _, r_before, _ = self.notes(r, "r")
            _, s_before, _ = self.notes(s, "s")
            leaves_before = self.pool_leaves()
            holder: dict[str, Completed] = {}

            def first() -> None:
                holder["first"] = self.shield(
                    r,
                    "send",
                    "-n",
                    "r",
                    "--direct",
                    "--from",
                    "g",
                    "--to",
                    state["s_descriptor"],
                    "--amount",
                    "12",
                    "-y",
                )

            thread = threading.Thread(target=first)
            thread.start()
            time.sleep(8)
            second = self.shield(
                r,
                "send",
                "-n",
                "r",
                "--direct",
                "--from",
                "g",
                "--to",
                state["s_descriptor"],
                "--amount",
                "1",
                "-y",
            )
            thread.join()
            completed = holder["first"]
            self.record_proving("send --direct", completed)
            if not completed.ok():
                raise LocalnetError(completed.stderr[-1200:])
            if second.ok() or "lock" not in second.stderr:
                raise LocalnetError("a second spend during the first was not refused by the lock")
            state["lock_control"] = self.command_facts(second)
            plan = adj.parse_spend_plan(completed.stdout)
            adj.require_spends_leaf(plan, int(state["recovery_leaf"]))
            if len(plan.inputs) != 2:
                raise LocalnetError("the direct send did not need both of R's notes")
            self.wait_leaves(leaves_before + OUTPUTS_PER_TRANSACT)
            sync_r, report_r = self.sync(r, "r")
            _, r_after, _ = self.notes(r, "r")
            adj.require_inputs_spent(r_before, r_after, [leaf for _, leaf in plan.inputs])
            sync_s, report_s = self.sync(s, "s")
            _, s_after, _ = self.notes(s, "s")
            imported = adj.require_exactly_one_import(s_before, s_after, DIRECT_SEND, "ordinary")
            return self.command_facts(
                completed,
                plan=plan.as_json(),
                recovered_leaf=state["recovery_leaf"],
                imported=imported.as_json(),
                sync_r=self.command_facts(sync_r, parsed=report_r),
                sync_s=self.command_facts(sync_s, parsed=report_s),
            )

        self.step("send-direct-r-to-s-spends-recovered-leaf", direct_send_with_lock_control)
        self.control("control-second-spend-refused-by-lock", lambda: dict(state["lock_control"]))

        def public_withdrawal() -> JSON:
            _, s_before, _ = self.notes(s, "s")
            w_before = chain.balance(net, state["w"])
            w_lt = chain.last_lt(net, state["w"])
            leaves_before = self.pool_leaves()
            completed = self.shield(
                s, "withdraw", "-n", "s", "--amount", "1", "--to", state["w"], "--from", "f", "-y"
            )
            self.record_proving("withdraw (public)", completed)
            if not completed.ok():
                raise LocalnetError(completed.stderr[-1200:])
            plan = adj.parse_spend_plan(completed.stdout)
            adj.require_withdrawal_plan(
                plan, PUBLIC_WITHDRAWAL, int(self.deployed["manifest"]["withdrawal_fee_nanotos"])
            )
            self.wait_leaves(leaves_before + OUTPUTS_PER_TRANSACT)
            payout = chain.wait_for(
                lambda: chain.find_payout(net, state["w"], self.pool, w_lt),
                "the payout reaching W",
                timeout=300,
            )
            time.sleep(3)
            w_after = chain.balance(net, state["w"])
            adj.require_public_payout(
                payout=payout,
                pool=self.pool,
                amount=PUBLIC_WITHDRAWAL,
                balance_before=w_before,
                balance_after=w_after,
            )
            sync_s, report_s = self.sync(s, "s")
            _, s_after, _ = self.notes(s, "s")
            adj.require_inputs_spent(s_before, s_after, [leaf for _, leaf in plan.inputs])
            return self.command_facts(
                completed,
                plan=plan.as_json(),
                payout=payout.__dict__,
                w_balance_before=w_before,
                w_balance_after=w_after,
                sync_s=self.command_facts(sync_s, parsed=report_s),
            )

        self.step("withdraw-s-to-w", public_withdrawal)

        # A descriptor is paid once, so the second relayed send needs a fresh one.
        self.step("address-r-again", address(r, "r", "r_descriptor_again"))
        self.step(
            "send-relayed-dropped-submit",
            relayed_send("dropped", RELAYED_SEND_SECOND, True, "r_descriptor_again"),
        )

        def settle_dropped() -> JSON:
            facts = settle_relayed("dropped", RELAYED_SEND_SECOND, expected_groups=2)()
            receipts = self.peer.snapshot()
            groups = sorted(
                {
                    r["isolation_group"]
                    for r in receipts
                    if isinstance(r.get("isolation_group"), int)
                }
            )
            adj.require_single_submission(receipts, groups[-1])
            facts["single_submission_group"] = groups[-1]
            return facts

        self.step("settle-dropped-submit-without-resubmission", settle_dropped)

        # The fail-closed controls must get as far as the connection: a paid
        # descriptor would make the client refuse before it, for another reason.
        self.step("address-r-unpaid", address(r, "r", "r_descriptor_unpaid"))

        def peer_unreachable() -> JSON:
            _, r_before, _ = self.notes(r, "r")
            fee_before = op.fee_notes(self.leases_db)
            closed = net.socks_port + 1
            completed = self.shield(
                s,
                "send",
                "-n",
                "s",
                "--relayer",
                str(self.relayer_profile),
                "--to",
                state["r_descriptor_unpaid"],
                "--amount",
                "1",
                "--tor-port",
                str(closed),
                "-y",
                traced=True,
            )
            if completed.ok():
                raise LocalnetError("a send without a reachable SOCKS peer succeeded")
            connects = parse_connects(self.trace_text())
            if not any(c.port == closed for c in connects):
                raise LocalnetError("the client failed before it tried the SOCKS port")
            if any(c.port == net.operator_port for c in connects):
                raise LocalnetError("the client fell back to a direct connection")
            _, r_after, _ = self.notes(r, "r")
            if adj.new_notes(r_before, r_after) or op.fee_notes(self.leases_db) != fee_before:
                raise LocalnetError("something was relayed without the peer")
            return self.command_facts(completed, connections=self.connection_verdict())

        self.control("control-send-fails-closed-without-socks-peer", peer_unreachable)

        def loopback_endpoint_refused() -> JSON:
            loopback_profile = self.private / "loopback-relayer-profile.json"
            template = json.loads(self.relayer_profile.read_text())
            source = Path(net.root) / "operator-c"
            if not (source / "provider.json").is_file():
                raise LocalnetError("no loopback-endpoint operator to borrow a Bond from")
            borrowed = json.loads((source / "provider.json").read_text())
            template["release"] = borrowed["release"]
            import base64

            template["bond_init_b64"] = base64.b64encode(
                (source / "bond-init.boc").read_bytes()
            ).decode()
            write_private_json(loopback_profile, template)
            receipts_before = len(self.peer.snapshot())
            completed = self.shield(
                s,
                "send",
                "-n",
                "s",
                "--relayer",
                str(loopback_profile),
                "--to",
                state["r_descriptor_unpaid"],
                "--amount",
                "1",
                "--tor-port",
                str(net.socks_port),
                "-y",
                traced=True,
            )
            if completed.ok() or "onion" not in completed.stderr:
                raise LocalnetError(
                    "a Bond with a loopback endpoint was not refused for its endpoint"
                )
            if len(self.peer.snapshot()) != receipts_before:
                raise LocalnetError("the client connected before refusing the endpoint")
            connects = parse_connects(self.trace_text())
            if any(c.port in (net.socks_port, net.operator_port) for c in connects):
                raise LocalnetError("the client opened a relay connection before refusing")
            return self.command_facts(completed)

        self.control(
            "control-loopback-bond-endpoint-refused-before-connecting", loopback_endpoint_refused
        )

        def unexpected_target_refused() -> JSON:
            import socket

            other = "r" + net.onion[1:]
            before = len(self.peer.snapshot())
            with socket.create_connection(("127.0.0.1", net.socks_port), timeout=10) as sock:
                sock.sendall(b"\x05\x01\x02")
                if sock.recv(2) != b"\x05\x02":
                    raise LocalnetError("the peer did not require authentication")
                sock.sendall(b"\x01" + bytes([4]) + b"ctrl" + bytes([4]) + b"ctrl")
                if sock.recv(2) != b"\x01\x00":
                    raise LocalnetError("the peer refused the control's credentials")
                sock.sendall(
                    b"\x05\x01\x00\x03"
                    + bytes([len(other)])
                    + other.encode()
                    + (80).to_bytes(2, "big")
                )
                reply = sock.recv(10)
            if reply[:2] != b"\x05\x02":
                raise LocalnetError(f"the peer did not refuse the other name: {reply!r}")
            receipts = self.peer.snapshot()[before:]
            if len(receipts) != 1 or not receipts[0]["refused_target"] or receipts[0]["forwarded"]:
                raise LocalnetError(f"the refusal was not recorded as such: {receipts}")
            return {"reply": reply.hex(), "receipt": receipts[0]}

        self.control("control-socks-peer-refuses-other-onion-name", unexpected_target_refused)

        def direct_bypass_detected() -> JSON:
            script = (
                "import socket,sys\n"
                f"s=socket.create_connection(('127.0.0.1',{net.operator_port}),timeout=5)\n"
                "s.sendall(b'GET /v1/health HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n')\n"
                "s.recv(64)\n"
            )
            trace_file = self.traces / "bypass-connect.strace"
            completed = run_measured(
                strace_argv([sys.executable, "-c", script], trace_file), timeout=60
            )
            connects = parse_connects(trace_file.read_text())
            verdict = adjudicate_connections(
                connects,
                socks_port=net.socks_port,
                operator_port=net.operator_port,
                permitted_ports=self.liteserver_ports | {self.rpc_port},
            )
            if verdict.passed or "direct" not in verdict.reason:
                raise LocalnetError(f"a direct bypass was not detected: {verdict}")
            return {
                "bypass_returncode": completed.returncode,
                "verdict": verdict.__dict__,
                "trace_sha256": sha256_file(trace_file),
            }

        self.control(
            "control-direct-bypass-is-detected-by-connection-trace", direct_bypass_detected
        )

        def final_state() -> JSON:
            _, s_notes, s_balance = self.notes(s, "s")
            _, r_notes, r_balance = self.notes(r, "r")
            return {
                "s": {
                    "balance": s_balance[0],
                    "spendable": s_balance[1],
                    "notes": [n.as_json() for n in s_notes],
                },
                "r": {
                    "balance": r_balance[0],
                    "spendable": r_balance[1],
                    "notes": [n.as_json() for n in r_notes],
                },
                "pool_leaves": self.pool_leaves(),
                "operator_fee_notes": len(op.fee_notes(self.leases_db)),
                "socks_receipts": self.peer.snapshot(),
            }

        self.step("final-state", final_state)

    # --------------------------------------------------------------- index ---

    def write_index(self) -> None:
        network = self.net.network()
        manifest = self.deployed["manifest"]
        index: JSON = {
            "schema": INDEX_SCHEMA,
            "result": "PASS" if self.failed is None else "FAIL",
            "failed_step": self.failed,
            "checked_utc": utc_now(),
            "base_commit": self.base_commit,
            "client_memory_cap": MEMORY_CAP,
            "revisions": {
                "worktree_head": git_head(),
                "harness_sha256": self.harness_revisions(),
                "pool_deployment": {
                    "generator_sha256": self.deployed["generator"]["sha256"],
                    "state_init_sha256": self.deployed["state_init_sha256"],
                },
                "operator": {
                    "provider_sha256": self.operator["provider_sha256"],
                    "relayer_profile_sha256": self.operator["relayer_profile_sha256"],
                },
            },
            "binaries": self.binaries(),
            "chain": {
                "global_id": network["global_id"],
                "global_version": network.get("global_version"),
                "zerostate_root": network["zerostate_root"],
                "zerostate_file": network["zerostate_file"],
            },
            "pool": {
                k: manifest[k]
                for k in (
                    "address",
                    "code_hash",
                    "initial_data_hash",
                    "pool_config_hash",
                    "profile_hash",
                    "groth16_vk_hash",
                    "development_verifying_key",
                    "ceremony_transcript",
                )
            },
            "bond": self.operator["release"],
            "tor": "offline SOCKS peer standing in for the Tor client; transport boundary only, no onion anonymity claim",
            "amounts": {
                "deposits": [str(DEPOSIT), str(DEPOSIT)],
                "relayed_send": str(RELAYED_SEND),
                "relayer_fee": "300000000",
                "bounced_withdrawal": str(BOUNCED_WITHDRAWAL),
                "direct_send_spending_recovered_leaf": str(DIRECT_SEND),
                "public_withdrawal": str(PUBLIC_WITHDRAWAL),
                "relayed_send_with_dropped_submit": str(RELAYED_SEND_SECOND),
            },
            "steps": self.steps,
            "controls": self.controls,
            "proving": self.proving,
            "raw_retention_root": str(self.run_dir),
            "privacy": "index only; Vaults, mnemonics, descriptors, encrypted journals and SOCKS credentials are not copied to Git and are redacted from receipts",
        }
        self.index_out.parent.mkdir(parents=True, exist_ok=True)
        self.index_out.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
        retained = []
        for path in sorted(
            p for p in self.run_dir.rglob("*") if p.is_file() and "private" not in p.parts
        ):
            retained.append(
                {
                    "path": str(path.relative_to(self.run_dir)),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
        write_private_json(
            self.run_dir / "EVIDENCE-RETENTION.json",
            {
                "schema": RETENTION_SCHEMA,
                "utc": utc_now(),
                "index": str(self.index_out),
                "index_sha256": sha256_file(self.index_out),
                "root": str(self.run_dir),
                "private": "private/ holds the participants' configurations, Vaults and encrypted journals; it is retained under 0700 and never hashed into the index",
                "files": retained,
            },
        )
        print(f"INDEX {self.index_out}", flush=True)


def git_head() -> str:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--localnet", type=Path, required=True)
    parser.add_argument("--pool", type=Path, required=True)
    parser.add_argument("--operator", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--index-out", type=Path, required=True)
    parser.add_argument("--base-commit", required=True)
    args = parser.parse_args()
    with contextlib.suppress(KeyboardInterrupt):
        return Run(args).execute()
    return 130


if __name__ == "__main__":
    sys.exit(main())
