#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
agent-wallet-account-e2e.py — real-localnet acceptance of the Agent Wallet /
Agent Account CLI lifecycle (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/agent-wallet-mvp.md's "next engineering
step": public-testnet-style acceptance for controller-signed Agent Account
actions, beyond the throwaway per-op coverage other scripts exercise
indirectly).

Boots a single local TOS chain (same machinery as agent-task-escrow-e2e.py),
deploys an Agent Wallet/Account, and exercises every lifecycle CLI command
end to end against a real validator:

  agent account deploy / show / status
  agent account native-prepare         (bodyless native TOS Gift profile)
  exact BOC retry + duplicate submission
  agent account cancel-prepare         (same-seqno finalized invalidation)
  agent account task-send            (controller-signed transfer)
  agent wallet update-policy + agent account update-policy
      (pushes the local policy to chain -- this is the exact code path a
      previously-undetected bug broke: `load_maybe_hash` was called without
      the `~` mutating-call convention in agent-account-code.fc, so it never
      advanced the parser's cursor and `update_policy` unconditionally threw
      a cell-underflow exception. Fixed this session; this script is the
      real-network proof, not just the sandbox unit test.)
  agent wallet rotate-controller + agent account rotate-controller
      (rotates the controller key, then proves the *new* key's signature is
      accepted for a subsequent task-send)
  agent wallet send                  (owner-authorized transfer)

It then stops and restarts the validator mid-lifecycle (with its data
directory intact) and re-verifies the Agent Account's on-chain state is
still correct after catch-up -- https://github.com/tosnetwork/doc/blob/main/tos-blockchain/ai-actor-testing-matrix.md's "restart
one validator during task lifecycle" / "verify transaction history after
catch-up" Local Testnet Tests, scoped to a single-node restart (this harness
has no existing multi-validator example to build a true multi-validator
fault-tolerance test on top of; that remains open, see ROADMAP.md).

Run from the repository root: uv run python scripts/agent-wallet-account-e2e.py
"""
import asyncio
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from tostester.install import Install
from tostester.network import Network, StartOptions
from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build-remove-workchains-full"))
TOSCTL = os.environ.get("TOSCTL", str(REPO / "tosctl/src/target/debug/tosctl"))
RPC = "127.0.0.1:19546"
WORKDIR = REPO / "test/integration/.agent-wallet-account-e2e"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000010"
NANO = 1_000_000_000

failures: list[str] = []


def check(label: str, ok: bool, detail: str = ""):
    if ok:
        print(f"  PASS: {label}")
    else:
        print(f"  FAIL: {label}  {detail}")
        failures.append(label)


def rpc_call(method: str, **params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        f"http://{RPC}/jsonRPC", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode())


def balance(addr: str) -> int:
    return int(rpc_call("getAddressInformation", address=addr)["result"]["balance"])


def broadcast_boc(exact_boc_base64: str, may_fail: bool = False):
    try:
        return rpc_call("sendBoc", boc=exact_boc_base64)
    except urllib.error.HTTPError as error:
        if not may_fail:
            raise
        return {"http_status": error.code, "body": error.read().decode(errors="replace")}


async def tosctl(*args: str, may_fail: bool = False) -> str:
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{WORKDIR}/e2e-vault.json?master_key={MASTER_KEY}"
    proc = await asyncio.create_subprocess_exec(
        TOSCTL, *args, "-c", str(CONFIG),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=180)
    except TimeoutError:
        proc.kill()
        raise RuntimeError(f"tosctl {' '.join(args)} timed out")
    if proc.returncode != 0 and not may_fail:
        raise RuntimeError(
            f"tosctl {' '.join(args)} failed:\n{out.decode()}\n{err.decode()}")
    return out.decode()


async def tosctl_json(*args: str):
    return json.loads(await tosctl(*args, "--format", "json"))


async def tosctl_action_json(*args: str):
    """Decode commands whose only output format is their strict JSON artifact."""
    return json.loads(await tosctl(*args))


def norm_addr(addr: str) -> str:
    return Address(addr).to_str(is_user_friendly=False).lower()


def same_addr(a: str, b: str) -> bool:
    try:
        return norm_addr(a) == norm_addr(b)
    except Exception:
        return False


def faucet_transfer(faucet, dest: str, amount_tos: float) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True, bounce=False, bounced=False,
                src=faucet.address, dest=Address(dest), value=tos_amount(amount_tos),
                ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0,
            ),
            init=None,
            body=Cell.empty(),
        ),
    )


def tos_amount(amount_tos: float):
    from contract import tos
    return tos(amount_tos)


async def poll_predicate(predicate, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        await asyncio.sleep(1)
    return False


async def predicate_stays_true(predicate, duration: float = 60.0) -> bool:
    """Continuously disprove a negative invariant over the normal CI window."""
    deadline = time.time() + duration
    observed = False
    while time.time() < deadline:
        try:
            holds = predicate()
            observed = True
            if not holds:
                return False
        except Exception:
            # A transient RPC failure is not evidence that the invariant held.
            pass
        await asyncio.sleep(1)
    return observed


async def async_predicate_stays_true(predicate, duration: float = 60.0) -> bool:
    """Async counterpart for invariants that require a CLI state read."""
    deadline = time.time() + duration
    observed = False
    while time.time() < deadline:
        try:
            holds = await predicate()
            observed = True
            if not holds:
                return False
        except Exception:
            pass
        await asyncio.sleep(1)
    return observed


async def wait_balance_at_least(addr: str, target: int, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if balance(addr) >= target:
                return True
        except Exception:
            pass
        await asyncio.sleep(1)
    return False


async def wait_account_seqno(account: str, target: int, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            state = await tosctl_json("agent", "account", "show", "--address", account)
            if state.get("seqno") == target:
                return True
        except Exception:
            pass
        await asyncio.sleep(1)
    return False


async def wait_rpc_ready(timeout: float = 180.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if "result" in rpc_call("getMasterchainInfo"):
                return True
        except Exception:
            pass
        await asyncio.sleep(2)
    return False


def write_config():
    import subprocess
    subprocess.run([TOSCTL, "config", "generate", "-o", str(CONFIG), "--force"], check=True)
    cfg = json.loads(CONFIG.read_text())
    cfg["chain_rpc"] = {"urls": [f"http://{RPC}/"], "api_key": None}
    cfg["elections"] = None
    cfg.pop("voting", None)
    CONFIG.write_text(json.dumps(cfg, indent=2))


async def run_checks(faucet, node) -> None:
    print("\n=== provision: funding wallet ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")

    await tosctl("wallet", "create", "-n", "funder", "-v", "V3R2", "-w", "0")
    funder_out = await tosctl_json("wallet", "ls")
    funder = norm_addr(next(e["address"] for e in funder_out if e["name"] == "funder"))
    await faucet.send(faucet_transfer(faucet, funder, 100))
    check("funder funded", await wait_balance_at_least(funder, 99 * NANO))
    await tosctl("wallet", "activate", "-n", "funder")
    check("funder wallet active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=funder).get("result") == "active"))

    print("\n=== deploy: Agent Wallet + Agent Account ===")
    await tosctl(
        "agent", "wallet", "create", "--name", "agent-1", "-v", "V5R1", "-w", "0",
        "--max-per-tx", "2", "--daily-limit", "10",
    )
    deploy_out = await tosctl_json(
        "agent", "account", "deploy", "--wallet", "agent-1", "--from", "funder",
        "-w", "0", "--amount", "3", "--yes",
    )
    account = norm_addr(deploy_out["address"])
    print(f"  agent account: {account}")
    check("agent account active on chain", await poll_predicate(
        lambda: rpc_call("getAddressState", address=account).get("result") == "active"))

    # The Agent Wallet is itself a wallet contract -- the *owner* of the
    # Agent Account -- separate from the Agent Account contract just
    # deployed above. Owner-authorized ops (update-policy, rotate-controller,
    # send) are sent from the Agent Wallet's own address, so it needs to be
    # funded and activated on-chain first, exactly like any other wallet.
    print("\n=== fund + activate the Agent Wallet itself (it is the Agent Account's owner) ===")
    agent_wallet_show = await tosctl_json("agent", "wallet", "show", "-n", "agent-1")
    agent_wallet_addr = norm_addr(agent_wallet_show.get("address", agent_wallet_show.get("result", {}).get("address", "")))
    await tosctl("agent", "wallet", "fund", "--name", "agent-1", "--from", "funder", "--amount", "2", "--yes")
    check("agent wallet funded", await wait_balance_at_least(agent_wallet_addr, int(1.9 * NANO)))
    await tosctl("agent", "wallet", "activate", "-n", "agent-1")
    check("agent wallet active on chain", await poll_predicate(
        lambda: rpc_call("getAddressState", address=agent_wallet_addr).get("result") == "active"))

    print("\n=== agent account status: local profile matches chain ===")
    status_out = await tosctl_json("agent", "account", "status", "--wallet", "agent-1", "-w", "0")
    check("status reports local profile matches chain",
          status_out.get("matches_profile") is True, str(status_out))

    await tosctl("wallet", "create", "-n", "target", "-v", "V3R2", "-w", "0")
    target_ls = await tosctl_json("wallet", "ls")
    target = norm_addr(next(e["address"] for e in target_ls if e["name"] == "target"))

    print("\n=== bodyless native Gift: exact retry and duplicate submission ===")
    target_before = balance(target)
    # Stay well inside the 3600-second contract ceiling: local wall time can
    # lead finalized block time slightly, so using the exact ceiling is flaky.
    valid_until = int(time.time()) + 300
    native_args = (
        "agent", "account", "native-prepare", "--wallet", "agent-1", "--target", target,
        "--amount-nanotos", str(500_000_000), "--fee-reserve-nanotos", str(50_000_000),
        "--valid-until", str(valid_until), "--action-id", "a" * 64,
        "--request-digest", "sha256:" + "1" * 64,
        "--response-digest", "sha256:" + "2" * 64,
        "--owner-authorization-digest", "sha256:" + "3" * 64,
        "--unsigned-transfer-digest", "sha256:" + "4" * 64, "--yes",
    )
    prepared = await tosctl_action_json(*native_args)
    retried = await tosctl_action_json(*native_args)
    exact_boc = prepared.get("exact_signed_boc", "")
    check("native Gift returns the frozen prepared-action schema",
          prepared.get("schema") == "tosctl.agent-account.prepared-action.v1"
          and prepared.get("action") == "agent-native-send" and bool(exact_boc), str(prepared))
    check("exact native Gift retry returns byte-identical BOC",
          retried.get("exact_signed_boc") == exact_boc)
    first_submit = broadcast_boc(exact_boc)
    duplicate_submit = broadcast_boc(exact_boc, may_fail=True)
    check("node accepts exact BOC submission path",
          "result" in first_submit and
          ("result" in duplicate_submit or duplicate_submit.get("http_status") == 500),
          f"first={first_submit} duplicate={duplicate_submit}")
    check("duplicate native Gift submission credits exactly once", await wait_balance_at_least(
        target, target_before + 500_000_000))
    check("duplicate native Gift remains credited exactly once for the observation window",
          await predicate_stays_true(
              lambda: balance(target) == target_before + 500_000_000))
    check("native Gift consumes exactly one Agent Account seqno",
          await wait_account_seqno(account, 1))

    print("\n=== same-seqno cancellation wins and original Gift stays unpaid ===")
    cancel_target_before = balance(target)
    cancel_valid_until = int(time.time()) + 300
    cancel_primary = await tosctl_action_json(
        "agent", "account", "native-prepare", "--wallet", "agent-1", "--target", target,
        "--amount-nanotos", str(200_000_000), "--fee-reserve-nanotos", str(50_000_000),
        "--valid-until", str(cancel_valid_until), "--action-id", "b" * 64,
        "--request-digest", "sha256:" + "5" * 64,
        "--response-digest", "sha256:" + "6" * 64,
        "--owner-authorization-digest", "sha256:" + "7" * 64,
        "--unsigned-transfer-digest", "sha256:" + "8" * 64, "--yes",
    )
    cancellation = await tosctl_action_json(
        "agent", "account", "cancel-prepare", "--wallet", "agent-1",
        "--action-id", "b" * 64,
        "--owner-authorization-digest", "sha256:" + "9" * 64,
        "--valid-until", str(cancel_valid_until), "--yes",
    )
    broadcast_boc(cancellation.get("exact_signed_boc", ""))
    check("cancellation consumes the shared sequence", await wait_account_seqno(account, 2))
    broadcast_boc(cancel_primary.get("exact_signed_boc", ""), may_fail=True)
    check("finalized cancellation prevents destination credit for the observation window",
          await predicate_stays_true(lambda: balance(target) == cancel_target_before))

    print("\n=== controller-signed transfer (agent account task-send) ===")
    target_before = balance(target)
    task_valid_until = int(time.time()) + 300
    await tosctl(
        "agent", "account", "task-send", "--wallet", "agent-1", "--target", target,
        "--value", "0.5", "--valid-until", str(task_valid_until),
        "--action-id", "c" * 64, "--yes",
    )
    check("controller-signed transfer delivered", await wait_balance_at_least(
        target, target_before + int(0.49 * NANO)))

    print("\n=== update-policy: push a new policy to the deployed Agent Account ===")
    print("  (this is the exact path a previously-undetected bug broke: an internal")
    print("   FunC helper never advanced its parser cursor, so update_policy always")
    print("   aborted with a cell-underflow exception -- fixed this session)")
    await tosctl(
        "agent", "wallet", "update-policy", "--name", "agent-1",
        "--max-per-tx", "1", "--daily-limit", "5",
    )
    await tosctl("agent", "account", "update-policy", "--wallet", "agent-1", "--amount", "0.05", "--yes")
    policy_out = await tosctl_json("agent", "account", "show", "--address", account)
    check("on-chain max_per_tx updated", policy_out.get("max_per_tx") == 1 * NANO, str(policy_out))
    check("on-chain daily_limit updated", policy_out.get("daily_limit") == 5 * NANO, str(policy_out))

    print("\n=== rotate-controller: rotate the key, prove the new key works ===")
    await tosctl("agent", "wallet", "rotate-controller", "--name", "agent-1")
    await tosctl("agent", "account", "rotate-controller", "--wallet", "agent-1", "--amount", "0.05", "--yes")
    target_before_2 = balance(target)
    valid_until_2 = int(time.time()) + 300
    await tosctl(
        "agent", "account", "task-send", "--wallet", "agent-1", "--target", target,
        "--value", "0.3", "--valid-until", str(valid_until_2),
        "--action-id", "d" * 64, "--yes",
    )
    check("post-rotation controller-signed transfer delivered", await wait_balance_at_least(
        target, target_before_2 + int(0.29 * NANO)))

    print("\n=== owner-authorized transfer (agent wallet send) ===")
    target_before_3 = balance(target)
    await tosctl("agent", "wallet", "send", "--name", "agent-1", "--to", target, "--amount", "0.3", "--yes")
    check("owner-authorized transfer delivered", await wait_balance_at_least(
        target, target_before_3 + int(0.29 * NANO)))

    print("\n=== restart the validator mid-lifecycle, verify catch-up ===")
    seqno_before_stop = rpc_call("getMasterchainInfo")["result"]["last"]["seqno"]
    await node.stop()
    print(f"  stopped at seqno {seqno_before_stop}")
    await asyncio.sleep(3)
    await node.run(StartOptions(args=["--json-rpc-address", RPC]))
    check("validator restarts and becomes reachable again", await wait_rpc_ready(timeout=120))
    check("masterchain seqno advances past the pre-restart value after catch-up",
          await poll_predicate(
              lambda: rpc_call("getMasterchainInfo")["result"]["last"]["seqno"] > seqno_before_stop,
              timeout=60))

    print("\n=== state survives the restart ===")
    post_restart = await tosctl_json("agent", "account", "show", "--address", account)
    check("agent account state intact after restart",
          post_restart.get("max_per_tx") == 1 * NANO, str(post_restart))
    check("post-restart balance matches pre-restart total transfers",
          balance(target) >= target_before_3 + int(0.29 * NANO))

    print("\n=== finalized chain time rejects an expired native Gift ===")
    expired_target_before = balance(target)
    expired_seqno = (await tosctl_json(
        "agent", "account", "show", "--address", account))["seqno"]
    expiry = int(time.time()) + 3
    expired = await tosctl_action_json(
        "agent", "account", "native-prepare", "--wallet", "agent-1", "--target", target,
        "--amount-nanotos", str(100_000_000), "--fee-reserve-nanotos", str(50_000_000),
        "--valid-until", str(expiry), "--action-id", "e" * 64,
        "--request-digest", "sha256:" + "a" * 64,
        "--response-digest", "sha256:" + "b" * 64,
        "--owner-authorization-digest", "sha256:" + "c" * 64,
        "--unsigned-transfer-digest", "sha256:" + "d" * 64, "--yes",
    )
    # Cross the validity boundary and then require a new finalized block before
    # submission, so rejection is based on chain time rather than local sleep.
    await asyncio.sleep(max(0, expiry - int(time.time()) + 1))
    pre_expiry_seqno = rpc_call("getMasterchainInfo")["result"]["last"]["seqno"]
    check("chain finalizes a block after the Gift validity boundary",
          await poll_predicate(
              lambda: rpc_call("getMasterchainInfo")["result"]["last"]["seqno"]
              > pre_expiry_seqno))
    broadcast_boc(expired.get("exact_signed_boc", ""), may_fail=True)

    async def expired_state_unchanged() -> bool:
        state = await tosctl_json("agent", "account", "show", "--address", account)
        return (state.get("seqno") == expired_seqno
                and balance(target) == expired_target_before)

    check("expired native Gift consumes no seqno and produces no credit for the observation window",
          await async_predicate_stays_true(expired_state_unchanged))


async def main() -> int:
    if not Path(TOSCTL).exists():
        print(f"FATAL: tosctl binary not found at {TOSCTL} "
              f"(build with: cargo build --manifest-path tosctl/src/Cargo.toml -p tosctl)",
              file=sys.stderr)
        return 2

    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    write_config()
    install = Install(BUILD_DIR, REPO)

    async with Network(install, WORKDIR / "net", base_port=24000) as network:
        dht = network.create_dht_node()
        node = network.create_full_node()
        node.make_initial_validator()
        node.announce_to(dht)

        dht_task = asyncio.create_task(dht.run())
        node_task = asyncio.create_task(node.run(StartOptions(args=["--json-rpc-address", RPC])))
        try:
            await asyncio.wait_for(network.wait_mc_block(seqno=1), timeout=120)
            client = await node.toslib_client()
            faucet = network.zerostate.main_wallet(client)
            await run_checks(faucet, node)
        finally:
            node_task.cancel()
            dht_task.cancel()
            await asyncio.gather(node_task, dht_task, return_exceptions=True)
            await node.stop()
            await dht.stop()

    print("\n=== RESULT:", "ALL PASS" if not failures else f"{len(failures)} FAILURE(S)", "===")
    return 1 if failures else 0


if __name__ == "__main__":
    rc = asyncio.run(main())
    sys.exit(rc)
