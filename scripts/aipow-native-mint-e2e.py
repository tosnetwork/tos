#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
aipow-native-mint-e2e.py -- W4.6 full-node e2e for the Phase C native epoch mint.

Boots a localnet with capAipow + ConfigParams 90-93 active (the settlement address
in 93 is the counterfactual address of a settlement we deploy at runtime), then
drives one commitment through the announce -> finalize -> window-elapsed -> mint
path and asserts the native aggregate mint fired exactly once:

  ACTIVATE  compute the settlement's counterfactual address (tosctl aipow-settlement
            address); boot with enable_aipow so ConfigParam 93 names it.
  DEPLOY    deploy the settlement there (small challenge_window so the window is
            seconds, not 7 days) and a score commitment for a fixed future epoch.
  REGISTER  announce the commitment (records a candidate with registered_at); wait
            out the challenge window; finalize permissionlessly.
  MINT      the masterchain collator originates the epoch mint to the settlement and
            validate-query re-derives it -- proven by the settlement's minted_total
            rising by exactly the pool, the cursor advancing to epoch+1, the block
            chain never halting (collator<->validator agreement), and the settle
            forwarding value to a live distributor (B1/B2).
  IDLE      a later block mints 0 for the (now unregistered) next epoch, and the
            cumulative mint never exceeds the cap.

Exit 0 iff every check passes. Run from the repo root:
  ninja -C build validator-engine dht-server create-state   # binaries MUST be current
  uv run python scripts/aipow-native-mint-e2e.py
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from tostester.install import Install
from tostester.network import Network, StartOptions
from contract import tos
from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build"))
TOSCTL = os.environ.get("TOSCTL", str(REPO / "tosctl/src/target/debug/tosctl"))
RPC = "127.0.0.1:19661"
WORKDIR = REPO / "test/integration/.aipow-native-mint-e2e"
CONFIG = WORKDIR / "tosctl-config.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000001"

EPOCH_SECONDS = 65_536
CHALLENGE_WINDOW = 15       # seconds; < register_grace
REGISTER_GRACE = 3600
WINDOW_MARGIN = 12          # extra seconds past the challenge window before finalize
NANO = 1_000_000_000
ORGANIC = 1 * NANO         # committed organic value -> pool = min(cap, k*organic) = 1 TOS (k=1/1)
EXPECTED_POOL = ORGANIC
TOTAL_SCORE = 1_000_000
SCORE_ROOT = "5c" * 32
METHODOLOGY_HASH = "11" * 32  # must match ConfigParam 93 methodology_hash (M2)
RATE_CARD_HASH = "22" * 32   # must match ConfigParam 93 rate_card_hash (round-3 H1)
# The governance-approved reviewer registered in ConfigParam 93 (gate 3). The native
# path mints only if the commitment's reviewer equals this; it never rules on the
# unchallenged happy path, so a fixed placeholder id suffices for the mint test.
REVIEWER_HEX = "44" * 32
REVIEWER_ADDR = f"-1:{REVIEWER_HEX}"

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(label)
    return ok


def rpc_call(method: str, **params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        f"http://{RPC}/jsonRPC", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


async def tosctl(*args: str, may_fail: bool = False) -> str:
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{CONFIG.parent}/e2e-vault.json?master_key={MASTER_KEY}"
    proc = await asyncio.create_subprocess_exec(
        TOSCTL, *args, "-c", str(CONFIG),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
    out, err = await asyncio.wait_for(proc.communicate(), timeout=180)
    if proc.returncode != 0 and not may_fail:
        raise RuntimeError(f"tosctl {' '.join(args)} failed:\n{out.decode()}\n{err.decode()}")
    return out.decode() + err.decode()


async def tosctl_json(*args: str):
    return json.loads(await tosctl(*args, "--format", "json"))


def norm_addr(addr: str) -> str:
    return Address(addr).to_str(is_user_friendly=False).lower()


async def settlement_address(next_epoch: int) -> tuple[str, int]:
    """(address, account_id_int) of the counterfactual settlement for `next_epoch`."""
    out = await tosctl_json(
        "agent", "aipow-settlement", "address",
        "--next-epoch", str(next_epoch), "--epoch-seconds", str(EPOCH_SECONDS),
        "--register-grace", str(REGISTER_GRACE), "--challenge-window", str(CHALLENGE_WINDOW),
        "--earner-workchain=-1")
    return norm_addr(out["address"]), int(out["account_id_hex"], 16)


def balance(addr: str) -> int:
    return int(rpc_call("getAddressInformation", address=addr)["result"]["balance"])


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


async def poll(predicate, timeout: float = 90.0, interval: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        await asyncio.sleep(interval)
    return False


async def async_poll(coro_fn, timeout: float = 90.0, interval: float = 2.0) -> bool:
    """Poll an async predicate until it returns True or the timeout elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if await coro_fn():
                return True
        except Exception:
            pass
        await asyncio.sleep(interval)
    return False


async def commit_status() -> str:
    try:
        return (await tosctl_json("agent", "aipow", "show", "--name", "e2e-commit")).get("status", "")
    except Exception:
        return ""


async def minted_total(addr: str) -> int:
    return int((await settlement_show(addr))["minted_total"])


async def wallet_address(name: str) -> str:
    for entry in await tosctl_json("wallet", "ls"):
        if entry["name"] == name and entry.get("address"):
            return norm_addr(entry["address"])
    raise RuntimeError(f"wallet {name} has no address")


def faucet_transfer(faucet, dest: str, amount_tos: float) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True, bounce=False, bounced=False,
                src=faucet.address, dest=Address(dest), value=tos(amount_tos),
                ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0),
            init=None, body=Cell.empty()))


async def settlement_show(addr: str) -> dict:
    # `--address=<addr>` (not `--address <addr>`): a masterchain address begins with
    # "-1:", which clap otherwise parses as an option.
    return await tosctl_json("agent", "aipow-settlement", "show", f"--address={addr}")


async def run_checks(faucet) -> None:
    print("\n=== provision ===")
    if not check("json-rpc ready", await wait_rpc_ready()):
        return
    for name in ("boss",):
        await tosctl("wallet", "create", "-n", name, "-v", "V3R2")
    boss = await wallet_address("boss")
    print(f"  boss (masterchain): {boss}")
    await faucet.send(faucet_transfer(faucet, boss, 200))
    if not check("boss funded", await wait_balance_at_least(boss, 190 * NANO)):
        return
    await tosctl("wallet", "activate", "-n", "boss")
    check("boss active", await poll(
        lambda: rpc_call("getAddressState", address=boss).get("result") == "active"))

    # A fixed FUTURE epoch: skippable_at = (epoch+1)*epoch_seconds + grace is then far
    # in the future, so the epoch is never skip-eligible during the test and the mint
    # is driven purely by the challenge window. It is also the settlement cursor and
    # the commitment epoch.
    epoch = int(time.time()) // EPOCH_SECONDS + 5
    settle_addr, _settle_id = await settlement_address(epoch)
    print(f"  epoch={epoch}  settlement={settle_addr}")
    check("ConfigParam 93 settlement address matches the counterfactual",
          settle_addr == SETTLE_ADDR_BOOT, f"{settle_addr} vs {SETTLE_ADDR_BOOT}")

    print("\n=== DEPLOY: settlement + commitment ===")
    await tosctl(
        "agent", "aipow-settlement", "deploy",
        "--next-epoch", str(epoch), "--epoch-seconds", str(EPOCH_SECONDS),
        "--register-grace", str(REGISTER_GRACE), "--challenge-window", str(CHALLENGE_WINDOW),
        "--earner-workchain=-1", "--from", "boss", "--amount", "5", "--yes")
    if not check("settlement active", await poll(
            lambda: rpc_call("getAddressState", address=settle_addr).get("result") == "active")):
        return
    data = await settlement_show(settle_addr)
    check("settlement cursor at the target epoch", data["next_epoch"] == epoch, str(data))
    check("settlement challenge_window stored", data["challenge_window"] == CHALLENGE_WINDOW, str(data))
    check("settlement minted_total starts at zero", int(data["minted_total"]) == 0, str(data))

    window_deadline = int(time.time()) + CHALLENGE_WINDOW + WINDOW_MARGIN
    deploy = await tosctl_json(
        "agent", "aipow", "deploy", "--name", "e2e-commit",
        f"--committer={boss}", f"--reviewer={REVIEWER_ADDR}", "--epoch", str(epoch),
        "--window-deadline", str(window_deadline), "--commit-bond", "2",
        "--score-root", SCORE_ROOT, "--methodology-hash", METHODOLOGY_HASH,
        "--rate-card-hash", RATE_CARD_HASH,
        "--total-score", str(TOTAL_SCORE), "--organic-settled-value", str(ORGANIC),
        f"--settlement={settle_addr}", "--from", "boss", "--yes")
    commitment_addr = norm_addr(deploy["address"])
    print(f"  commitment: {commitment_addr}")
    if not check("commitment active", await poll(
            lambda: rpc_call("getAddressState", address=commitment_addr).get("result") == "active")):
        return

    print("\n=== REGISTER: announce, wait the challenge window, finalize ===")
    await tosctl("agent", "aipow", "send", "--operation", "announce", "--name", "e2e-commit",
                 "--from", "boss", "--yes")
    # The announce records a candidate with the settlement; the commitment stays
    # committed until finalize.
    check("commitment still committed after announce",
          await async_poll(lambda: commit_status_is("committed")))

    wait_s = max(0, window_deadline - int(time.time())) + 3
    print(f"  waiting {wait_s}s for the challenge window to close…")
    await asyncio.sleep(wait_s)
    await tosctl("agent", "aipow", "send", "--operation", "finalize", "--name", "e2e-commit",
                 "--from", "boss", "--yes")
    check("commitment final on chain",
          await async_poll(lambda: commit_status_is("final"), timeout=60))

    print("\n=== MINT: the native epoch mint credits the settlement ===")
    minted = await async_poll(
        lambda: minted_at_least(settle_addr, EXPECTED_POOL), timeout=150, interval=3)
    data = await settlement_show(settle_addr)
    check("settlement minted_total rose to the pool (native mint fired)", minted, str(data))
    check("settlement minted_total equals exactly the pool", int(data["minted_total"]) == EXPECTED_POOL,
          str(data))
    check("settlement cursor advanced past the settled epoch (settle succeeded, no bounce)",
          data["next_epoch"] == epoch + 1, str(data))

    print("\n=== IDLE: the next block mints 0 and the cap holds ===")
    before = int(data["minted_total"])
    await asyncio.sleep(10)
    after = await minted_total(settle_addr)
    check("a later block mints nothing for the unregistered next epoch", after == before,
          f"{before}->{after}")
    check("cumulative mint is within the cap", after <= int(data["total_cap"]))


async def commit_status_is(want: str) -> bool:
    return await commit_status() == want


async def minted_at_least(addr: str, target: int) -> bool:
    return await minted_total(addr) >= target


# Captured after the counterfactual is computed, before boot (see main).
SETTLE_ADDR_BOOT = ""


async def main() -> int:
    global SETTLE_ADDR_BOOT
    if not Path(TOSCTL).exists():
        print(f"FATAL: tosctl not found at {TOSCTL}", file=sys.stderr)
        return 2
    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    subprocess.run([TOSCTL, "config", "generate", "-o", str(CONFIG), "--force"], check=True)
    cfg = json.loads(CONFIG.read_text())
    cfg["chain_rpc"] = {"urls": [f"http://{RPC}/"], "api_key": None}
    cfg["elections"] = None
    cfg.pop("voting", None)
    cfg["tick_interval"] = 2
    CONFIG.write_text(json.dumps(cfg, indent=2))

    # The settlement address depends on next_epoch; fix the epoch the same way
    # run_checks will, so ConfigParam 93 names exactly the settlement we deploy.
    epoch = int(time.time()) // EPOCH_SECONDS + 5
    out = subprocess.run(
        [TOSCTL, "agent", "aipow-settlement", "address", "--next-epoch", str(epoch),
         "--epoch-seconds", str(EPOCH_SECONDS), "--register-grace", str(REGISTER_GRACE),
         "--challenge-window", str(CHALLENGE_WINDOW), "--earner-workchain=-1",
         "--format", "json", "-c", str(CONFIG)],
        capture_output=True, text=True, check=True)
    info = json.loads(out.stdout)
    SETTLE_ADDR_BOOT = norm_addr(info["address"])
    settle_id = int(info["account_id_hex"], 16)
    commitment_code_hash = int(info["commitment_code_hash"], 16)
    print(f"counterfactual settlement (ConfigParam 93): {SETTLE_ADDR_BOOT}")
    print(f"commitment code hash (ConfigParam 93): {info['commitment_code_hash']}")

    install = Install(BUILD_DIR, REPO)
    async with Network(install, WORKDIR / "net", base_port=25300) as network:
        network.config.enable_aipow = True
        network.config.aipow_settlement_addr = settle_id
        network.config.aipow_commitment_code_hash = commitment_code_hash
        network.config.aipow_reviewer_addr = int(REVIEWER_HEX, 16)
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
            await run_checks(faucet)
        finally:
            for t in (node_task, dht_task):
                t.cancel()
            await asyncio.gather(node_task, dht_task, return_exceptions=True)

    print("\n=== RESULT:", "ALL PASS" if not failures else f"{len(failures)} FAILURE(S)", "===")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
