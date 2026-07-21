#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
agent-chain-index-e2e.py — real-localnet acceptance of chain-wide contract
discovery via the tosctld indexer (see ROADMAP.md, Phase 3's indexer entry).

Boots a single local TOS chain (same machinery as agent-query-api-e2e.py),
but uses *two independent* tosctl configs against the same running node:

  CONFIG_A  deploys a Task Escrow (workchain 0) and a Capability Registry
            entry (workchain 0) through normal `tosctl agent ...` commands.
            These addresses are recorded in config-a's local `agent_tasks`/
            `capability_registries` maps.

  CONFIG_B  never runs a single `agent task create` or `agent registry
            deploy` command -- its local config has empty `agent_tasks`/
            `capability_registries` maps, confirmed by reading the config
            file directly. Its own `tosctld` HTTP daemon is started against
            the same chain RPC endpoint, with a short tick interval so its
            in-process indexer task catches up quickly.

The check: config-b's `GET /tasks` and `GET /registry` must list the
addresses config-a deployed, purely from the indexer walking chain blocks
-- proving discovery does not depend on which operator's local config
happens to know about an address.

Run from the repository root: uv run python scripts/agent-chain-index-e2e.py
"""
import asyncio
import json
import os
import shutil
import subprocess
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
RPC = "127.0.0.1:19446"
HTTP_B = "127.0.0.1:19447"
WORKDIR = REPO / "test/integration/.agent-chain-index-e2e"
CONFIG_A = WORKDIR / "tosctl-config-a.json"
CONFIG_B = WORKDIR / "tosctl-config-b.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000009"
POLICY_HASH = "22" * 32
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


def http_get(path: str) -> tuple[int, dict]:
    req = urllib.request.Request(f"http://{HTTP_B}{path}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    try:
        return status, json.loads(raw.decode())
    except json.JSONDecodeError:
        print(f"  DEBUG non-JSON response: status={status} raw={raw!r}")
        return status, {}


# tosctl runs as an *async* subprocess: a blocking subprocess.run would stall
# the event loop that drains the in-process node's log pipes, deadlocking the
# chain (and therefore the tosctl call itself) until the subprocess timeout.
async def tosctl(config: Path, *args: str, may_fail: bool = False) -> str:
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{config.parent}/e2e-vault.json?master_key={MASTER_KEY}"
    proc = await asyncio.create_subprocess_exec(
        TOSCTL, *args, "-c", str(config),
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


async def tosctl_json(config: Path, *args: str):
    return json.loads(await tosctl(config, *args, "--format", "json"))


def norm_addr(addr: str) -> str:
    """Normalize base64 and raw address forms to lowercase `wc:hex`."""
    return Address(addr).to_str(is_user_friendly=False).lower()


def same_addr(a: str, b: str) -> bool:
    try:
        return norm_addr(a) == norm_addr(b)
    except Exception:
        return False


async def wallet_address(config: Path, name: str) -> str:
    for entry in await tosctl_json(config, "wallet", "ls"):
        if entry["name"] == name and entry.get("address"):
            return norm_addr(entry["address"])
    raise RuntimeError(f"wallet {name} has no address in `wallet ls`")


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


async def wait_http_ready(timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = http_get("/health")
            if status == 200:
                return True
        except Exception:
            pass
        await asyncio.sleep(1)
    return False


async def poll_http_predicate(path: str, predicate, timeout: float) -> tuple[bool, dict]:
    """Polls GET `path` on config-b's HTTP daemon until `predicate(body)` is
    true or `timeout` elapses -- the indexer catches up asynchronously on its
    own tick interval, so discovery is not expected to be instantaneous."""
    deadline = time.time() + timeout
    last_body: dict = {}
    while time.time() < deadline:
        status, body = http_get(path)
        last_body = body
        if status == 200 and predicate(body):
            return True, body
        await asyncio.sleep(1)
    return False, last_body


def prepare_config(config: Path, http_bind: str | None):
    """Generate a base tosctl config and patch it for this run: point
    chain_rpc at the localnet, disable elections/voting so `tosctl service`
    doesn't need a validator/pool setup, and give the indexer a short tick
    interval so config-b's discovery is fast in a test. `http_bind=None`
    means this config is only ever used for CLI calls (config-a), never
    `tosctl service`.
    """
    subprocess.run([TOSCTL, "config", "generate", "-o", str(config), "--force"], check=True)
    cfg = json.loads(config.read_text())
    cfg["chain_rpc"] = {"urls": [f"http://{RPC}/"], "api_key": None}
    if http_bind is not None:
        cfg["http"] = {"bind": http_bind, "enable_swagger": False, "auth": None}
    cfg["elections"] = None
    cfg.pop("voting", None)
    cfg["tick_interval"] = 2
    config.write_text(json.dumps(cfg, indent=2))


async def run_checks(faucet) -> None:
    print("\n=== provision: config-a wallets ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")

    await tosctl(CONFIG_A, "wallet", "create", "-n", "creator", "-v", "V3R2", "-w", "0")
    await tosctl(CONFIG_A, "wallet", "create", "-n", "owner", "-v", "V3R2", "-w", "0")
    creator = await wallet_address(CONFIG_A, "creator")
    owner = await wallet_address(CONFIG_A, "owner")
    print(f"  creator: {creator}\n  owner:   {owner}")

    await faucet.send(faucet_transfer(faucet, creator, 50))
    check("creator funded", await wait_balance_at_least(creator, 49 * NANO))
    await faucet.send(faucet_transfer(faucet, owner, 50))
    check("owner funded", await wait_balance_at_least(owner, 49 * NANO))
    await tosctl(CONFIG_A, "wallet", "activate", "-n", "creator")
    await tosctl(CONFIG_A, "wallet", "activate", "-n", "owner")
    for label, addr in (("creator", creator), ("owner", owner)):
        active = await poll_predicate(
            lambda a=addr: rpc_call("getAddressState", address=a).get("result") == "active")
        check(f"{label} wallet active", bool(active))

    print("\n=== config-a: deploy a Task Escrow and a Capability Registry entry ===")
    deadline = int(time.time()) + 3600
    task_out = await tosctl_json(
        CONFIG_A, "agent", "task", "create", "--name", "idx-task",
        "--creator", creator, "--budget", "1.0", "--deadline", str(deadline),
        "--review-period", "3600", "--policy-hash", POLICY_HASH,
        "--from", "creator", "--amount", "1.2", "-w", "0", "--yes",
    )
    task_address = norm_addr(task_out["address"])
    print(f"  task escrow:          {task_address}")

    registry_out = await tosctl_json(
        CONFIG_A, "agent", "registry", "deploy", "--name", "idx-registry",
        "--owner", owner,
        "--task-categories-hash", "11" * 32, "--pricing-hash", "22" * 32,
        "--metadata-hash", "33" * 32, "--verification-method-hash", "44" * 32,
        "--bond", "1", "--from", "owner", "--amount", "1.2", "-w", "0", "--yes",
    )
    registry_address = norm_addr(registry_out["address"])
    print(f"  capability registry:  {registry_address}")

    check("task escrow active on chain", await poll_predicate(
        lambda: rpc_call("getAddressState", address=task_address).get("result") == "active"))
    check("capability registry active on chain", await poll_predicate(
        lambda: rpc_call("getAddressState", address=registry_address).get("result") == "active"))

    print("\n=== config-b: confirm it has never heard of either address ===")
    config_b_json = json.loads(CONFIG_B.read_text())
    check("config-b agent_tasks is empty", config_b_json.get("agent_tasks", {}) == {},
          str(config_b_json.get("agent_tasks")))
    check("config-b capability_registries is empty",
          config_b_json.get("capability_registries", {}) == {},
          str(config_b_json.get("capability_registries")))

    print("\n=== start config-b's tosctld HTTP daemon (never ran agent task create) ===")
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{CONFIG_B.parent}/e2e-vault-b.json?master_key={MASTER_KEY}"
    service_proc = await asyncio.create_subprocess_exec(
        TOSCTL, "service", "-c", str(CONFIG_B),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
    )
    try:
        check("config-b tosctld health endpoint ready", await wait_http_ready())

        print("\n=== GET /tasks on config-b discovers config-a's Task Escrow ===")
        found, body = await poll_http_predicate(
            "/tasks",
            lambda b: any(same_addr(item.get("address", ""), task_address)
                          for item in b.get("result", [])),
            timeout=60.0,
        )
        check("indexer discovers the task escrow chain-wide", found, str(body)[:2000])
        if found:
            item = next(i for i in body["result"] if same_addr(i["address"], task_address))
            check("discovered task has no local name (indexer-only entry)",
                  item.get("name") is None or same_addr(item["name"], task_address), str(item))
            task = item.get("task") or {}
            check("discovered task creator matches", same_addr(task.get("creator", ""), creator),
                  str(task))
            check("discovered task status is open", task.get("status") == "open", str(task))

        print("\n=== GET /registry on config-b discovers config-a's Capability Registry ===")
        found, body = await poll_http_predicate(
            "/registry",
            lambda b: any(same_addr(item.get("address", ""), registry_address)
                          for item in b.get("result", [])),
            timeout=60.0,
        )
        check("indexer discovers the capability registry chain-wide", found, str(body)[:2000])
        if found:
            entry = next(i for i in body["result"] if same_addr(i["address"], registry_address))
            check("discovered registry owner matches", same_addr(entry.get("owner", ""), owner),
                  str(entry))
            check("discovered registry status is active", entry.get("status") == "active",
                  str(entry))

        print("\n=== GET /registry/{address} direct lookup on config-b ===")
        status, body = http_get(f"/registry/{registry_address}")
        check("get_registry status 200", status == 200, f"status={status} body={body}")
        check("get_registry owner matches",
              same_addr(body.get("result", {}).get("owner", ""), owner), str(body))

        print("\n=== GET /disputes on config-b (no disputes deployed -- empty, not an error) ===")
        status, body = http_get("/disputes")
        check("list_disputes status 200", status == 200, f"status={status} body={body}")
        check("list_disputes total is zero", body.get("total") == 0, str(body))

    finally:
        service_proc.terminate()
        try:
            await asyncio.wait_for(service_proc.wait(), timeout=10)
        except TimeoutError:
            service_proc.kill()


async def main() -> int:
    if not Path(TOSCTL).exists():
        print(f"FATAL: tosctl binary not found at {TOSCTL} "
              f"(build with: cargo build --manifest-path tosctl/src/Cargo.toml -p tosctl)",
              file=sys.stderr)
        return 2

    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    prepare_config(CONFIG_A, http_bind=None)
    prepare_config(CONFIG_B, http_bind=HTTP_B)
    install = Install(BUILD_DIR, REPO)

    async with Network(install, WORKDIR / "net", base_port=23900) as network:
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
    rc = asyncio.run(main())
    sys.exit(rc)
