#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
agent-query-api-e2e.py — real-localnet acceptance of the Agent/Task HTTP query API.

Boots a single-process local TOS chain (same machinery as
agent-task-escrow-e2e.py), provisions a file vault plus a tosctl config,
creates and funds a creator + agent wallet, deploys a real Agent Account and
three real Task Escrows (left open, accepted, and fully settled), then starts
the `tosctld` HTTP daemon (`tosctl service`) against that same config and
exercises the query API over real HTTP against the running validator:

  GET /agents/{address}   -- the deployed Agent Account
  GET /tasks/{address}    -- each of the three Task Escrows, in their real states
  GET /tasks              -- unfiltered listing, then status/creator/agent/deadline filters
  GET /agents/not-an-address, GET /tasks/not-an-address -- malformed address -> 400
  GET /tasks/{never-deployed address}                   -- calibrates not_found vs rpc_unavailable
  GET /tasks/{the Agent Account address}                -- wrong contract kind for the decoder

Exit code 0 iff every check passes.

Run from the repository root: uv run python scripts/agent-query-api-e2e.py
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
RPC = "127.0.0.1:18647"
HTTP = "127.0.0.1:18648"
WORKDIR = REPO / "test/integration/.agent-query-api-e2e"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000002"
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
    req = urllib.request.Request(f"http://{HTTP}{path}", method="GET")
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


def norm_addr(addr: str) -> str:
    """Normalize base64 and raw address forms to lowercase `wc:hex`."""
    return Address(addr).to_str(is_user_friendly=False).lower()


async def wallet_address(name: str) -> str:
    for entry in await tosctl_json("wallet", "ls"):
        if entry["name"] == name and entry.get("address"):
            return norm_addr(entry["address"])
    raise RuntimeError(f"wallet {name} has no address in `wallet ls`")


async def send_op(operation: str, name: str, frm: str, *extra: str):
    await tosctl("agent", "task", "send", "--operation", operation, "--name", name,
                 "--from", frm, "--yes", *extra)


async def create_task(name: str, creator: str, agent: str | None, budget: float,
                      deadline: int, amount: float) -> str:
    args = ["agent", "task", "create", "--name", name, "--creator", creator,
            "--budget", str(budget), "--deadline", str(deadline),
            "--review-period", "3600", "--policy-hash", POLICY_HASH,
            "--from", "creator", "--amount", str(amount), "-w", "0", "--yes"]
    if agent is not None:
        args += ["--agent", agent]
    out = json.loads(await tosctl(*args, "--format", "json"))
    return out["address"]


async def task_show(name: str):
    return await tosctl_json("agent", "task", "show", "--name", name)


async def wait_status(name: str, want: str, timeout: float = 90.0) -> str:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            last = (await task_show(name))["status"]
            if last == want:
                return last
        except Exception as e:
            last = f"error: {e}"
        await asyncio.sleep(2)
    return last


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


def prepare_config():
    """Generate a base tosctl config and patch it for this run: point
    chain_rpc at the localnet, bind the HTTP daemon, disable auth (this run
    only exercises the auth-disabled passthrough -- Rust-level tests already
    cover the auth-required path structurally), and disable elections/voting
    so `tosctl service` doesn't need a validator/pool setup to start.
    """
    import subprocess
    subprocess.run([TOSCTL, "config", "generate", "-o", str(CONFIG), "--force"], check=True)
    cfg = json.loads(CONFIG.read_text())
    cfg["chain_rpc"] = {"urls": [f"http://{RPC}/"], "api_key": None}
    cfg["http"] = {"bind": HTTP, "enable_swagger": False, "auth": None}
    cfg["elections"] = None
    cfg.pop("voting", None)
    CONFIG.write_text(json.dumps(cfg, indent=2))


async def run_checks(faucet) -> None:
    print("\n=== provision: tosctl wallets ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")

    await tosctl("wallet", "create", "-n", "creator", "-v", "V3R2", "-w", "0")
    await tosctl("wallet", "create", "-n", "agent", "-v", "V3R2", "-w", "0")
    creator = await wallet_address("creator")
    agent = await wallet_address("agent")
    print(f"  creator: {creator}\n  agent:   {agent}")

    await faucet.send(faucet_transfer(faucet, creator, 50))
    check("creator funded", await wait_balance_at_least(creator, 49 * NANO))
    await faucet.send(faucet_transfer(faucet, agent, 50))
    check("agent funded", await wait_balance_at_least(agent, 49 * NANO))
    await tosctl("wallet", "activate", "-n", "creator")
    await tosctl("wallet", "activate", "-n", "agent")
    for label, addr in (("creator", creator), ("agent", agent)):
        active = await poll_predicate(
            lambda a=addr: rpc_call("getAddressState", address=a).get("result") == "active")
        check(f"{label} wallet active", bool(active))

    print("\n=== deploy: Agent Account + three Task Escrows ===")
    await tosctl(
        "agent", "wallet", "create", "--name", "runtime-agent", "-v", "V3R2", "-w", "0",
        "--max-per-tx", "1", "--daily-limit", "5", "--format", "json",
    )
    agent_account_out = await tosctl_json(
        "agent", "account", "deploy", "--wallet", "runtime-agent", "--from", "creator",
        "-w", "0", "--amount", "2", "--yes",
    )
    agent_account = norm_addr(agent_account_out["address"])
    # The Agent Account's owner is the runtime-agent wallet's own underlying
    # address, not the "creator" wallet that merely funded the deployment.
    agent_wallet_info = await tosctl_json("agent", "wallet", "show", "--name", "runtime-agent")
    agent_account_owner = norm_addr(agent_wallet_info["address"])
    check("Agent Account deployed", await poll_predicate(
        lambda: rpc_call("getAddressState", address=agent_account).get("result") == "active"))

    deadline = int(time.time()) + 3600
    open_addr = await create_task("q-open", creator, agent, 1.0, deadline, 1.2)
    check("open task deployed", await wait_status("q-open", "open") == "open")

    accepted_addr = await create_task("q-accepted", creator, agent, 2.0, deadline + 10, 2.2)
    check("accepted-task predeploy open", await wait_status("q-accepted", "open") == "open")
    await send_op("accept", "q-accepted", "agent")
    check("accepted task accepted", await wait_status("q-accepted", "accepted") == "accepted")

    settled_addr = await create_task("q-settled", creator, agent, 3.0, deadline + 20, 3.2)
    await send_op("accept", "q-settled", "agent")
    await send_op("result", "q-settled", "agent",
                  "--result-hash", "aa" * 32, "--evidence-hash", "bb" * 32)
    check("settled task result submitted",
          await wait_status("q-settled", "result_submitted") == "result_submitted")
    await send_op("settle", "q-settled", "creator", "--payout", "1.5")
    check("settled task settled", await wait_status("q-settled", "settled") == "settled")

    print("\n=== start tosctld HTTP daemon ===")
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{WORKDIR}/e2e-vault.json?master_key={MASTER_KEY}"
    service_proc = await asyncio.create_subprocess_exec(
        TOSCTL, "service", "-c", str(CONFIG),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
    )
    try:
        check("tosctld health endpoint ready", await wait_http_ready())

        print("\n=== GET /agents/{address} ===")
        status, body = http_get(f"/agents/{agent_account}")
        check("get_agent status 200", status == 200, f"status={status} body={body}")
        check("get_agent owner matches",
              same_addr(body.get("result", {}).get("owner"), agent_account_owner), str(body))

        print("\n=== GET /tasks/{address} ===")
        # Contract-level note (not a query API concern): `budget` tracks the
        # escrow's *remaining* disbursable balance, which the contract zeroes
        # out once a task is fully settled -- it does not stay pinned to the
        # amount the task was created with.
        for name, addr, want_status, want_budget in (
            ("q-open", open_addr, "open", 1_000_000_000),
            ("q-accepted", accepted_addr, "accepted", 2_000_000_000),
            ("q-settled", settled_addr, "settled", 0),
        ):
            status, body = http_get(f"/tasks/{addr}")
            check(f"get_task {name} status 200", status == 200, f"status={status} body={body}")
            result = body.get("result", {})
            check(f"get_task {name} status field", result.get("status") == want_status,
                  str(result))
            check(f"get_task {name} budget field", result.get("budget") == want_budget,
                  str(result))
            check(f"get_task {name} creator field", same_addr(result.get("creator"), creator),
                  str(result))

        print("\n=== GET /tasks (listing + filters) ===")
        status, body = http_get("/tasks")
        check("list_tasks status 200", status == 200, f"status={status}")
        names = {item["name"] for item in body.get("result", [])}
        check("list_tasks includes all three", {"q-open", "q-accepted", "q-settled"} <= names,
              str(names))
        check("list_tasks total matches", body.get("total") == len(body.get("result", [])),
              str(body))

        status, body = http_get("/tasks?status=settled")
        settled_names = {item["name"] for item in body.get("result", [])}
        check("status filter returns only settled", settled_names == {"q-settled"},
              str(settled_names))

        status, body = http_get(f"/tasks?creator={creator}")
        creator_names = {item["name"] for item in body.get("result", [])}
        check("creator filter returns all three", {"q-open", "q-accepted", "q-settled"} <= creator_names,
              str(creator_names))

        status, body = http_get(f"/tasks?agent={agent}")
        agent_names = {item["name"] for item in body.get("result", [])}
        check("agent filter returns all three (all assigned to the same agent)",
              {"q-open", "q-accepted", "q-settled"} <= agent_names, str(agent_names))

        status, body = http_get(f"/tasks?deadline_after={deadline + 15}")
        after_names = {item["name"] for item in body.get("result", [])}
        check("deadline_after filter returns only q-settled", after_names == {"q-settled"},
              str(after_names))

        print("\n=== malformed addresses -> 400 invalid_request ===")
        status, body = http_get("/agents/not-an-address")
        check("get_agent malformed address -> 400", status == 400, f"status={status}")
        check("get_agent malformed address kind", body.get("error", {}).get("kind") == "invalid_request",
              str(body))

        status, body = http_get("/tasks/not-an-address")
        check("get_task malformed address -> 400", status == 400, f"status={status}")
        check("get_task malformed address kind", body.get("error", {}).get("kind") == "invalid_request",
              str(body))

        print("\n=== never-deployed address (calibration) ===")
        never_deployed = "0:" + "ee" * 32
        status, body = http_get(f"/tasks/{never_deployed}")
        print(f"  OBSERVED: status={status} body={json.dumps(body)}")
        check("never-deployed address does not 200", status != 200, f"status={status}")

        print("\n=== wrong contract kind (Agent Account queried as a Task) ===")
        status, body = http_get(f"/tasks/{agent_account}")
        print(f"  OBSERVED: status={status} body={json.dumps(body)}")
        check("wrong-kind contract does not 200", status != 200, f"status={status}")
    finally:
        service_proc.terminate()
        try:
            await asyncio.wait_for(service_proc.wait(), timeout=10)
        except TimeoutError:
            service_proc.kill()
            await service_proc.wait()


def same_addr(candidate, want: str) -> bool:
    try:
        return candidate is not None and norm_addr(candidate) == norm_addr(want)
    except Exception:
        return False


async def main() -> int:
    if not Path(TOSCTL).exists():
        print(f"FATAL: tosctl binary not found at {TOSCTL} "
              f"(build with: cargo build --manifest-path tosctl/src/Cargo.toml -p tosctl)",
              file=sys.stderr)
        return 2

    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    prepare_config()
    install = Install(BUILD_DIR, REPO)
    import logging
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    async with Network(install, WORKDIR / "net", base_port=23200) as network:
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

    return 1 if failures else 0


if __name__ == "__main__":
    rc = asyncio.run(main())
    if rc == 1:
        print(f"\n=== RESULT: {len(failures)} FAILURES ===")
        for f in failures:
            print(f"  - {f}")
    elif rc == 0:
        print("\n=== RESULT: ALL PASS ===")
    sys.exit(rc)
