#!/usr/bin/env python3
"""Run real development-only PQ elections on the persistent local network."""

import asyncio
import base64
import json
import re
import time
from pathlib import Path

import local_pq_testnet as local
import nacl.signing
from contract import WalletV1
from local_pq_election_evidence import election_result
from local_pq_funding import ensure_operations, verify_local_network
from local_pq_transactions import (
    Faucet,
    atomic_json,
    cursor,
    faucet_lock,
    history_since,
    read_json,
    require_success,
)
from pytosiq_core import (
    Address,
    Cell,
    StateInit,
)
from tosapi import tos_api
from toslib import EngineConsoleClient, ToslibCDLL, ToslibClient, ToslibEventLoop
from tostester.pq_election_fixture import build_pool_stake_order, make_pool_fixture
from x02_config34_proof import decode_validator_set

DATA = Path("/data")
OUT = DATA / "elections"
REPO = Path(__file__).resolve().parents[1]
NANO = 10**9
ELECTOR = Address((-1, bytes.fromhex("33" * 32)))


def roster(round_index):
    return (1, 2, 3, 7) if round_index % 2 == 0 else (1, 2, 3, 4)


def require_first_hops(sender, actual, current):
    if sender not in current:
        raise ValueError("sender is not a current validator")
    expected = set(current) - {sender}
    if set(actual) != expected:
        raise ValueError(f"first hops differ: actual={sorted(actual)}, expected={sorted(expected)}")


def write(name, obj):
    atomic_json(OUT / name, obj)


def event(kind, **fields):
    row = {"at": time.time(), "kind": kind, **fields}
    local.append_text(OUT / "events.jsonl", json.dumps(row) + "\n")
    print(json.dumps(row), flush=True)
    if kind == "failed":
        write("status.json", {**row, "healthy": False})


async def wait(predicate, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = await predicate()
        if value:
            return value
        await asyncio.sleep(0.5)
    raise TimeoutError("election transaction confirmation timed out")


async def lite_int(method, *args, address=ELECTOR):
    proc = await asyncio.create_subprocess_exec(
        str(local.INSTALLED_LITE_CLIENT),
        "-C",
        str(DATA / "configs/node-1-lite.json"),
        "-v",
        "0",
        "-c",
        f"runmethod {address.to_str(is_user_friendly=False)} {method} " + " ".join(args),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        output, _ = await asyncio.wait_for(proc.communicate(), 20)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    text = output.decode(errors="replace")
    match = re.search(r"result:\s*\[\s*(-?(?:0x[0-9a-fA-F]+|\d+))", text)
    if proc.returncode or not match:
        raise ValueError(f"Elector {method} did not answer: {text[-1000:]}")
    return int(match[1], 0)


def trace_once(offsets):
    import os

    captured = 0
    with os.fdopen(
        local.open_private(OUT / "relay-trace.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND), "a"
    ) as out:
        for node in (1, 2, 3, 4, 7):
            for path in (DATA / f"testnet/node{node}").glob("log*"):
                try:
                    f = path.open("rb")
                except FileNotFoundError:
                    # Rotation can unlink a name after directory enumeration.
                    continue
                with f:
                    stat = os.fstat(f.fileno())
                    inode = (node, stat.st_ino)
                    offset = offsets.get(inode, 0)
                    f.seek(offset if offset <= stat.st_size else 0)
                    while True:
                        position = f.tell()
                        raw = f.readline()
                        if not raw or not raw.endswith(b"\n"):
                            f.seek(position)
                            break
                        if b"twostep " in raw or b"two-step relays:" in raw:
                            out.write(
                                json.dumps(
                                    {"node": node, "line": raw.decode(errors="replace").strip()}
                                )
                                + "\n"
                            )
                            captured += 1
                    offsets[inode] = f.tell()
    write("trace-status.json", {"checked_at": time.time(), "rows_captured": captured})


async def trace_loop():
    offsets = {}
    while True:
        await asyncio.to_thread(trace_once, offsets)
        await asyncio.sleep(1)


async def snapshot(previous):
    infos = await asyncio.gather(
        *[asyncio.to_thread(local.rpc, 8010 + i, "getMasterchainInfo") for i in range(1, 8)]
    )
    height = min(r["last"]["seqno"] for r in infos)
    response = await asyncio.to_thread(local.rpc, 8011, "getConfigParam", param=34, seqno=height)
    cell = Cell.one_from_boc(base64.b64decode(response["config"]["bytes"]))
    decoded = decode_validator_set(cell)
    if decoded["utime_since"] != previous:
        replies = await asyncio.gather(
            *[
                asyncio.to_thread(local.rpc, 8010 + i, "getConfigParam", param=34, seqno=height)
                for i in range(1, 8)
            ]
        )
        if any(r["config"]["bytes"] != response["config"]["bytes"] for r in replies):
            raise ValueError("nodes disagree on elected Config34 bytes")
        write(
            f"activation-{decoded['utime_since']}.json",
            {
                "observed_at": time.time(),
                "height": height,
                "config34": decoded,
                "rpc_responses": replies,
            },
        )
        event(
            "elected_set_observed",
            since=decoded["utime_since"],
            until=decoded["utime_until"],
            controllers=[v["controller_id_hex"] for v in decoded["validators"]],
        )
    return decoded["utime_since"]


async def reconcile_candidate(client, sender, intent, candidate, pool):
    """Resolve one persisted order without inventing a second business request."""

    async def observed():
        return election_result(
            await history_since(client, pool.address, intent["pool_baseline"]),
            await history_since(
                client, Address(candidate["controller"]), intent["controller_baseline"]
            ),
            owner=sender.wallet.address,
            pool=pool.address,
            controller=Address(candidate["controller"]),
            query=intent["query"],
            body_hash=Cell.one_from_boc(base64.b64decode(intent["body"])).hash.hex(),
        )

    result = await wait(observed, 60)
    intent.update(state="done", result=result)
    write(f"candidate-intent-{intent['node']}.json", intent)
    return result


async def submit_candidate(client, sender, console, candidate, pool, election, index, network):
    name = f"candidate-intent-{index}.json"
    intent = read_json(OUT / name) if (OUT / name).exists() else None
    if intent:
        if (
            intent["network"] != network["zerostate_root"]
            or intent["node"] != index
            or intent["pool"] != pool.address.to_str(is_user_friendly=False)
            or intent["controller"] != candidate["controller"]
        ):
            raise ValueError("saved election intent belongs to a different chain/candidate")
        if intent["election"] != election:
            old_label = f"stake-{intent['election']}-{index}"
            if intent["state"] != "done" and sender.record(old_label):
                # A prior round may have changed while this process was down.
                # Finish observing its sent order before touching this controller.
                await reconcile_candidate(client, sender, intent, candidate, pool)
            write(f"intent-history-{intent['election']}-{index}.json", intent)
            intent = None  # An unsent expired intent is superseded, never broadcast.
        elif intent["state"] == "done":
            return intent["result"]
    if intent is None:
        await ensure_operations(
            client, sender, candidate, index, OUT, network["global_id"], emit=event
        )
        query = await lite_int("next_relay_query", address=Address(candidate["controller"]))
        if not (1 << 63) < query < (1 << 64):
            raise ValueError("controller returned an invalid relay query")
        request = tos_api.Engine_validator_createPqStakeAuthorizationRequest(
            election_date=election,
            max_factor=1 << 16,
            adnl_addr=bytes.fromhex(candidate["adnl_id"]),
            stake_owner=pool.address.hash_part,
        )
        response, _, authorization = await console.request_with_raw(request)
        auth = request.parse_result(response)
        if (
            auth.validator_id != Address(candidate["controller"]).hash_part
            or auth.key_id.hex() != candidate["key_id"]
            or auth.public_key.hex() != candidate["public_key"]
            or auth.algorithm_id != 1
        ):
            raise ValueError("node stake authorization differs from candidate")
        local.write_bytes(OUT / f"authorization-{election}-{index}.json", authorization, 0o600)
        body = build_pool_stake_order(
            query_id=query,
            stake_amount=11000 * NANO,
            stake_at=election,
            max_factor=1 << 16,
            adnl_addr=bytes.fromhex(candidate["adnl_id"]),
            algorithm_id=1,
            public_key=auth.public_key,
            signature=auth.signature,
            witness=Cell.one_from_boc(base64.b64decode(candidate["witness_b64"])),
        )
        pool_account = await client.raw_get_account_state(pool.address)
        controller_account = await client.raw_get_account_state(Address(candidate["controller"]))
        intent = dict(
            network=network["zerostate_root"],
            election=election,
            node=index,
            pool=pool.address.to_str(is_user_friendly=False),
            controller=candidate["controller"],
            query=query,
            body=base64.b64encode(body.to_boc()).decode(),
            pool_baseline=cursor(pool_account.last_transaction_id),
            controller_baseline=cursor(controller_account.last_transaction_id),
            capital=max(0, 11020 * NANO - int(pool_account.balance)),
            state="prepared",
        )
        write(name, intent)  # Before capital or order is broadcast.
    if intent["capital"]:
        require_success(
            await sender.transfer(
                f"pool-capital-{election}-{index}", pool.address, intent["capital"]
            )
        )
    body = Cell.one_from_boc(base64.b64decode(intent["body"], validate=True))
    receipt = await sender.transfer(f"stake-{election}-{index}", pool.address, 20 * NANO, body)
    if not receipt["ok"]:
        result = {k: receipt[k] for k in ("exit_code", "action_code")}
        result["kind"] = "pool_refused"
        intent.update(state="done", result=result)
        write(name, intent)
        return result
    return await reconcile_candidate(client, sender, intent, candidate, pool)


async def main():
    local.require_installed_executable(local.INSTALLED_LITE_CLIENT)
    with faucet_lock(DATA):
        await run_driver()


async def run_driver():
    # Runs from a snapshot with no build tree: the lite-client is the
    # installed one, checked before anything else is touched.
    local.require_installed_executable(local.INSTALLED_LITE_CLIENT)
    # Runs as root: refuse an output directory another user could redirect.
    local.secure_output_dir(OUT)
    plan = json.loads((OUT / "plan.json").read_text())
    if plan["elected_for"] != 600 or plan["rosters"] != [list(roster(0)), list(roster(1))]:
        raise ValueError("rotation plan differs")
    cdll = ToslibCDLL(REPO / "build/toslib/libtoslibjson.so")
    cdll.client_set_verbosity_level(0)
    config = tos_api.Liteclient_config_global.from_dict(
        json.loads((DATA / "configs/node-1-lite.json").read_text())
    )
    network = json.loads((DATA / "network.json").read_text())
    pool_code = Cell.one_from_boc(
        bytes.fromhex(
            (REPO / "crypto/smartcont/single-nominator-pool/single-nominator-code.hex")
            .read_text()
            .strip()
        )
    )
    candidates = {i: json.loads((OUT / f"candidate-{i}.json").read_text()) for i in (1, 2, 3, 4, 7)}
    tracer = asyncio.create_task(trace_loop())
    try:
        async with ToslibClient(config, cdll) as client:
            # The faucet is exclusively owned by this service after pool deployment.
            wallet = WalletV1(
                client,
                Address(network["genesis_wallet_address"]),
                nacl.signing.SigningKey((DATA / "testnet/state/main-wallet.pk").read_bytes()),
            )
            await verify_local_network(client, network, plan)
            sender = Faucet(client, wallet, OUT / "faucet-journal", network["zerostate_root"])
            await sender.recover()
            config15 = await client.get_config_param(15)
            fields = config15.begin_parse()
            values = [fields.load_uint(32) for _ in range(4)]
            if values != [600, 300, 60, 180]:
                raise ValueError(f"live election periods differ: {values}")
            write(
                "config15.json",
                {"values": values, "boc_b64": base64.b64encode(config15.to_boc()).decode()},
            )
            pools = {
                i: make_pool_fixture(pool_code, wallet.address, Address(c["controller"]))
                for i, c in candidates.items()
            }
            for i, c in candidates.items():
                init = StateInit.deserialize(
                    Cell.one_from_boc(base64.b64decode(c["state_init_b64"])).begin_parse()
                )
                for addr, state, code in (
                    (Address(c["controller"]), init, init.code),
                    (pools[i].address, pools[i].state_init, pool_code),
                ):
                    if not (await client.raw_get_account_state(addr)).code:
                        require_success(
                            await sender.transfer(
                                f"deploy-{addr.to_str(is_user_friendly=False)}",
                                addr,
                                10 * NANO,
                                init=state,
                            )
                        )

                    async def deployed(addr=addr, code=code):
                        raw = await client.raw_get_account_state(addr)
                        return bool(raw.code) and Cell.one_from_boc(raw.code).hash == code.hash

                    await wait(deployed)
                saved = OUT / f"candidate-intent-{i}.json"
                if not saved.exists() or read_json(saved)["state"] == "done":
                    await ensure_operations(
                        client, sender, c, i, OUT, network["global_id"], emit=event
                    )
                event(
                    "candidate_ready",
                    node=i,
                    controller=c["controller"],
                    pool=pools[i].address.to_str(is_user_friendly=False),
                )
            with ToslibEventLoop(cdll) as loop:
                consoles = {}
                try:
                    for i in candidates:
                        private = json.loads((OUT / f"console-{i}.private.json").read_text())
                        consoles[i] = EngineConsoleClient(
                            cdll, loop, tos_api.EngineConsoleClient_config.from_dict(private)
                        )
                    submitted = (
                        json.loads((OUT / "submitted.json").read_text())
                        if (OUT / "submitted.json").exists()
                        else {}
                    )
                    previous = None
                    while True:
                        if tracer.done():
                            await tracer
                            raise RuntimeError("relay trace task stopped")
                        previous = await snapshot(previous)
                        election = await lite_int("active_election_id")
                        if election and str(election) not in submitted:
                            round_index = len(submitted)
                            selected = roster(round_index)
                            event("election_submitting", election=election, roster=selected)
                            accepted_nodes = []
                            for i in selected:
                                write(
                                    "status.json",
                                    dict(
                                        at=time.time(),
                                        kind="submitting",
                                        healthy=True,
                                        election=election,
                                        node=i,
                                        activation_since=previous,
                                    ),
                                )
                                result = await submit_candidate(
                                    client,
                                    sender,
                                    consoles[i],
                                    candidates[i],
                                    pools[i],
                                    election,
                                    i,
                                    network,
                                )
                                if result["kind"] == "accepted":
                                    accepted_nodes.append(i)
                                    event(
                                        "stake_accepted",
                                        election=election,
                                        node=i,
                                        reply=result["reply"],
                                    )
                                elif result.get("reply") == [0xEE6F454C, 0]:
                                    event(
                                        "election_closed_skipped",
                                        election=election,
                                        node=i,
                                        result=result,
                                    )
                                    break
                                else:
                                    # The persisted refusal cannot be paid again after a restart.
                                    event("stake_refused", election=election, node=i, result=result)
                                    raise ValueError(f"node {i} stake refused: {result}")
                            selected = accepted_nodes
                            submitted[str(election)] = list(selected)
                            write("submitted.json", submitted)
                        write(
                            "status.json",
                            dict(
                                at=time.time(),
                                kind="running",
                                healthy=True,
                                election=election,
                                activation_since=previous,
                            ),
                        )
                        await asyncio.sleep(5)
                finally:
                    for console in consoles.values():
                        console.close()
    finally:
        tracer.cancel()
        await asyncio.gather(tracer, return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        event("failed", error=f"{type(exc).__name__}: {exc}")
        raise
