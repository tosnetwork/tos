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
from contract import WalletV1, tos
from pytosiq_core import (
    Address,
    Cell,
    InternalMsgInfo,
    MessageAny,
    StateInit,
    WalletMessage,
)
from tosapi import tos_api
from tostester.pq_election_fixture import build_pool_stake_order, elector_reply, make_pool_fixture
from x02_config34_proof import decode_validator_set

from toslib import EngineConsoleClient, ToslibCDLL, ToslibClient, ToslibEventLoop

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
    local.write_json(OUT / name, obj)


def event(kind, **fields):
    row = {"at": time.time(), "kind": kind, **fields}
    local.append_text(OUT / "events.jsonl", json.dumps(row) + "\n")
    print(json.dumps(row), flush=True)


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
        "/usr/local/bin/tos-lite-client",
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


async def send(wallet, dest, amount, body=None, init=None):
    seq = (await wallet.current).seqno
    message = WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True,
                bounce=False,
                bounced=False,
                src=wallet.address,
                dest=dest,
                value=tos(amount),
                ihr_fee=0,
                fwd_fee=0,
                created_lt=0,
                created_at=0,
            ),
            init=init,
            body=body if body is not None else Cell.empty(),
        ),
    )
    await wallet.send(message, seqno=seq)

    async def included():
        return (await wallet.current).seqno >= seq + 1

    await wait(included)


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


async def main():
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
                        await send(wallet, addr, 10, init=state)

                    async def deployed(addr=addr, code=code):
                        raw = await client.raw_get_account_state(addr)
                        return bool(raw.code) and Cell.one_from_boc(raw.code).hash == code.hash

                    await wait(deployed)
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
                            for i in selected:
                                c = candidates[i]
                                pool = pools[i]
                                query = await lite_int(
                                    "next_relay_query", address=Address(c["controller"])
                                )
                                if not (1 << 63) < query < (1 << 64):
                                    raise ValueError("controller returned an invalid relay query")
                                # Local test capital; no external funds or production keys.
                                await send(wallet, pool.address, 11020)
                                request = (
                                    tos_api.Engine_validator_createPqStakeAuthorizationRequest(
                                        election_date=election,
                                        max_factor=1 << 16,
                                        adnl_addr=bytes.fromhex(c["adnl_id"]),
                                        stake_owner=pool.address.hash_part,
                                    )
                                )
                                response, req_bytes, raw = await consoles[i].request_with_raw(
                                    request
                                )
                                auth = request.parse_result(response)
                                if (
                                    auth.validator_id.hex()
                                    != Address(c["controller"]).hash_part.hex()
                                    or auth.key_id.hex() != c["key_id"]
                                    or auth.public_key.hex() != c["public_key"]
                                    or auth.algorithm_id != 1
                                ):
                                    raise ValueError(
                                        "node stake authorization differs from candidate"
                                    )
                                (OUT / f"authorization-{election}-{i}.json").write_bytes(raw)
                                body = build_pool_stake_order(
                                    query_id=query,
                                    stake_amount=11000 * NANO,
                                    stake_at=election,
                                    max_factor=1 << 16,
                                    adnl_addr=bytes.fromhex(c["adnl_id"]),
                                    algorithm_id=1,
                                    public_key=auth.public_key,
                                    signature=auth.signature,
                                    witness=Cell.one_from_boc(base64.b64decode(c["witness_b64"])),
                                )
                                await send(wallet, pool.address, 20, body)

                                async def accepted():
                                    account = await client.raw_get_account_state(pool.address)
                                    transactions = await client.raw_get_transactions(
                                        pool.address, account.last_transaction_id
                                    )
                                    answer = elector_reply(
                                        transactions.transactions,
                                        query,
                                        controller=Address(c["controller"]),
                                    )
                                    # Reason 0 means the election is already finished (or none
                                    # is active): a stake sent at the window's close, or after a
                                    # restart that re-read a closing election. That is not a
                                    # fault to die on; the election is recorded as skipped and
                                    # the loop waits for the next one.
                                    if answer and answer[0] == 0xEE6F454C and answer[1] == 0:
                                        return answer
                                    if answer and answer[0] != 0xF374484C:
                                        raise ValueError(f"Elector refused node {i}: {answer}")
                                    return answer

                                answer = await wait(accepted, 60)
                                if answer and answer[0] == 0xEE6F454C:
                                    event(
                                        "election_closed_skipped",
                                        election=election,
                                        node=i,
                                        query=query,
                                        reply=answer,
                                    )
                                    selected = []
                                    break
                                event(
                                    "stake_accepted",
                                    election=election,
                                    node=i,
                                    query=query,
                                    reply=answer,
                                )
                            submitted[str(election)] = list(selected)
                            write("submitted.json", submitted)
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
