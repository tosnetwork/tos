"""Shared setup/steady-state controller funding for the disposable PQ network."""

import asyncio
import base64
import json
import subprocess
import time
from pathlib import Path

import local_pq_testnet as local
from local_pq_funding_policy import NANO, coins, funding_plan
from local_pq_transactions import atomic_json, cursor, raw, require_success
from pytosiq_core import Address, Builder, Cell, StateInit
from pytosiq_core.tlb.config import ConfigParam20, ConfigParam24

CANDIDATES = (1, 2, 3, 4, 7)
AUTHORIZATION_WINDOW = 600


def operating_payload(payer, deposit, allowance, limit, floor, expires):
    if type(expires) is not int or not 0 < expires < 1 << 32:
        raise ValueError("sponsorship expiry must fit uint32")
    if not isinstance(payer, Address) or payer.wc != -1:
        raise ValueError("local operating payer must be a masterchain address")
    return (
        Builder()
        .store_address(payer)
        .store_coins(coins(deposit, "deposit", zero=True))
        .store_coins(coins(allowance, "allowance"))
        .store_coins(coins(limit, "per-request limit"))
        .store_coins(coins(floor, "storage floor"))
        .store_uint(expires, 32)
        .end_cell()
    )


def fee_budget(gas_cell, forward_cell):
    """Match GETGASFEE/GETFORWARDFEE and stake-relay.fc using live MC prices."""
    gas_slice, forward_slice = gas_cell.begin_parse(), forward_cell.begin_parse()
    gas = ConfigParam20.deserialize(gas_slice)
    forward = ConfigParam24.deserialize(forward_slice)
    if (
        gas_slice.remaining_bits
        or gas_slice.remaining_refs
        or forward_slice.remaining_bits
        or forward_slice.remaining_refs
    ):
        raise ValueError("trailing live fee configuration data")
    flat_limit = flat_price = 0
    if gas.type_ == "gas_flat_pfx":
        flat_limit, flat_price = gas.flat_gas_limit, gas.flat_gas_price
        gas = gas.other
    if gas.type_ not in ("gas_prices", "gas_prices_ext") or gas.gas_limit < 200000:
        raise ValueError("unsupported local gas configuration")

    def price(units):
        return flat_price + ((max(0, units - flat_limit) * gas.gas_price + 65535) >> 16)

    control_forward = forward.lump_price + (
        (4096 * forward.bit_price + 8 * forward.cell_price + 65535) >> 16
    )
    control = price(50000) + control_forward
    callback = price(200000) + control_forward
    grant = coins(4 * control + callback, "automatic grant")
    processing = coins(price(200000) + control, "funding processing fee")
    return dict(
        grant=grant,
        processing=processing,
        config20=gas_cell.hash.hex(),
        config24=forward_cell.hash.hex(),
    )


def read_controller(account, address, init):
    """Read the complete authority/operating tuple from one checked state BOC."""
    if (
        address.wc != -1
        or init.serialize().hash != address.hash_part
        or not account.code
        or Cell.one_from_boc(account.code).hash != init.code.hash
    ):
        raise ValueError("controller code or birth identity differs")
    data = Cell.one_from_boc(account.data).begin_parse()
    epoch, nonce = data.load_uint(64), data.load_uint(64)
    algorithm, key, root = data.load_uint(16), data.load_bytes(32), data.load_ref()
    birth = init.data.begin_parse()
    birth.load_uint(64)
    birth.load_uint(64)
    if (
        algorithm != birth.load_uint(16)
        or key != birth.load_bytes(32)
        or root.hash != birth.load_ref().hash
    ):
        raise ValueError("controller authority is not the disposable birth fixture")
    relay = data.load_maybe_ref() if data.remaining_bits else None
    operating = data.load_maybe_ref() if data.remaining_bits else None
    retry_fees = data.load_maybe_ref() if data.remaining_bits else None
    if data.remaining_bits or data.remaining_refs:
        raise ValueError("trailing controller state")
    pending = False
    sequence = 1 << 63
    if relay is not None:
        value = relay.begin_parse()
        sequence, request = value.load_uint(64), value.load_maybe_ref()
        pending = request is not None
        if value.remaining_bits or value.remaining_refs:
            raise ValueError("trailing controller relay state")
    state = dict(funds=0, allowance=0, limit=0, floor=0, expires=0, payer=raw(address))
    if operating is not None:
        value = operating.begin_parse()
        for name in ("funds", "allowance", "limit", "floor"):
            state[name] = value.load_coins()
        state["expires"] = value.load_uint(32)
        payer = value.load_address()
        if not isinstance(payer, Address) or value.remaining_bits or value.remaining_refs:
            raise ValueError("invalid controller operating payer/state")
        state["payer"] = raw(payer)
    return dict(
        epoch=epoch,
        nonce=nonce,
        operations=state,
        sequence=sequence,
        pending=pending or retry_fees is not None,
        balance=int(account.balance),
        now=account.sync_utime,
    )


def sign(
    seed,
    global_id,
    controller,
    epoch,
    nonce,
    payload,
    valid_until,
    tool=Path("/usr/local/bin/tos-pq-controller"),
):
    tool = local.require_installed_executable(tool)
    proc = subprocess.run(
        [
            str(tool),
            "fund-operations",
            str(seed),
            str(global_id),
            controller.hash_part.hex(),
            str(epoch),
            str(nonce),
            str(valid_until),
            base64.b64encode(payload.to_boc()).decode(),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode:
        raise RuntimeError(f"controller signer refused: {proc.stderr.strip()[-500:]}")
    return Cell.one_from_boc(base64.b64decode(proc.stdout.strip(), validate=True))


async def verify_local_network(client, network, plan):
    if (
        network.get("scope") != "local-development"
        or network.get("mode") != "pq"
        or network.get("global_id") != 3
        or network.get("election_period_seconds") != 600
        or plan.get("scope") != "local-development-only"
        or plan.get("rosters") != [[1, 2, 3, 7], [1, 2, 3, 4]]
    ):
        raise ValueError("automatic root signing requires the explicit disposable --rotate profile")
    info = await client.get_masterchain_info()
    if info.init is None or info.init.root_hash.hex() != network["zerostate_root"]:
        raise ValueError("connected chain is not the provisioned local zero-state")
    config15 = (await client.get_config_param(15)).begin_parse()
    if (
        [config15.load_uint(32) for _ in range(4)] != [600, 300, 60, 180]
        or config15.remaining_bits
        or config15.remaining_refs
    ):
        raise ValueError("connected election schedule differs from the local profile")


async def confirmed_state(client, controller, receipt):
    """Wait for the account view to reach the independently confirmed transaction."""
    deadline = time.monotonic() + 30
    while True:
        account = await client.raw_get_account_state(controller)
        current = cursor(account.last_transaction_id)
        confirmed = receipt["transaction"]
        if current["lt"] == confirmed["lt"] and current["hash"] != confirmed["hash"]:
            raise ValueError("confirmed controller transaction hash differs at the same LT")
        if account.last_transaction_id is not None and current["lt"] >= confirmed["lt"]:
            return account
        if time.monotonic() >= deadline:
            raise TimeoutError("confirmed controller state is not yet available")
        await asyncio.sleep(0.5)


async def ensure_operations(
    client,
    faucet,
    candidate,
    index,
    directory,
    global_id,
    *,
    check=False,
    emit=None,
    days=30,
    target=None,
    signer=sign,
    signer_tool=Path("/usr/local/bin/tos-pq-controller"),
):
    """Deploy, replenish by deficit, confirm the exact transition, check capital.

    Caller owns the faucet lock. A pending relay is never overwritten by this
    helper; wait for its completion and alert rather than masking an old failure.
    """
    directory = Path(directory)
    controller = Address(candidate["controller"])
    init = StateInit.deserialize(
        Cell.one_from_boc(
            base64.b64decode(candidate["state_init_b64"], validate=True)
        ).begin_parse()
    )
    account = await client.raw_get_account_state(controller)
    if not account.code:
        if check:
            return dict(node=index, ready=False, reason="controller not deployed")
        receipt = await faucet.transfer(
            f"controller-deploy-{index}", controller, 10 * NANO, init=init
        )
        require_success(receipt)
        account = await confirmed_state(client, controller, receipt)
    observed = read_controller(account, controller, init)
    if observed["pending"] and not check:
        deadline = time.monotonic() + 30
        while observed["pending"]:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"controller {index} still has an unfinished relay")
            await asyncio.sleep(0.5)
            account = await client.raw_get_account_state(controller)
            observed = read_controller(account, controller, init)
    # A stale lite-server view must never be used to sign a ten-minute authorization.
    now = observed["now"]
    if abs(time.time() - now) > 120:
        raise ValueError("controller view is stale or host clock differs from chain time")
    budget = fee_budget(await client.get_config_param(20), await client.get_config_param(24))
    state = observed["operations"]
    proposal = funding_plan(
        state,
        now=now,
        grant=budget["grant"],
        payer=raw(faucet.wallet.address),
        days=days,
        target=target,
    )
    if proposal is not None and emit:
        emit(
            "operations_renewal_due",
            node=index,
            funds=state["funds"],
            allowance=state["allowance"],
            expires=state["expires"],
            grant=budget["grant"],
        )
    if proposal is not None and not check:
        if observed["pending"]:
            raise ValueError(f"controller {index} has an unfinished relay; funding deferred")
        epoch, nonce = observed["epoch"], observed["nonce"]
        if nonce == (1 << 64) - 1:
            raise ValueError("controller root nonce exhausted")
        payload = operating_payload(
            faucet.wallet.address,
            proposal["deposit"],
            proposal["allowance"],
            proposal["limit"],
            proposal["floor"],
            proposal["expires"],
        )
        body = await asyncio.to_thread(
            signer,
            directory / f"keys/root-{index}.seed",
            global_id,
            controller,
            epoch,
            nonce,
            payload,
            now + AUTHORIZATION_WINDOW,
            signer_tool,
        )
        receipt = await faucet.transfer(
            f"operations-{index}-{epoch}-{nonce}",
            controller,
            proposal["deposit"] + budget["processing"] + NANO,
            body,
            bounce=True,
        )
        require_success(receipt)
        account = await confirmed_state(client, controller, receipt)
        observed = read_controller(account, controller, init)
        expected = {k: v for k, v in proposal.items() if k != "deposit"}
        if (
            observed["epoch"] != epoch
            or observed["nonce"] != nonce + 1
            or observed["operations"] != expected
        ):
            raise ValueError(
                f"controller {index} authorization readback differs from exact transition"
            )
        state = observed["operations"]
        if emit:
            emit("operations_funded", node=index, deposit=proposal["deposit"], **state)
    required = state["funds"] + state["floor"]
    if observed["balance"] < required + 20 * NANO and not check:
        # Credit is confirmed at the destination; an uncertain old payment is
        # recovered before any newly calculated deficit is sent.
        amount = required + 20 * NANO - observed["balance"]
        receipt = await faucet.transfer(
            f"capital-{index}-{account.last_transaction_id.lt}", controller, amount
        )
        require_success(receipt)
        account = await confirmed_state(client, controller, receipt)
        observed = read_controller(account, controller, init)
    ready = (
        not observed["pending"]
        and observed["balance"] >= required
        and min(state["funds"], state["allowance"], state["limit"]) >= budget["grant"]
        and state["expires"] > now + 2 * 600
        and state["payer"] == raw(faucet.wallet.address)
    )
    result = dict(
        node=index,
        controller=raw(controller),
        ready=ready,
        renewal_due=check and proposal is not None,
        operating_state=state,
        balance=observed["balance"],
        automatic_value=budget["grant"],
        runway_seconds=min(state["funds"], state["allowance"]) // budget["grant"] * 600,
        covers_funds_plus_floor=observed["balance"] >= required,
        checked_at=int(time.time()),
    )
    if not check:
        atomic_json(directory / f"operations-{index}.json", result)
        if not ready:
            raise ValueError(f"controller {index} not ready for a relay: {json.dumps(result)}")
    return result
