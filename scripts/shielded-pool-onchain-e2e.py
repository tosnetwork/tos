#!/usr/bin/env python3
"""Deploy the shielded pool on a real local chain and put a deposit through it.

Every number this project has ever quoted -- gas, roots, refusals, ceilings --
was measured in the sandbox executor.  That executor is the code a validator
runs, but running it is not running a chain: it has no block production, no
message queue, no forward fees and no account storage.  So the claim "the pool
works" has never been tested against the thing it will actually live in.

This harness closes that.  It owns a fresh localnet, deploys the exact state
the frozen manifest names, sends one real deposit from a real wallet, and
requires the chain to arrive at the commitment root the circuit predicted
*before* the message was sent.

By default the localnet has one validator, which is enough for everything the
pool itself does: a contract cannot tell how many nodes agreed on the block it
ran in.  `--validators N` builds a set of N instead, and is worth running
before anything is frozen -- with one node there is no catchain round, no
block a validator has to accept from someone else, and so no way to find out
that the pool's transactions are fine in an executor and not in a block that
has to be agreed.  A transact is by far the heaviest transaction this chain
has, and whether a validator set collects one is a different question from
whether an executor runs one.

Nothing here re-implements the pool.  The code, the state, the deposit body and
the expected root all come out of `onchain_fixture`, which builds them from the
same sources the suites compile.  This script only carries bytes to a node and
reads answers back.

Run from the repository:

    uv run python scripts/shielded-pool-onchain-e2e.py

It needs a build with the node binaries (`ninja validator-engine dht-server
lite-client`) and the Rust fixture generator; pass --build-dir for a build tree
elsewhere, and --fixture to reuse one that has already been generated.

From a git worktree it also needs `tosapi`, which is generated rather than
committed and so exists only where it has been generated:

    uv run python test/tostester/generate_tl.py

Without it the run dies at import with `ModuleNotFoundError: No module named
'tosapi'`, which reads like a broken harness and is a missing generated
module. The schemas it is built from are committed, so that one command is all
it takes.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))

from contract import WalletV1, tos  # noqa: E402
from pytosiq_core import (  # noqa: E402
    Address,
    Cell,
    InternalMsgInfo,
    MessageAny,
    StateInit,
    WalletMessage,
)
from tostester.install import Install  # noqa: E402
from tostester.network import FullNode, Network, StartOptions  # noqa: E402

TOS = 1_000_000_000

# Global version 18 is where POSEIDON2_PATH7 lives, and 17 is where the
# permutation and the seven-input hash do.  A chain below 18 cannot run this
# contract at all: the instructions are not merely absent, they are refused.
GLOBAL_VERSION = 18

# Nothing on top of what section 14.1's funding rule demands.
#
# This was 50,000,000, added on the theory that a real internal message pays a
# forward fee out of its own value and so arrives worth less than it was sent
# for.  It does not, here: the wallet sends with mode 3, which pays transfer
# fees separately from the message value, so the whole value arrives and the
# contract's `msg_value >= get_compute_fee(ceiling)` sees exactly what was
# attached.  Measured with the allowance at zero, all four paths still pass.
#
# So it goes to zero, and not merely because it was unnecessary: a run that
# attaches more than the rule demands is not testing the rule.  Sending the
# exact minimum is what shows that the minimum really is sufficient on a chain
# -- forward fees, storage, action phase and all -- which is the one thing a
# sandbox measurement of it cannot show.
#
# The flag remains for anyone who needs slack while chasing something else.
FORWARD_FEE_ALLOWANCE = 0


class Failed(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[onchain] {message}", flush=True)


# ---------------------------------------------------------------------------
# The fixture: the bytes a node needs, built by the crosscheck crate.


def build_fixture(out: Path, build: Path, refuse: bool, transfer: bool) -> Path:
    log("building the deployment fixture from the crosscheck crate ...")
    crate = REPO / "tools/shielded-pool-circuit/crosscheck"
    cargo = Path.home() / ".cargo/bin/cargo"
    environment = dict(os.environ)
    # `TOS_ROOT` is where the FunC compiler and the Fift assembler are looked
    # for -- `build/crypto/func` under it -- not where the sources are. Those
    # come from the crate itself. Pointing it at this checkout when the build
    # lives elsewhere finds some other tree's toolchain, and an older Fift
    # answers `POSEIDON2_HASH7:-?` instead of assembling it.
    environment["TOS_ROOT"] = str(build.parent)
    environment["CARGO_TERM_COLOR"] = "never"
    command = [str(cargo), "run", "--release", "--bin", "onchain_fixture", "--",
               str(REPO), str(out)]
    if refuse:
        command.append("--refuse")
    if transfer:
        command.append("--transfer")
    result = subprocess.run(
        command,
        cwd=crate,
        env=environment,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise Failed(f"onchain_fixture failed:\n{result.stdout}\n{result.stderr}")
    return out


def load_fixture(directory: Path) -> dict:
    fixture = json.loads((directory / "fixture.json").read_text())
    names = ["code.boc", "data.boc", fixture["destination"]["code"]]
    names += [step["body"] for step in fixture["steps"] if step["body"] is not None]
    for name in names:
        path = directory / name
        if not path.exists():
            raise Failed(f"the fixture has no {name}")
    return fixture


def cell_from(path: Path) -> Cell:
    return Cell.one_from_boc(path.read_bytes())


# ---------------------------------------------------------------------------
# The chain: get-methods through the lite client, because that is the interface
# a wallet or an explorer would use.


class LiteClient:
    def __init__(self, binary: Path, config: Path) -> None:
        self.binary = binary
        self.config = config

    def run(self, command: str, timeout: float = 30.0) -> str:
        result = subprocess.run(
            [str(self.binary), "-C", str(self.config), "-v", "0", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise Failed(f"lite-client {command!r} exited {result.returncode}:\n{result.stderr}")
        return result.stdout

    def get_method(self, address: str, method: str) -> str:
        """One field element off the top of a get-method's stack, as decimal."""
        output = self.run(f"runmethod {address} {method}")
        match = re.search(r"result:\s*\[\s*([0-9-]+)\s*\]", output)
        if not match:
            raise Failed(f"{method} returned nothing the harness could read:\n{output}")
        return match.group(1)

    def account(self, address: str) -> str:
        return self.run(f"getaccount {address}")

    def transaction_gas(self, address: str, lt: str, transaction_hash: str) -> int | None:
        """The gas the chain charged, out of the dumped transaction.

        The JSON-RPC reports a fee and the number of VM steps but not the gas,
        and the gas is the number every ceiling in section 14 is expressed in.
        """
        output = self.run(f"lasttransdump {address} {lt} {transaction_hash} 1")
        match = re.search(r"gas_used:\(var_uint\s+len:\d+\s+value:(\d+)\)", output)
        if not match:
            match = re.search(r"gas_used[^0-9]{0,40}(\d+)", output)
        return int(match.group(1)) if match else None

    def balance(self, address: str) -> int:
        """What an account holds, off its state rather than the JSON-RPC.

        The lite protocol answers this reliably on a node that has just
        sealed a block, where `getAddressBalance` has been seen to hang.
        """
        output = self.account(address)
        match = re.search(
            r"balance:\(currencies\s+\w+:\(\w+\s+amount:\(var_uint\s+len:\d+\s+value:(\d+)\)",
            output,
        )
        if not match:
            raise Failed(f"the account state carries no balance the harness could read:\n{output}")
        return int(match.group(1))

    def account_exists(self, address: str) -> bool:
        output = self.account(address)
        self.last_account = output
        return "account_none" not in output and "account_active" in output


def rpc(endpoint: str, method: str, **params):
    """The other read path. The lite client speaks the lite protocol; this is
    the HTTP interface a wallet or an explorer would use, and the two agreeing
    is worth more than either alone."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    # Retried, because a node that has just sealed a block can take longer
    # than one timeout to answer and a slow read is not a failed run.
    last = None
    for attempt in range(4):
        request = urllib.request.Request(
            f"http://{endpoint}/jsonRPC", data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.loads(response.read().decode())
        except Exception as error:
            last = error
            time.sleep(1.0 + attempt)
    raise Failed(f"the JSON-RPC did not answer {method}: {last}")


def describe_transaction(rpc_address: str, account: str, bounced: bool = False) -> dict | None:
    """The chain's most recent transaction of the kind asked for.

    Not simply the last one: a refused payout bounces back, so by the time the
    withdrawal's own cost is read the account's latest transaction is the
    recovery. Picking by kind is what keeps a step's cost the step's.
    """
    answer = rpc(rpc_address, "getTransactions", address=account, limit=5)
    for transaction in answer.get("result", []):
        if bool(transaction.get("in_msg", {}).get("bounced")) == bounced:
            return transaction
    return None


# ---------------------------------------------------------------------------


def internal(source: Address, destination: Address, value: int, body: Cell,
             init: StateInit | None, bounce: bool) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True,
                bounce=bounce,
                bounced=False,
                src=source,
                dest=destination,
                value=tos(value / TOS),
                ihr_fee=0,
                fwd_fee=0,
                created_lt=0,
                created_at=0,
            ),
            init=init,
            body=body,
        ),
    )


async def wait_for(what: str, predicate, timeout: float, interval: float = 1.0):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception as error:  # a chain that is not ready answers by failing
            last = error
        await asyncio.sleep(interval)
    raise Failed(f"timed out waiting for {what}" + (f": {last}" if last else ""))


def compare(name: str, expected: str, produced: str, failures: list[str]) -> None:
    verdict = "ok" if expected == produced else "DISAGREES"
    log(f"  {name:<26} {produced:<78} {verdict}")
    if expected != produced:
        failures.append(f"{name}: the chain says {produced}, the circuit predicted {expected}")


def check_recovery(lite, rpc_address, account, fixture, fixture_dir, step, build, failures) -> None:
    """The recovery note, checked against what the chain decided to recover.

    Section 15.4 mints the note for whatever the bounce actually delivered,
    and that depends on forward fees no prover can know in advance.  So this
    reads the bounced value off the chain and asks the circuit's own tree what
    root it implies -- the prediction still comes from the circuit, not from
    the pool's report of what it did.

    The predictor is not taken on trust either: `onchain_fixture` runs the
    same scenario in the sandbox, where a real bounce happens, and refuses to
    write the fixture unless the predictor agrees with the pool there.
    """
    bounce = describe_transaction(rpc_address, account, bounced=True)
    if bounce is None:
        failures.append(
            f"{step['name']}: no bounced message reached the pool, so nothing was recovered"
        )
        return None

    recovered = int(bounce["in_msg"]["value"])
    log(f"  {'recovered by the chain':<34} {recovered}")
    sandbox = fixture.get("recovery_sandbox") or {}
    if sandbox:
        log(f"  {'recovered in the sandbox':<34} {sandbox.get('recovered_nanotos')}")

    # What that amount implies, computed by the circuit rather than read back.
    result = subprocess.run(
        [str(Path.home() / ".cargo/bin/cargo"), "run", "--release", "--bin", "onchain_fixture",
         "--", "--recovery-root", str(fixture_dir), str(recovered)],
        cwd=REPO / "tools/shielded-pool-circuit/crosscheck",
        env={**os.environ, "TOS_ROOT": str(build.parent), "CARGO_TERM_COLOR": "never"},
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        failures.append(f"{step['name']}: the recovery predictor failed:\n{result.stderr}")
        return
    predicted = json.loads(result.stdout.strip().splitlines()[-1])

    compare("commitment_root", predicted["commitment_root"],
            lite.get_method(account, "commitment_root"), failures)
    log(f"  {'the recovery note landed at':<34} {predicted['leaf_index']}")

    # And the pool owes the recovered money again: section 15.4's whole point
    # is that a refused payout does not leave the value unaccounted for.
    #
    # What it owes is what the note is worth, which is what the bounce
    # delivered less the pool's charge for putting it back -- not the
    # delivered value. That figure comes from the predictor rather than being
    # recomputed here, because this was the third place the subtraction had to
    # happen and the first two had already been missed.
    before = int(step["expect"]["liability_before_recovery"])
    compare("native_liability", str(before + int(predicted["minted_nanotos"])),
            lite.get_method(account, "native_liability"), failures)
    return bounce


def anchor_epoch_seconds() -> int:
    """The anchor epoch's length, read from the contract rather than copied."""
    source = (REPO / "crypto/smartcont/shielded/anchors.fc").read_text()
    match = re.search(r'int anchor_epoch_seconds\(\) asm "(\d+) PUSHINT"', source)
    if not match:
        raise Failed("the anchor epoch length is not declared where it was")
    return int(match.group(1))


def report_cost(lite, rpc_address, account, step, workdir, failures,
                fixture_sandbox_bounce=None, transaction=None,
                previous_utime=None) -> int | None:
    """What the chain charged for the message just sent, against what the
    sandbox charged for the same bytes.

    Every gas figure this project quotes comes from the sandbox, on the
    understanding that it is the code a validator runs. This is the one place
    the understanding is checked rather than assumed.
    """
    # A step with no body is the bounce itself; every other step's own
    # transaction is the one that did not arrive bounced. The caller may
    # already hold it, and asking the node twice for the same thing is how
    # this ran into a JSON-RPC that stopped answering.
    if transaction is None:
        transaction = describe_transaction(rpc_address, account, bounced=step["body"] is None)
    if transaction is None:
        log("  the JSON-RPC returned no transaction for the pool account")
        return None
    name = (step["body"] or "bounce").replace(".boc", "")
    (workdir / f"{name}-transaction.json").write_text(json.dumps(transaction, indent=2))

    compute = transaction.get("compute", {})
    action = transaction.get("action", {})
    log(f"  {'fee charged':<34} {transaction.get('fee')}")
    log(f"  {'compute exit code':<34} {compute.get('exit_code')}")
    if transaction.get("aborted"):
        failures.append(f"{step['name']}: the transaction was aborted")
    if compute.get("exit_code") not in (0, None):
        failures.append(f"{step['name']}: the compute phase exited {compute.get('exit_code')}")
    if action and action.get("success") is False:
        failures.append(f"{step['name']}: the action phase failed, code {action.get('result_code')}")

    identifier = transaction.get("transaction_id", {})
    lt = identifier.get("lt")
    digest = identifier.get("hash")
    if not (lt and digest):
        return transaction.get("utime")
    gas = lite.transaction_gas(account, str(lt), base64.b64decode(digest).hex())
    if gas is None:
        log("  the transaction dump did not say how much gas was used")
        return transaction.get("utime")
    ceiling = int(step["gas_ceiling"])
    sandbox = step.get("sandbox_gas_used")
    if sandbox is None:
        # The bounce: the sandbox recorded its own, but it recovered its own
        # amount and so minted a different note. The two are printed side by
        # side and not required to match.
        recorded = (fixture_sandbox_bounce or {}).get("gas_used")
        log(f"  {'gas_used, on the chain':<34} {gas}")
        if recorded is not None:
            log(f"  {'gas_used, in the sandbox':<34} {recorded}")
        log(f"  {'the ceiling it ran under':<34} {ceiling}")
        if gas > ceiling:
            failures.append(
                f"{step['name']}: the chain charged {gas} gas under a ceiling of {ceiling}, "
                f"so SETGASLIMIT did not bind"
            )
        return
    sandbox = int(sandbox)
    log(f"  {'gas_used, on the chain':<34} {gas}")
    log(f"  {'gas_used, in the sandbox':<34} {sandbox}")
    log(f"  {'the ceiling it ran under':<34} {ceiling}")
    if gas > ceiling:
        failures.append(
            f"{step['name']}: the chain charged {gas} gas under a ceiling of {ceiling}, "
            f"so SETGASLIMIT did not bind"
        )
    if gas != sandbox:
        # One input the sandbox cannot match is the clock. An anchor epoch is
        # thirty seconds and the pool checkpoints the first time it sees a new
        # one, so two messages seconds apart can straddle a boundary on a
        # chain while the sandbox -- whose clock is frozen at the moment the
        # fixture was built -- never does. That is a difference in what the
        # two were asked to do, not in what they charge for doing it.
        epoch = anchor_epoch_seconds()
        utime = transaction.get("utime")
        opened = (
            previous_utime is not None
            and utime is not None
            and utime // epoch != previous_utime // epoch
        )
        # Bounded, so that the tolerance cannot swallow a real divergence that
        # happens to land on a boundary: a checkpoint is one write into the
        # epoch ring, and a dictionary write measures about 5,200 gas.
        checkpoint_ceiling = 10_000
        if opened and 0 < gas - sandbox <= checkpoint_ceiling:
            log(f"  {'it opened a new anchor epoch':<34} "
                f"+{gas - sandbox} gas for the checkpoint the sandbox's frozen clock skipped")
        else:
            failures.append(
                f"{step['name']}: the chain charged {gas} gas and the sandbox charged {sandbox} "
                f"for the same message. Every gas figure in this project comes from the sandbox, "
                f"so the difference is the error bar on all of them."
            )
    return transaction.get("utime")

async def run(args) -> int:
    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="tos-shielded-"))
    build = Path(args.build_dir)
    fixture_dir = (
        Path(args.fixture)
        if args.fixture
        else build_fixture(workdir / "fixture", build, args.refuse, args.transfer)
    )
    fixture = load_fixture(fixture_dir)
    # Section 9's intent window is an hour, so a fixture is perishable: its
    # transact carries a `valid_until` the contract compares against the
    # chain's clock. Refused here rather than on the chain, where it would
    # look like a proof failure.
    remaining = int(fixture["valid_until"]) - int(time.time())
    if remaining < args.step_timeout + 60:
        raise Failed(
            f"this fixture's intent expires in {remaining}s, which is not enough to bring a "
            f"chain up and send three messages. Rebuild it: drop --fixture, or rerun "
            f"onchain_fixture."
        )
    log(f"the fixture's intent is good for another {remaining}s")
    address_text = fixture["address"]
    log(f"pool address {address_text}")
    log(f"state hash   {fixture['state_hash']}")

    install = Install(build, REPO)
    lite_binary = build / "lite-client/lite-client"
    if not lite_binary.exists():
        raise Failed(f"{lite_binary} is missing; run ninja lite-client")

    chain_dir = workdir / "chain"
    shutil.rmtree(chain_dir, ignore_errors=True)
    chain_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    failures: list[str] = []

    async with Network(install, chain_dir, base_port=args.base_port) as network:
        # Set before the first node starts: the zerostate is generated lazily,
        # and the global version is part of it.
        network.config.global_version = GLOBAL_VERSION
        # And the deployed chain's fee schedule, not the cheap test one.
        # Two things depend on it. Every gas ceiling in section 14 was derived
        # under ConfigParam 21 as `gen-zerostate.fif` writes it, so a fee
        # measured under the test schedule is a fee on a chain nobody runs;
        # and the test schedule grants a transaction 1,000,000 gas, which is
        # below the pool's own transact ceiling of 1,510,000 -- under it a
        # withdrawal is not slow, it is refused.
        network.config.deployment_fee_schedule = True
        # The chain's global id is eight of the eighteen public inputs, by way
        # of the execution domain. The fixture was proved for one value, so
        # the chain is built with that value; a proof made for another chain
        # is refused, and would look like a broken proof rather than a
        # mismatched chain.
        network.config.global_id = int(fixture["global_id"])
        log(f"localnet at global_version={network.config.global_version}, "
            f"global_id={network.config.global_id}, deployment fee schedule")

        dht = network.create_dht_node()
        # Node 0 is the one this script talks to; the rest exist to make the
        # blocks real. Every one of them is an initial validator, so a block
        # carrying a transact has to be produced and accepted by a set rather
        # than asserted by a single node.
        nodes: list[FullNode] = []
        for _ in range(args.validators):
            peer = network.create_full_node()
            peer.make_initial_validator()
            peer.announce_to(dht)
            nodes.append(peer)
        node = nodes[0]
        # No `chmod` pass over the keyrings here, although the multi-validator
        # integration test has one: `tostester.key` already writes every key
        # file 0600 and the keyring directory 0700. Copying that loop in would
        # have been a line that does nothing, which is the hardest kind to
        # ever delete again.

        lite_config = chain_dir / "lite-client.json"
        lite_config.write_text(node.liteserver_config.to_json())
        lite = LiteClient(lite_binary, lite_config)

        rpc_address = f"127.0.0.1:{args.base_port + 500}"
        tasks = [asyncio.create_task(dht.run())]
        tasks.append(
            asyncio.create_task(node.run(StartOptions(args=["--json-rpc-address", rpc_address])))
        )
        tasks.extend(asyncio.create_task(peer.run()) for peer in nodes[1:])
        try:
            if args.validators > 1:
                log(f"waiting for {args.validators} validators to agree on masterchain "
                    f"block #2 ...")
                # Block 2 rather than 1: the first block a set produces is the
                # first one that needed agreeing.
                await asyncio.wait_for(network.wait_mc_block(seqno=2), timeout=args.boot_timeout)
            else:
                log("waiting for masterchain block #1 ...")
                await asyncio.wait_for(network.wait_mc_block(seqno=1), timeout=args.boot_timeout)
            log("the chain is producing blocks")

            client = await node.toslib_client()
            faucet: WalletV1 = network.zerostate.main_wallet(client)
            destination = Address(address_text)

            # --- deploy ----------------------------------------------------
            code = cell_from(fixture_dir / "code.boc")
            data = cell_from(fixture_dir / "data.boc")
            init = StateInit(split_depth=None, special=None, code=code, data=data, library=None)
            deploy_value = int(fixture["deploy_value_nanotos"])
            log(f"deploying with {deploy_value/TOS:.9f} TOS ...")
            await faucet.send(
                internal(faucet.address, destination, deploy_value, Cell.empty(), init, bounce=False)
            )
            try:
                await wait_for(
                    "the pool account to become active",
                    lambda: lite.account_exists(address_text),
                    timeout=args.step_timeout,
                )
            except Failed:
                log("the deploy did not take. What the chain says about the account:")
                print(getattr(lite, "last_account", "(nothing was read)"))
                log("and about the faucet, to show the message left at all:")
                print(lite.account(faucet.address.to_str()))
                raise
            log("the pool is deployed and active on the chain")

            # The state a real node holds must be the state the manifest
            # freezes.  Reading the roots back is how that is checked without
            # trusting the deploy path.
            log("genesis, as the chain holds it:")
            expected = fixture["expected_at_genesis"]
            compare("commitment_root", expected["commitment_root"],
                    lite.get_method(address_text, "commitment_root"), failures)
            compare("nullifier_root", expected["nullifier_root"],
                    lite.get_method(address_text, "nullifier_root"), failures)
            compare("commitment_next_index", "0",
                    lite.get_method(address_text, "commitment_next_index"), failures)
            compare("native_liability", "0",
                    lite.get_method(address_text, "native_liability"), failures)

            # --- the scenario ----------------------------------------------
            #
            # Three messages: two deposits and one proved withdrawal. Each one
            # is compared against what the circuit said the chain would hold
            # afterwards, computed before any of them was sent.
            destination_address = Address(fixture["destination"]["address"])
            log(f"deploying the payout destination {fixture['destination']['address']} ...")
            await faucet.send(
                internal(
                    faucet.address,
                    destination_address,
                    int(fixture["destination"]["deploy_value_nanotos"]),
                    Cell.empty(),
                    StateInit(
                        split_depth=None,
                        special=None,
                        code=cell_from(fixture_dir / fixture["destination"]["code"]),
                        data=Cell.empty(),
                        library=None,
                    ),
                    bounce=False,
                )
            )
            await wait_for(
                "the destination account to become active",
                lambda: lite.account_exists(fixture["destination"]["address"]),
                timeout=args.step_timeout,
            )

            previous_utime = None
            for step in fixture["steps"]:
                expect = step["expect"]
                if step["body"] is None:
                    # A step the chain does by itself: the payout was refused,
                    # so it comes back and the pool mints a recovery note.
                    # Nothing is sent here, only waited for.
                    log(f"{step['name']}: waiting for the chain ...")
                else:
                    body = cell_from(fixture_dir / step["body"])
                    value = int(step["value_nanotos"]) + args.fee_allowance
                    log(f"{step['name']}: attaching {value/TOS:.9f} TOS ...")
                    await faucet.send(
                        internal(faucet.address, destination, value, body, None, bounce=True)
                    )
                # Whichever counter this step moves. A withdrawal whose payout
                # is refused moves the nullifier counter now and the
                # commitment counter again a block or two later, when the
                # bounce lands, so it is the nullifier counter that says this
                # step is done.
                counter = (
                    "commitment_next_index"
                    if "commitment_next_index" in expect
                    else "nullifier_next_index"
                )
                try:
                    await wait_for(
                        f"{step['name']} to be accepted",
                        lambda counter=counter, expect=expect: lite.get_method(
                            address_text, counter
                        ) == str(expect[counter]),
                        timeout=args.step_timeout,
                    )
                except Failed:
                    log(f"{step['name']} did not land. Dumping what the chain has:")
                    for who, account in (("pool", address_text),
                                         ("wallet", faucet.address.to_str())):
                        answer = rpc(rpc_address, "getTransactions", address=account, limit=3)
                        path = workdir / f"failure-{who}-transactions.json"
                        path.write_text(json.dumps(answer, indent=2))
                        log(f"  {path}")
                        for transaction in answer.get("result", []):
                            log(
                                f"  {who} lt={transaction.get('transaction_id', {}).get('lt')} "
                                f"fee={transaction.get('fee')} "
                                f"aborted={transaction.get('aborted')} "
                                f"compute={transaction.get('compute')} "
                                f"in_value={transaction.get('in_msg', {}).get('value')} "
                                f"out={len(transaction.get('out_msgs', []))}"
                            )
                    raise
                log(f"after {step['name']}:")
                for field in ("commitment_root", "commitment_next_index", "nullifier_root",
                              "nullifier_next_index", "native_liability"):
                    if field in expect:
                        compare(field, str(expect[field]),
                                lite.get_method(address_text, field), failures)
                bounce = None
                if step["body"] is None:
                    bounce = check_recovery(lite, rpc_address, address_text, fixture,
                                            fixture_dir, step, Path(args.build_dir), failures)
                previous_utime = report_cost(
                    lite, rpc_address, address_text, step, workdir, failures,
                    fixture.get("recovery_sandbox"), bounce, previous_utime,
                )

            # Where the money ended up. A withdrawal that moved every root
            # correctly and paid nobody would pass every check above, so the
            # destination's balance is read as well -- and when the
            # destination refuses, the same reading says the opposite: it must
            # *not* be holding the payout, because the payout came home.
            paid = int(fixture["destination"]["expects_nanotos"])
            deployed = int(fixture["destination"]["deploy_value_nanotos"])
            refuses = bool(fixture["destination"].get("refuses"))
            balance = lite.balance(fixture["destination"]["address"])
            log(f"the destination holds {balance/TOS:.9f} TOS")
            if refuses and balance >= deployed:
                failures.append(
                    f"the destination refused the payout and still holds {balance} nanotos, "
                    f"which is more than the {deployed} it was deployed with: the money did "
                    f"not come back"
                )
            if not refuses and paid > 0 and balance < paid:
                failures.append(
                    f"the destination holds {balance} nanotos, which is less than the "
                    f"{paid} the withdrawal was supposed to pay it"
                )
            # A transfer pays nobody, and "nobody was paid" is the claim that
            # has to be checked rather than assumed. Every root moving
            # correctly is exactly what a transfer and a withdrawal have in
            # common, so the roots cannot tell them apart; the destination's
            # balance can.
            #
            # Not `== deployed`. That was the first form of this check and it
            # failed on a run where nothing was wrong: an account pays for its
            # own deployment and its own storage, so it had 2,114 nanotos less
            # than it was given. Value arriving can only push the balance up,
            # so "no more than it started with" is the claim that distinguishes
            # a transfer, and it is the one that is true.
            if paid == 0 and balance > deployed:
                failures.append(
                    f"nothing was supposed to leave the pool, and the destination holds "
                    f"{balance} nanotos, more than the {deployed} it was deployed with: "
                    f"something paid it"
                )

            # And the claim itself, rather than a consequence of it.
            #
            # A balance can only say "that particular account did not visibly
            # gain". It cannot say nobody was paid: a small receipt hides under
            # the deployment and storage costs, and a payment to some other
            # address is not looked at by it at all. What a transfer must do is
            # send nothing, and what the pool sends is public -- an amount and
            # a destination, which is the pair this pool exists to hide. So the
            # outbound set is read off the chain and required to be empty.
            if paid == 0:
                final = describe_transaction(rpc_address, address_text)
                outbound = len((final or {}).get("out_msgs", []))
                log(f"  {'messages the pool sent':<34} {outbound}")
                if final is None:
                    failures.append(
                        "no transaction was found on the pool, so what it sent is unknown"
                    )
                elif outbound != 0:
                    failures.append(
                        f"a private transfer sent {outbound} message(s). A transfer pays "
                        f"nobody, and anything it sends is public."
                    )
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    if failures:
        log("FAILED")
        for failure in failures:
            log(f"  {failure}")
        return 1
    log("the chain agrees with the circuit at every point checked")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", default=os.environ.get("TOS_BUILD_DIR", str(REPO / "build")))
    parser.add_argument("--fixture", default=None,
                        help="a directory onchain_fixture has already written")
    parser.add_argument("--workdir", default=None)
    parser.add_argument("--base-port", type=int, default=21000)
    parser.add_argument(
        "--validators", type=int, default=1,
        help="how many initial validators the localnet has. One is enough to "
             "exercise the contract; more than one is what exercises the "
             "block a transact has to be agreed in.")
    parser.add_argument("--boot-timeout", type=float, default=180.0)
    parser.add_argument("--step-timeout", type=float, default=120.0)
    parser.add_argument(
        "--fee-allowance",
        type=int,
        default=FORWARD_FEE_ALLOWANCE,
        help="nanotos to attach on top of what section 14.1's funding rule demands. "
             "Zero by default, because a message carrying more than the rule asks for "
             "does not test the rule",
    )
    parser.add_argument(
        "--refuse",
        action="store_true",
        help="build a fixture whose payout destination refuses the money, so the "
             "withdrawal bounces and the pool has to mint a recovery note",
    )
    parser.add_argument(
        "--transfer",
        action="store_true",
        help="spend two notes into three, paying nobody. The only money path "
             "that had never run on a chain: the same handler takes a cheaper "
             "branch, and an argument that it must therefore work is not a run",
    )
    args = parser.parse_args()
    try:
        return asyncio.run(run(args))
    except Failed as error:
        log(f"FAILED: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
