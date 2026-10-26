#!/usr/bin/env python3
"""Real-signature self-pay Quantum transaction tests and admission measurements.

Set FUNC_PATH, FIFT_PATH, EMULATOR_PATH, MLDSA_TOOL and SLH_TOOL. Test keys are
public deterministic fixtures. Raw traces and signer output stay in --output.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from functools import partial
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/mldsa-auth")]
import fee_tx_parity  # noqa: E402
import native  # noqa: E402
from cells import Cell, LibraryReference, from_boc, make_dict, read_dict  # noqa: E402
from protocol import chain  # noqa: E402
from test_auth_policy import policy  # noqa: E402

# The generic adapter refuses exotic fixtures by default. Explicitly admit
# level-zero library references only for these malformed-input controls.
from_boc = partial(from_boc, allow_library=True)

NETWORK = int.from_bytes(hashlib.sha256(b"PUBLIC TEST QSP NETWORK").digest(), "big")
TAGS = {0: 0x45584543, 1: 0x434F4E46, 3: 0x4C4F434B, 4: 0x4D494752}
MAX64 = (1 << 64) - 1
MAX32 = (1 << 32) - 1


def provenance(rust_driver=None):
    """Bind the complete FunC include closure, harness and used executables."""
    sources = {}

    def visit(path):
        path = path.resolve()
        name = str(path.relative_to(ROOT))
        if name in sources:
            return
        data = path.read_bytes()
        sources[name] = hashlib.sha256(data).hexdigest()
        if path.suffix == ".fc":
            for include in re.findall(r'#include\s+"([^"]+)"', data.decode()):
                visit(path.parent / include)

    for name in (
        "crypto/smartcont/stdlib.fc",
        "crypto/smartcont/wallet-quantum-self-pay.fc",
        "crypto/smartcont/wallet-quantum-possession-probe.fc",
        "test/wallet-quantum/test_self_pay.py",
        "test/wallet-quantum/test_self_pay_recovery.py",
        "test/wallet-quantum/test_auth_policy.py",
        "test/wallet-quantum/fee_tx_parity.py",
        "test/auth-extensions/native.py",
        "test/auth-extensions/cells.py",
        "test/mldsa-auth/protocol.py",
        "tosctl/src/executor/real_boc/default_config.boc",
    ):
        visit(ROOT / name)
    executables = {
        name: Path(os.environ[name]).resolve()
        for name in ("FUNC_PATH", "FIFT_PATH", "EMULATOR_PATH", "MLDSA_TOOL", "SLH_TOOL")
    }
    if rust_driver:
        executables["rust_driver"] = rust_driver.resolve()
    return dict(
        source_commit=run("git", "-C", ROOT, "rev-parse", "HEAD").strip(),
        source_status=run("git", "-C", ROOT, "status", "--porcelain").strip(),
        sources=sources,
        executables={
            name: dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            for name, path in executables.items()
        },
    )


def run(*args):
    return subprocess.check_output([str(a) for a in args], text=True)


def state(authority, seqno=0, retired=0, epoch=0, primary=0, rescue=0):
    return (
        Cell()
        .uint(1, 8)
        .uint(seqno, 32)
        .uint(0, 32)
        .uint(retired, 16)
        .uint(epoch, 64)
        .uint(primary, 64)
        .uint(rescue, 64)
        .ref(authority)
    )


def unpack(data):
    s = data.slice()
    assert s.uint(8) == 1
    result = dict(
        zip(
            ("seqno", "wallet_id", "retired", "epoch", "primary", "rescue"),
            (s.uint(32), s.uint(32), s.uint(16), s.uint(64), s.uint(64), s.uint(64)),
        )
    )
    result["authority"] = s.ref().hash.hex()
    s.end()
    return result


def uninitialized(address, balance):
    account = (
        Cell()
        .uint(1, 1)
        .addr(address)
        .varuint(0, 7)
        .varuint(0, 7)
        .uint(0, 3)
        .uint(native.NOW, 32)
        .uint(0, 1)
        .uint(0, 64)
        .coins(balance)
        .uint(0, 1)
        .uint(0, 2)
    )
    return Cell().uint(0, 256).uint(0, 64).ref(account)


def config(credit=20000, policy_cell=True):
    entries = read_dict(native.config(16), 32)
    if policy_cell is True:
        policy_cell = policy(network=NETWORK)
    if policy_cell is None:
        entries.pop(48, None)
    else:
        entries[48] = Cell().ref(policy_cell)
    prices = entries[21].refs[0]
    offset = 136 if int(prices.bits[:8], 2) == 0xD1 else 0
    assert int(prices.bits[offset : offset + 8], 2) == 0xDE
    offset += 8 + 64 * 3
    entries[21] = Cell().ref(
        Cell(prices.bits[:offset] + f"{credit:064b}" + prices.bits[offset + 64 :], prices.refs)
    )
    return make_dict(entries, 32)


def actions(address, count=1, mode=3, message=None):
    msg = native.internal(address, (0, 123), Cell(), value=1_000_000)
    if message is not None:
        msg = message
    result = Cell()
    for _ in range(count):
        result = Cell().uint(0x0EC3C86D, 32).uint(mode, 8).ref(result).ref(msg)
    return result


class Harness:
    def __init__(self, output, primary_seed="11", rescue_seed="22"):
        output = output.resolve()
        self.output = output
        output.mkdir(parents=True, exist_ok=True)
        self.code = native.compile_contract("wallet-quantum-self-pay.fc", output / "wallet.boc")
        self.pkfile, self.skfile = output / "ml.pk", output / "ml.sk"
        run(os.environ["MLDSA_TOOL"], "keygen", primary_seed * 32, self.pkfile, self.skfile)
        pk, self.slh_sk = run(os.environ["SLH_TOOL"], "keygen", rescue_seed * 48).split()
        self.slh_pk = bytes.fromhex(pk)
        self.authority = self.make_authority()
        self.data = state(self.authority)
        self.address = (0, int.from_bytes(native.state_init(self.code, self.data).hash, "big"))
        self.account = native.active_account(self.address, self.code, self.data)
        self.rows = []
        self.signatures = {}
        self.scenarios = []
        self.transcripts = []

    def make_authority(self, policy_value=1, network=NETWORK, primary=None, rescue=None):
        return (
            Cell()
            .uint(1, 8)
            .sint(native.GLOBAL_ID, 32)
            .uint(network, 256)
            .uint(1, 8)
            .ref(chain(self.pkfile.read_bytes()) if primary is None else primary)
            .raw(self.slh_pk if rescue is None else rescue)
            .uint(policy_value, 8)
        )

    def account_for(self, **kwargs):
        return native.active_account(self.address, self.code, state(self.authority, **kwargs))

    def message(
        self,
        role=1,
        kind=0,
        payload=None,
        nonce=0,
        epoch=0,
        network=NETWORK,
        global_id=native.GLOBAL_ID,
        destination=None,
        authority=None,
        deadline=native.NOW + 600,
        context=None,
        forged=False,
    ):
        if payload is None:
            payload = Cell().uint(TAGS[kind], 32)
            if kind == 0:
                payload.ref(Cell())
            elif kind == 1:
                payload.uint(2, 2)
            elif kind == 3:
                payload.uint(1, 8)
        request = (
            Cell()
            .uint(0x51535031, 32)
            .sint(global_id, 32)
            .uint(network, 256)
            .addr(destination or self.address)
            .raw((authority or self.authority).hash)
            .uint(role, 8)
            .uint(epoch, 64)
            .uint(nonce, 64)
            .uint(deadline, 32)
            .uint(kind, 8)
            .ref(payload)
        )
        if context is None:
            context = b"TOS-QSP-MLDSA44-v1" if role == 1 else b"TOS-QSP-SLH128S-v1"
        cache_key = (role, request.hash, context)
        if cache_key not in self.signatures:
            msg, sig = self.output / "digest.bin", self.output / "signature.bin"
            msg.write_bytes(request.hash)
            if role == 1:
                run(os.environ["MLDSA_TOOL"], "sign", self.skfile, context.hex(), msg, sig)
            else:
                run(os.environ["SLH_TOOL"], "sign", self.slh_sk, context.hex(), msg, sig)
            self.signatures[cache_key] = sig.read_bytes()
        signature = self.signatures[cache_key]
        if forged:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return native.external(self.address, Cell().ref(request).ref(chain(signature)))

    def transact(self, name, message, account=None, configuration=None, trace=False):
        configuration = config() if configuration is None else configuration
        account = self.account if account is None else account
        emu = native.Emulator.from_config(configuration, vm_log_verbosity=3 if trace else 0)
        try:
            with patch.object(native, "from_boc", from_boc):
                result = emu.send(account, message)
            lt = emu.lt
        finally:
            emu.close()
        if name:
            (self.output / (name + ".json")).write_text(json.dumps(result, indent=2) + "\n")
            if configuration.hash == config().hash and (
                result["success"] or result.get("external_not_accepted")
            ):
                self.scenarios.append(
                    "\t".join(
                        [
                            name,
                            str(native.NOW),
                            str(lt),
                            account.refs[0].boc().hex(),
                            message.boc().hex(),
                            "-",
                        ]
                    )
                )
                with patch.object(fee_tx_parity, "from_boc", from_boc):
                    self.transcripts.append(fee_tx_parity.transcript(name, result))
        return result

    def send(
        self,
        name,
        message,
        account=None,
        expected=0,
        accepted=True,
        configuration=None,
        trace=False,
    ):
        result = self.transact(name, message, account, configuration, trace)
        assert result["success"] == accepted, (
            name,
            {
                k: v
                for k, v in result.items()
                if k not in ("vm_log", "transaction", "shard_account")
            },
        )
        if accepted:
            assert result["details"]["exit"] == expected, (name, result["details"])
            after = from_boc(result["shard_account"])
            data, balance = native.account_data(after)
            row = dict(name=name, **result["details"], state=unpack(data), balance=balance)
        else:
            assert result["external_not_accepted"], (name, result)
            assert result["vm_exit_code"] == expected, (name, result)
            assert not result.get("transaction") and not result.get("shard_account")
            row = dict(name=name, exit=expected, transaction_created=False)
        if name:
            self.rows.append(row)
            print(json.dumps(row), flush=True)
        return result

    def boundary(self, label, message, account=None):
        account = self.account if account is None else account
        low, high = 1, 20000
        while low < high:
            mid = (low + high) // 2
            e = native.Emulator.from_config(config(mid), vm_log_verbosity=0)
            try:
                result = e.send(account, message)
            finally:
                e.close()
            if result["success"]:
                assert result["details"]["exit"] == 0 and not result["details"]["aborted"]
                high = mid
            else:
                assert result["vm_exit_code"] == -14, result
                low = mid + 1
        self.send(
            label + "-below",
            message,
            account=account,
            configuration=config(low - 1),
            expected=-14,
            accepted=False,
        )
        result = self.send(
            label + "-exact", message, account=account, configuration=config(low), trace=True
        )
        return dict(minimum_credit=low, total_gas=result["details"]["gas"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rust-driver", type=Path)
    args = parser.parse_args()
    h = Harness(args.output)
    boundaries = {}
    for role in (1, 2):
        body = h.message(role=role).refs[0]
        init = native.state_init(h.code, h.data)
        message = (
            Cell()
            .uint(8, 4)
            .addr(h.address)
            .coins(0)
            .uint(1, 1)
            .uint(1, 1)
            .ref(init)
            .uint(1, 1)
            .ref(body)
        )
        result = h.send(
            f"pre-funded-deployment-{role}",
            message,
            account=uninitialized(h.address, 100_000_000_000),
        )
        saved = unpack(native.account_data(from_boc(result["shard_account"]))[0])
        assert saved["primary" if role == 1 else "rescue"] == 1
    for role in (1, 2):
        label = "primary" if role == 1 else "rescue"
        msg = h.message(role=role)
        result = h.send(label, msg, trace=True)
        after = from_boc(result["shard_account"])
        saved, balance = native.account_data(after)
        assert unpack(saved)[label] == 1 and unpack(saved)["seqno"] == 1
        assert balance < native.account_data(h.account)[1]
        h.send(label + "-replay", msg, account=after, expected=1804, accepted=False)
        boundaries[label] = h.boundary(label, msg)
        h.send(label + "-forged", h.message(role=role, forged=True), expected=1808, accepted=False)
        h.send(
            label + "-domain",
            h.message(role=role, context=b"TOS-AUTH-V2-ML-DSA-44-v1"),
            expected=1808,
            accepted=False,
        )

    for name, kwargs, error in [
        ("network", {"network": NETWORK ^ 1}, 1801),
        ("global-id", {"global_id": 43}, 1801),
        ("address", {"destination": (0, 123)}, 1802),
        ("authority", {"authority": Cell()}, 1809),
        ("epoch", {"epoch": 1}, 1803),
        ("nonce", {"nonce": 1}, 1804),
        ("expired", {"deadline": native.NOW}, 1805),
        ("too-far", {"deadline": native.NOW + 3601}, 1805),
        ("primary-lock", {"kind": 3}, 1812),
        ("unknown-role", {"role": 3}, 1812),
        ("unknown-kind", {"role": 2, "kind": 2, "payload": Cell()}, 1812),
    ]:
        h.send(name, h.message(**kwargs), expected=error, accepted=False)

    envelope = h.message().refs[0]
    request, signature = envelope.refs
    for label, body, error in [
        ("trailing-envelope-bit", Cell("1", envelope.refs), 9),
        ("trailing-envelope-ref", Cell("", [*envelope.refs, Cell()]), 9),
        (
            "trailing-request-bit",
            Cell().ref(Cell(request.bits + "1", request.refs)).ref(signature),
            9,
        ),
        (
            "trailing-request-ref",
            Cell().ref(Cell(request.bits, [*request.refs, Cell()])).ref(signature),
            9,
        ),
        ("exotic-request", Cell().ref(LibraryReference(1)).ref(signature), 1820),
        ("exotic-signature", Cell().ref(request).ref(LibraryReference(1)), 9),
    ]:
        h.send(label, native.external(h.address, body), expected=error, accepted=False)
    for role in (1, 2):
        envelope = h.message(role=role).refs[0]
        sig, raw = envelope.refs[1], b""
        while True:
            raw += int(sig.bits, 2).to_bytes(len(sig.bits) // 8, "big")
            if not sig.refs:
                break
            sig = sig.refs[0]
        for delta in (-1, 1):
            changed = raw[:-1] if delta == -1 else raw + b"\x00"
            msg = native.external(h.address, Cell().ref(envelope.refs[0]).ref(chain(changed)))
            h.send(f"signature-length-{role}-{delta}", msg, expected=9, accepted=False)
    for label, authority, error in [
        ("exotic-installed-authority", LibraryReference(1), 1820),
        ("trailing-installed-authority", Cell(h.authority.bits + "1", h.authority.refs), 9),
    ]:
        h.send(
            label,
            h.message(),
            account=native.active_account(h.address, h.code, state(authority)),
            expected=error,
            accepted=False,
        )
    for label, payload, error in [
        ("exotic-payload", LibraryReference(1), 1820),
        ("trailing-payload", Cell().uint(TAGS[0], 32).uint(1, 1).ref(Cell()), 9),
    ]:
        msg = h.message(payload=payload)
        result = h.send(label, msg, expected=error)
        after = from_boc(result["shard_account"])
        assert unpack(native.account_data(after)[0])["primary"] == 1
        h.send(label + "-replay", msg, account=after, expected=1804, accepted=False)

    for label, policy_cell, error in [
        ("missing-policy", None, 1820),
        ("retired-policy", policy(network=NETWORK, retired=2), 1813),
        ("cutoff-policy", policy(network=NETWORK, deadline=native.NOW), 1813),
        ("malformed-policy", Cell(), 9),
    ]:
        cfg = config(policy_cell=policy_cell)
        h.send(label, h.message(), expected=error, accepted=False, configuration=cfg)
        h.send(label + "-rescue", h.message(role=2), configuration=cfg)

    for name, data, role in [
        ("seqno-max", {"seqno": MAX32}, 1),
        ("primary-max", {"primary": MAX64}, 1),
        ("rescue-max", {"rescue": MAX64}, 2),
    ]:
        h.send(
            name,
            h.message(role=role, nonce=MAX64 if name != "seqno-max" else 0),
            account=h.account_for(**data),
            expected=1810,
            accepted=False,
        )
    for kind in (1, 3, 4):
        payload = Cell().uint(TAGS[kind], 32)
        if kind == 1:
            payload.uint(2, 2)
        elif kind == 3:
            payload.uint(1, 8)
        else:
            payload.ref(h.make_authority(policy_value=2))
        h.send(
            f"epoch-max-{kind}",
            h.message(role=2, kind=kind, payload=payload, epoch=MAX64),
            account=h.account_for(epoch=MAX64),
            expected=1810,
            accepted=False,
        )
        if kind != 1:
            result = h.send(
                f"saturated-control-{kind}",
                h.message(role=2, kind=kind, payload=payload, nonce=MAX64),
                account=h.account_for(seqno=MAX32, rescue=MAX64),
            )
            saved = unpack(native.account_data(from_boc(result["shard_account"]))[0])
            assert saved["epoch"] == 1 and saved["primary"] == saved["rescue"] == 0
            assert saved["seqno"] == (MAX32 if kind == 3 else 0)

    for label, action, error in [
        ("send", actions(h.address), 0),
        ("bad-mode", actions(h.address, mode=1), 137),
        ("destroy", actions(h.address, mode=34), 1811),
        ("both-balances", actions(h.address, mode=194), 1811),
        ("empty-message", actions(h.address, message=Cell()), 0),
        ("truncated-message", actions(h.address, message=Cell().uint(0, 1)), 0),
        ("invalid-ext-mode", actions(h.address, mode=18, message=Cell().uint(3, 2)), 147),
        ("too-many", actions(h.address, count=256), 147),
        ("max-actions", actions(h.address, count=255), 0),
    ]:
        msg = h.message(payload=Cell().uint(TAGS[0], 32).ref(action))
        result = h.send(label, msg, expected=error)
        after = from_boc(result["shard_account"])
        assert unpack(native.account_data(after)[0])["primary"] == 1, (label, result["details"])
        h.send(label + "-replay", msg, account=after, expected=1804, accepted=False)

    for label, body in [
        ("deposit", Cell()),
        ("legacy-auth", Cell().uint(0x41553342, 32)),
        ("self-message", Cell().ref(h.authority)),
    ]:
        result = h.send(label, native.internal(h.address, h.address, body))
        assert native.account_data(from_boc(result["shard_account"]))[0].hash == h.data.hash
        assert not native.outgoing(from_boc(result["transaction"]))

    # Every control consumes an authenticated attempt. Failed migration preserves
    # its original seqno and authority; a corrected request uses the new epoch.
    for label, kind, payload, error in [
        ("bad-configure", 1, Cell().uint(TAGS[1], 32).uint(1, 2), 1806),
        ("bad-lock", 3, Cell().uint(TAGS[3], 32).uint(2, 8), 1811),
        (
            "bad-migrate-key",
            4,
            Cell().uint(TAGS[4], 32).ref(h.make_authority(primary=chain(b"short"))),
            63,
        ),
        (
            "bad-migrate-network",
            4,
            Cell().uint(TAGS[4], 32).ref(h.make_authority(network=NETWORK ^ 1)),
            1801,
        ),
    ]:
        msg = h.message(role=2, kind=kind, payload=payload)
        result = h.send(label, msg, account=h.account_for(seqno=7), expected=error)
        after = from_boc(result["shard_account"])
        saved = unpack(native.account_data(after)[0])
        assert saved["authority"] == h.authority.hash.hex() and saved["retired"] == 0
        assert saved["epoch"] == 1 and saved["primary"] == saved["rescue"] == 0
        assert saved["seqno"] == (8 if kind == 1 else 7)
        h.send(label + "-replay", msg, account=after, expected=1803, accepted=False)

    malformed = Cell().uint(TAGS[4], 32).ref(h.make_authority(primary=chain(b"short")))
    result = h.send(
        "saturated-bad-migrate",
        h.message(role=2, kind=4, nonce=MAX64, payload=malformed),
        account=h.account_for(seqno=MAX32, rescue=MAX64),
        expected=63,
    )
    after = from_boc(result["shard_account"])
    assert unpack(native.account_data(after)[0])["seqno"] == MAX32
    successor = h.make_authority(policy_value=2)
    result = h.send(
        "corrected-migrate",
        h.message(role=2, kind=4, epoch=1, payload=Cell().uint(TAGS[4], 32).ref(successor)),
        account=after,
    )
    saved = unpack(native.account_data(from_boc(result["shard_account"]))[0])
    assert (
        saved["seqno"] == 0 and saved["epoch"] == 2 and saved["authority"] == successor.hash.hex()
    )

    for kind in (1, 3, 4):
        payload = None if kind != 4 else Cell().uint(TAGS[4], 32).ref(successor)
        boundaries[f"control-{kind}"] = h.boundary(
            f"control-{kind}", h.message(role=2, kind=kind, payload=payload)
        )
    for role in (1, 2):
        account = h.account_for(seqno=MAX32 - 1, epoch=MAX64, primary=MAX64 - 1, rescue=MAX64 - 1)
        msg = h.message(
            role=role,
            epoch=MAX64,
            nonce=MAX64 - 1,
            payload=Cell().uint(TAGS[0], 32).ref(actions(h.address, count=255)),
        )
        boundaries[f"maximum-state-actions-{role}"] = h.boundary(
            f"maximum-state-actions-{role}", msg, account
        )
    for label, successor, error in [
        ("short-key", h.make_authority(primary=chain(h.pkfile.read_bytes()[:-1])), 63),
        ("long-key", h.make_authority(primary=chain(h.pkfile.read_bytes() + b"\x00")), 63),
        ("exotic-successor", LibraryReference(1), 1820),
        ("trailing-successor", Cell(h.authority.bits + "1", h.authority.refs), 9),
    ]:
        result = h.send(
            label,
            h.message(role=2, kind=4, payload=Cell().uint(TAGS[4], 32).ref(successor)),
            expected=error,
        )
        saved = unpack(native.account_data(from_boc(result["shard_account"]))[0])
        assert saved["authority"] == h.authority.hash.hex() and saved["epoch"] == 1
    result = h.send(
        "lock-without-policy", h.message(role=2, kind=3), configuration=config(policy_cell=None)
    )
    assert unpack(native.account_data(from_boc(result["shard_account"]))[0])["retired"] == 2

    # READY migration pays for a missing-policy refusal after acceptance;
    # REQUIRED migration must remain available with no CP48 at all.
    for next_policy, error in [(1, 1820), (2, 0)]:
        successor = h.make_authority(policy_value=next_policy)
        account = h.account_for(seqno=7)
        result = h.send(
            f"migrate-policy-{next_policy}-without-cp48",
            h.message(role=2, kind=4, payload=Cell().uint(TAGS[4], 32).ref(successor)),
            account=account,
            configuration=config(policy_cell=None),
            expected=error,
        )
        data, balance = native.account_data(from_boc(result["shard_account"]))
        saved = unpack(data)
        assert saved == dict(
            seqno=7 if error else 0,
            wallet_id=0,
            retired=0,
            epoch=1,
            primary=0,
            rescue=0,
            authority=(h.authority if error else successor).hash.hex(),
        ), saved
        assert balance < native.account_data(account)[1]

    for label, account, cfg in [
        ("local-retired", h.account_for(retired=2), config()),
        ("global-retired", h.account, config(policy_cell=policy(network=NETWORK, retired=2))),
        (
            "scheduled-retired",
            h.account,
            config(policy_cell=policy(network=NETWORK, deadline=native.NOW)),
        ),
    ]:
        msg = h.message(role=2, kind=4, payload=Cell().uint(TAGS[4], 32).ref(h.authority))
        result = h.send(
            label + "-migrate-ready", msg, account=account, configuration=cfg, expected=1813
        )
        saved = unpack(native.account_data(from_boc(result["shard_account"]))[0])
        assert saved["authority"] == h.authority.hash.hex() and saved["epoch"] == 1

    # Sweep balances across import/admission/paid-execution thresholds. Every
    # accepted attempt must persist its counter, including paid out-of-gas.
    balance_rows = []
    for role in (1, 2):
        msg = h.message(
            role=role, payload=Cell().uint(TAGS[0], 32).ref(actions(h.address, count=255))
        )
        accepted_count = rejected_count = paid_oog_count = 0
        for balance in (
            0,
            1_000_000,
            20_000_000,
            50_000_000,
            75_000_000,
            90_000_000,
            100_000_000,
            125_000_000,
            150_000_000,
            250_000_000,
            1_000_000_000,
        ):
            label = f"balance-{role}-{balance}"
            account = native.active_account(h.address, h.code, h.data, balance=balance)
            result = h.transact(label, msg, account)
            if result["success"]:
                accepted_count += 1
                after = from_boc(result["shard_account"])
                saved = unpack(native.account_data(after)[0])
                assert saved["primary" if role == 1 else "rescue"] == 1, (label, result["details"])
                if result["details"]["exit"] == -14:
                    paid_oog_count += 1
                replay = h.transact(label + "-replay", msg, after)
                assert not replay["success"] and not replay.get("transaction"), label
                balance_rows.append(dict(name=label, accepted=True, **result["details"]))
            else:
                rejected_count += 1
                assert not result.get("transaction") and not result.get("shard_account"), label
                balance_rows.append(dict(name=label, accepted=False, error=result.get("error")))
        assert accepted_count and rejected_count and paid_oog_count, (role, balance_rows)

    # Sensitivity: removing signature authorization admits an actual forgery;
    # removing the explicit commit loses nonce state after a signed bad action.
    source_path = ROOT / "crypto/smartcont/wallet-quantum-self-pay.fc"
    source = source_path.read_text()
    mutations = {}
    for label, old, new in [
        (
            "signature",
            "throw_unless(auth::bad_signature, pq_check_suite(digest, context, signature, public_key, suite));",
            ";; TEST MUTATION: signature check removed",
        ),
        ("commit", "  commit();", "  ;; TEST MUTATION: replay fallback removed"),
    ]:
        assert source.count(old) == 1
        mutant = source.replace(old, new)
        for include in ("wallet-quantum-self-pay-common.fc", "wallet-v5-action-list.fc"):
            mutant = mutant.replace(
                f'"{include}"',
                f'"{os.path.relpath(ROOT / "crypto/smartcont" / include, h.output)}"',
            )
        path = h.output / ("mutation-" + label + ".fc")
        path.write_text(mutant)
        code = native.compile_contract(str(path), path.with_suffix(".boc"))
        account = native.active_account(h.address, code, h.data)
        msg = (
            h.message(forged=True)
            if label == "signature"
            else h.message(payload=Cell().uint(TAGS[0], 32).ref(actions(h.address, mode=1)))
        )
        result = h.transact("mutation-" + label, msg, account)
        assert result["success"]
        saved = unpack(native.account_data(from_boc(result["shard_account"]))[0])
        assert saved["primary"] == (1 if label == "signature" else 0)
        mutations[label] = "caught"

    fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
    (h.output / "config.boc").write_bytes(Cell(fixture.bits, [config()]).boc())
    (h.output / "scenarios.tsv").write_text("\n".join(h.scenarios) + "\n")
    (h.output / "native.tsv").write_text("\n".join(h.transcripts) + "\n")
    if args.rust_driver:
        result = subprocess.run(
            [
                str(args.rust_driver.resolve()),
                str(h.output / "config.boc"),
                str(h.output / "scenarios.tsv"),
                "16",
                "--details",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        (h.output / "rust.tsv").write_text(result.stdout)
        (h.output / "rust.log").write_text(result.stderr)
        assert result.stdout.splitlines() == h.transcripts, "native/Rust transaction mismatch"

    report = dict(
        source_commit=run("git", "-C", ROOT, "rev-parse", "HEAD").strip(),
        source_sha256=hashlib.sha256(
            (ROOT / "crypto/smartcont/wallet-quantum-self-pay.fc").read_bytes()
        ).hexdigest(),
        code_hash=h.code.hash.hex(),
        boundaries=boundaries,
        cases=h.rows,
        balance_sweep=balance_rows,
        mutations=mutations,
        parity_cases=len(h.scenarios),
        rust_parity="passed" if args.rust_driver else "not run",
        provenance=provenance(args.rust_driver),
        scope="Local transaction fixtures; no mobile or live-chain acceptance",
    )
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(cases=len(h.rows), boundaries=boundaries)))


if __name__ == "__main__":
    main()
