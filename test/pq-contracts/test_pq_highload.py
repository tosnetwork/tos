#!/usr/bin/env python3
"""pq-highload-wallet-code.fc as real transactions at global version 16.

usage: test_pq_highload.py --build <build-dir> --signer <test-pq-contracts-sign> [--report out.json]

Every case asserts the outcome that matters, not only that the emulator ran: the exit code,
the stored state (whether the query id was consumed), each outbound message's destination,
value and order, and whether a refused request can still be submitted.
"""

import argparse
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pqtest  # noqa: E402
from pqtest import ROOT, Cell  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--build", required=True)
parser.add_argument("--signer", required=True)
parser.add_argument("--source", default=str(ROOT / "crypto/smartcont/pq-highload-wallet-code.fc"))
parser.add_argument("--report", help="write measured gas as JSON here")
parser.add_argument("--results", help="write the structured test outcome as JSON here")
ARGS, REST = parser.parse_known_args()
native = pqtest.configure(ARGS.build, ARGS.signer)

CONTEXT = b"TOS-PQ-HIGHLOAD-v1"
GLOBAL_ID = native.GLOBAL_ID
OWNER_KEY = 0
WALLET = (0, 0xAB << 248)
RELAYER = (0, 0x7E << 248)
PAYEE = (0, 0x9A << 248)
SUBWALLET = 7
TIMEOUT = 3600
WALLET_FUNDS = 1_000 * 10**9
SUBMIT = 0x50514857
EXCESSES = 0xD53276DB
SEND_MSG = 0x0EC3C86D
MAX_ACTIONS = 254
GENEROUS = 10 * 10**9
ERR = {
    "wrong_workchain": 0x1C02,
    "bad_submission": 0x1C03,
    "wrong_network": 0x1C04,
    "wrong_wallet": 0x1C05,
    "wrong_subwallet": 0x1C06,
    "wrong_timeout": 0x1C07,
    "invalid_action": 0x1C08,
    "invalid_mode": 0x1C09,
    "invalid_message": 0x1C0A,
    "insufficient_value": 0x1C0B,
    "invalid_signature": 0x1C0C,
    "already_processed": 0x1701,
    "invalid_query_id": 0x1702,
    "invalid_created_at": 0x1703,
}
REPORT = {}

with tempfile.TemporaryDirectory() as tmp:
    CODE = pqtest.compile_source(ARGS.source, Path(tmp) / "wallet.boc")


def wallet_data(
    key=OWNER_KEY, subwallet=SUBWALLET, timeout=TIMEOUT, old=None, queries=None, last_clean=0
):
    return (
        Cell()
        .ref(pqtest.stored(pqtest.public_key(key)))
        .uint(subwallet, 32)
        .maybe(old)
        .maybe(queries)
        .uint(last_clean, 64)
        .uint(timeout, 22)
    )


def relaxed(dest, value, body=None, inline=b"", src_none=True, bounced=False, init=False):
    c = Cell().uint(0, 1).uint(1, 1).uint(0, 1).uint(1 if bounced else 0, 1)
    c = c.uint(0, 2) if src_none else c.addr(RELAYER)
    c = c.addr(dest).coins(value).uint(0, 1).coins(0).coins(0).uint(0, 64).uint(0, 32)
    c = c.uint(1, 1).uint(0, 1).ref(Cell()) if init else c.uint(0, 1)
    if body is not None:
        return c.uint(1, 1).ref(body)
    return c.uint(0, 1).raw(inline)


def out_list(sends):
    """sends: [(mode, message)] in signed order; the OutList head is the last one."""
    node = Cell()
    for mode, message in sends:
        node = Cell().ref(node).uint(SEND_MSG, 32).uint(mode, 8).ref(message)
    return node


def request(
    sends,
    query_id,
    created_at=None,
    wallet=WALLET,
    subwallet=SUBWALLET,
    timeout=TIMEOUT,
    network=GLOBAL_ID,
):
    created_at = native.NOW - 10 if created_at is None else created_at
    return (
        Cell()
        .sint(network, 32)
        .addr(wallet)
        .uint(subwallet, 32)
        .uint(query_id, 23)
        .uint(created_at, 64)
        .uint(timeout, 22)
        .ref(out_list(sends))
    )


def submission(req, key=OWNER_KEY, relayer_query_id=1, signature=None):
    if signature is None:
        signature = pqtest.stored(pqtest.sign(key, req.hash, CONTEXT))
    return Cell().uint(SUBMIT, 32).uint(relayer_query_id, 64).ref(req).ref(signature)


def relayed(body, value, sender=RELAYER, bounce=True):
    flags = 6 if bounce else 4  # int_msg_info$0 ihr_disabled bounce bounced
    return (
        Cell()
        .uint(flags, 4)
        .addr(sender)
        .addr(WALLET)
        .coins(value)
        .uint(0, 1)
        .coins(0)
        .coins(0)
        .uint(0, 64)
        .uint(native.NOW, 32)
        .uint(0, 1)
        .uint(1, 1)
        .ref(body)
    )


def parse_out(message):
    s = message.slice()
    assert s.uint(1) == 0
    s.uint(1)
    bounce = s.uint(1)
    bounced = s.uint(1)
    s.addr()
    dest = s.addr()
    value = s.coins()
    s.maybe()
    s.coins()
    s.coins()
    s.uint(64)
    s.uint(32)
    assert s.uint(1) == 0
    body = s.ref() if s.uint(1) else Cell(s.bits, s.refs)
    return {"dest": dest, "value": value, "bounce": bounce, "bounced": bounced, "body": body}


def processed_ids(shard):
    """Query ids recorded in the wallet's replay dictionaries (both generations)."""
    data, _ = native.account_data(shard)
    s = data.slice()
    s.ref()
    s.uint(32)
    ids = set()
    for _ in range(2):
        rows = s.maybe()
        if rows is not None:
            for row, cell in pqtest.read_dict(rows, 13).items():
                bits = cell.slice().ref().slice().uint(1023)  # each row is a ^Cell of 1023 bits
                ids |= {(row << 10) | b for b in range(1023) if (bits >> (1022 - b)) & 1}
    return ids


class Wallet:
    def __init__(self, version=16, data=None, address=WALLET, funds=WALLET_FUNDS):
        self.emulator = native.Emulator(global_version=version)
        self.address = address
        self.shard = native.active_account(address, CODE, data or wallet_data(), funds)

    def balance(self):
        return native.account_data(self.shard)[1]

    def data_hash(self):
        return native.account_data(self.shard)[0].hash

    def send(self, message):
        """Runs one transaction and adopts the account the executor returns, whatever the
        outcome, so a refusal is judged on the state it actually left behind."""
        before = self.data_hash()
        result = self.emulator.send(self.shard, message)
        details = pqtest.details_of(result)
        self.shard = pqtest.from_boc(result["shard_account"])
        details["data_changed"] = self.data_hash() != before
        details["out"] = [
            parse_out(m) for m in native.outgoing(pqtest.from_boc(result["transaction"]))
        ]
        return details

    def submit(self, req, value=GENEROUS, **kwargs):
        sender = kwargs.pop("sender", RELAYER)
        bounce = kwargs.pop("bounce", True)
        return self.send(relayed(submission(req, **kwargs), value, sender=sender, bounce=bounce))


def pay(value, tag):
    return relaxed(PAYEE, value, body=Cell().uint(tag, 32))


class PqHighloadTest(unittest.TestCase):
    def assertExit(self, details, name):
        """A refusal must leave the wallet's data exactly as it was and send nothing for the
        owner; a success must have completed both phases."""
        code = ERR[name] if isinstance(name, str) else name
        self.assertEqual(details["exit"], code, details)
        if code == 0:
            self.assertTrue(details["compute_success"] and not details["aborted"], details)
            self.assertTrue(details["action"] and details["action"]["success"], details)
        else:
            self.assertFalse(details["data_changed"], details)
            # at most the relayer's own value bounced back, never a message for the owner
            self.assertTrue(all(o["bounced"] for o in details["out"]), details)

    def test_batch_runs_in_signed_order_after_the_refund(self):
        w = Wallet()
        before = w.balance()
        d = w.submit(request([(1, pay(5 * 10**9, 1)), (1, pay(7 * 10**9, 2))], query_id=5))
        self.assertExit(d, 0)
        self.assertTrue(d["action"]["success"])
        self.assertEqual([o["dest"] for o in d["out"]], [RELAYER, PAYEE, PAYEE])
        refund, first, second = d["out"]
        self.assertEqual((first["value"], second["value"]), (5 * 10**9, 7 * 10**9))
        self.assertEqual(refund["body"].slice().uint(32), EXCESSES)
        self.assertEqual(refund["bounce"], 0)
        self.assertGreater(refund["value"], GENEROUS - 10**9)
        self.assertIn(5, processed_ids(w.shard))
        # the wallet paid the batch and its forwarding, and nothing for the relayer's gas
        spent = before - w.balance()
        self.assertGreaterEqual(spent, 12 * 10**9)
        self.assertLess(spent, 12 * 10**9 + 10**8)
        REPORT["two_message_gas"] = d["gas"]

    def test_a_payment_then_a_sweep(self):
        w = Wallet()
        d = w.submit(request([(1, pay(10**9, 1)), (128, pay(0, 2))], query_id=6))
        self.assertExit(d, 0)
        self.assertEqual([o["dest"] for o in d["out"]], [RELAYER, PAYEE, PAYEE])
        self.assertEqual(d["out"][1]["value"], 10**9)
        self.assertGreater(d["out"][2]["value"], WALLET_FUNDS - 2 * 10**9)

    def test_replayed_request_refused(self):
        w = Wallet()
        req = request([(1, pay(10**9, 1))], query_id=9)
        self.assertExit(w.submit(req), 0)
        d = w.submit(req)
        self.assertExit(d, "already_processed")

    def test_bad_signature_changes_nothing(self):
        w = Wallet()
        req = request([(1, pay(10**9, 1))], query_id=11)
        d = w.submit(req, key=1)
        self.assertExit(d, "invalid_signature")
        self.assertNotIn(11, processed_ids(w.shard))
        # still usable with the right signature
        self.assertExit(w.submit(req), 0)

    def test_requests_are_bound(self):
        w = Wallet()
        sends = [(1, pay(10**9, 1))]
        self.assertExit(w.submit(request(sends, 12, network=GLOBAL_ID + 1)), "wrong_network")
        self.assertExit(w.submit(request(sends, 12, wallet=(0, 0xAC << 248))), "wrong_wallet")
        self.assertExit(w.submit(request(sends, 12, wallet=(-1, WALLET[1]))), "wrong_wallet")
        self.assertExit(w.submit(request(sends, 12, subwallet=SUBWALLET + 1)), "wrong_subwallet")
        self.assertExit(w.submit(request(sends, 12, timeout=TIMEOUT + 1)), "wrong_timeout")
        self.assertNotIn(12, processed_ids(w.shard))

    def first_verification_gas(self, w, query_id):
        """Gas of a well-formed request that fails verification: one verification paid."""
        d = w.submit(request([(1, pay(10**9, 1))], query_id), key=1)
        self.assertExit(d, "invalid_signature")
        return d["gas"]

    def assertRefusedBeforeVerification(self, w, details, name, query_id):
        self.assertExit(details, name)
        self.assertNotIn(query_id, processed_ids(w.shard))
        self.assertLess(details["gas"] + 40_000, self.first_verification_gas(w, query_id), details)

    def test_malformed_batches_refused_whole_before_verification(self):
        w = Wallet()
        good = pay(10**9, 1)
        cases = [
            ([(1 | 32, good)], "invalid_mode"),
            ([(1 | 64, good)], "invalid_mode"),
            ([(128 | 32, good)], "invalid_mode"),
            # +4 and +8 the executor treats as invalid, +16 the forced +2 makes meaningless
            ([(4, good)], "invalid_mode"),
            ([(8, good)], "invalid_mode"),
            ([(16, good)], "invalid_mode"),
            ([(1 | 4, good)], "invalid_mode"),
            ([(1 | 16 | 128, good)], "invalid_mode"),
            ([(1, relaxed(PAYEE, 1, init=True))], "invalid_message"),
            ([(1, relaxed(PAYEE, 1, src_none=False))], "invalid_message"),
            ([(1, relaxed(PAYEE, 1, bounced=True))], "invalid_message"),
            ([], "invalid_action"),
        ]
        for i, (sends, error) in enumerate(cases):
            qid = 100 + i
            self.assertRefusedBeforeVerification(w, w.submit(request(sends, qid)), error, qid)
        # One action too many is found only once 254 have been checked: refused before
        # verification and unused, though the relayer pays for the walk.
        d = w.submit(request([(1, good)] * (MAX_ACTIONS + 1), 110))
        self.assertExit(d, "invalid_action")
        self.assertNotIn(110, processed_ids(w.shard))
        REPORT["oversized_batch_refusal_gas"] = d["gas"]
        # a referenced body with trailing data after its reference
        trailing = Cell(
            relaxed(PAYEE, 1, body=Cell()).bits + "1", relaxed(PAYEE, 1, body=Cell()).refs
        )
        self.assertRefusedBeforeVerification(w, w.submit(request([(1, trailing)], 120)), 9, 120)
        # an action that is not a send
        reserve = Cell().ref(Cell()).uint(0x36E6B809, 32).uint(0, 8).coins(1).uint(0, 1)
        req = request([], 121)
        req.refs[0] = reserve
        self.assertRefusedBeforeVerification(w, w.submit(req), "invalid_action", 121)

    def test_signature_wrapper_and_list_terminator(self):
        w = Wallet()
        req = request([(1, pay(10**9, 1))], 60)
        signature = pqtest.sign(OWNER_KEY, req.hash, CONTEXT)
        wrong_length = Cell().uint(len(signature) - 1, 32).ref(pqtest.chain(signature[:-1]))
        self.assertExit(w.submit(req, signature=wrong_length), "bad_submission")
        self.assertExit(w.submit(req, signature=Cell().uint(len(signature), 32)), "bad_submission")
        # an OutList whose terminator carries data is not a list the wallet signs for
        bad_end = request([(1, pay(10**9, 1))], 61)
        bad_end.refs[0].refs[0] = Cell().uint(1, 1)
        self.assertExit(w.submit(bad_end), 9)
        self.assertEqual(processed_ids(w.shard), set())
        self.assertExit(w.submit(req), 0)

    def test_undeliverable_message_skipped_and_id_consumed(self):
        w = Wallet()
        to_none = Cell(relaxed(PAYEE, 10**9).bits.replace(Cell().addr(PAYEE).bits, "00", 1), [])
        d = w.submit(
            request([(1, pay(10**9, 1)), (1, to_none), (1, pay(2 * 10**9, 3))], query_id=13)
        )
        self.assertExit(d, 0)
        self.assertTrue(d["action"]["success"])
        self.assertEqual([o["value"] for o in d["out"][1:]], [10**9, 2 * 10**9])
        self.assertIn(13, processed_ids(w.shard))

    def test_relayer_and_wallet_must_be_on_basechain(self):
        w = Wallet()
        req = request([(1, pay(10**9, 1))], query_id=14)
        self.assertExit(w.submit(req, sender=(-1, RELAYER[1])), "wrong_workchain")
        mc = Wallet(address=(-1, WALLET[1]))
        self.assertExit(
            mc.submit(request([(1, pay(10**9, 1))], 14, wallet=(-1, WALLET[1]))), "wrong_workchain"
        )

    def test_replay_boundaries(self):
        w = Wallet()
        sends = [(1, pay(10**9, 1))]
        self.assertExit(
            w.submit(request(sends, 20, created_at=native.NOW - TIMEOUT)), "invalid_created_at"
        )
        self.assertExit(
            w.submit(request(sends, 20, created_at=native.NOW + 1)), "invalid_created_at"
        )
        self.assertExit(w.submit(request(sends, 20, created_at=native.NOW - TIMEOUT + 1)), 0)
        self.assertExit(w.submit(request(sends, 1023)), "invalid_query_id")
        self.assertExit(w.submit(request(sends, (5 << 10) | 1023)), "invalid_query_id")

    def test_ids_age_out_after_two_timeouts(self):
        w = Wallet()
        sends = [(1, pay(10**9, 1))]
        self.assertExit(w.submit(request(sends, 30)), 0)
        for step, remembered in ((TIMEOUT + 1, True), (2 * TIMEOUT + 2, False)):
            w.emulator.lib.transaction_emulator_set_unixtime(w.emulator.ptr, native.NOW + step)
            created = native.NOW + step - 10
            # a new request rotates the generations; the old id is then judged against them
            self.assertExit(w.submit(request(sends, 31 + step, created_at=created)), 0)
            self.assertEqual(30 in processed_ids(w.shard), remembered)
        w.emulator.lib.transaction_emulator_set_unixtime(w.emulator.ptr, native.NOW)

    def test_version_15_cannot_verify(self):
        w = Wallet(version=15)
        d = w.submit(request([(1, pay(10**9, 1))], query_id=40))
        self.assertExit(d, 6)
        self.assertNotIn(40, processed_ids(w.shard))

    def test_bad_bounceable_submission_bounces_the_remainder(self):
        w = Wallet()
        d = w.submit(request([(1, pay(1, 1))], 41), key=1)
        self.assertExit(d, "invalid_signature")
        self.assertEqual(len(d["out"]), 1)
        self.assertEqual(d["out"][0]["dest"], RELAYER)
        self.assertGreater(d["out"][0]["value"], GENEROUS - 10**9)
        # a non-bounceable submission keeps its remainder in the wallet
        quiet = w.submit(request([(1, pay(1, 1))], 42), key=1, bounce=False)
        self.assertExit(quiet, "invalid_signature")
        self.assertEqual(quiet["out"], [])

    def test_output_past_the_total_limit_is_skipped(self):
        # Three messages sharing one body of 8,191 distinct cells: each is within the
        # per-message limit, but the action phase counts the body once per message, and the
        # third passes the total output limit. With IGNORE_ERRORS forced it is skipped alone:
        # the others go out and the id is consumed.
        def tree(depth, tag):
            if depth == 0:
                return Cell().uint(tag, 32)
            return (
                Cell().uint(tag, 32).ref(tree(depth - 1, tag * 2)).ref(tree(depth - 1, tag * 2 + 1))
            )

        body = tree(12, 1)  # 8,191 cells
        w = Wallet()
        sends = [(1, relaxed(PAYEE, 10**9, body=body))] * 3
        d = w.submit(request(sends, 50))
        self.assertExit(d, 0)
        self.assertEqual([o["dest"] for o in d["out"]], [RELAYER, PAYEE, PAYEE])
        self.assertIn(50, processed_ids(w.shard))

    def dense_wallet(self):
        """Both replay generations nearly full of rows, so recording an id walks the deepest
        dictionary paths: the worst state the compute bound has to cover."""
        row = Cell().ref(Cell().uint(1, 1023))
        rows = pqtest.make_dict({shift: row for shift in range(0, 8190, 2)}, 13)
        return Wallet(data=wallet_data(old=rows, queries=rows, last_clean=native.NOW))

    def test_gas_profile(self):
        gas = {}
        for n in (1, MAX_ACTIONS):
            w = self.dense_wallet()
            qid = (8191 << 10) | n  # a row neither generation holds yet
            d = w.submit(request([(1, pay(1, i)) for i in range(n)], qid))
            self.assertExit(d, 0)
            self.assertTrue(d["action"]["success"])
            self.assertEqual(len(d["out"]), n + 1)
            gas[n] = d["gas"]
        per_action = -(-(gas[MAX_ACTIONS] - gas[1]) // (MAX_ACTIONS - 1))
        REPORT["gas_by_actions_dense"] = gas
        REPORT["measured_gas_per_action"] = per_action
        REPORT["measured_base_gas"] = gas[1] - per_action
        source = Path(ARGS.source).read_text()
        profile = {
            name: int(re.search(rf"const int fee::{name} = (\d+);", source).group(1))
            for name in ("base_gas", "gas_per_action")
        }
        for name, measured in (("base_gas", gas[1] - per_action), ("gas_per_action", per_action)):
            self.assertLessEqual(measured, profile[name], name)
            self.assertLessEqual(profile[name], measured * 5 // 4, name)

    def threshold(self, w, sends, query_id):
        """The smallest value the wallet takes a request at, found by bisection on real
        transactions. Below it the request must be refused unused; at it, run whole."""
        low, high = 0, GENEROUS
        while high - low > 1:
            mid = (low + high) // 2
            d = w.submit(request(sends, query_id), value=mid)
            if d["exit"] == 0:
                high = mid
                w.shard = self.fresh_shard
            else:
                self.assertIn(d["exit"], (ERR["insufficient_value"], -14), d)
                low = mid
        return high

    def test_required_value_is_exactly_enough(self):
        for n in (1, MAX_ACTIONS):
            w = self.dense_wallet()
            self.fresh_shard = w.shard
            qid = (8191 << 10) | n
            sends = [(1, pay(1, i)) for i in range(n)]
            value = self.threshold(w, sends, qid)
            below = w.submit(request(sends, qid), value=value - 1)
            self.assertExit(below, "insufficient_value")
            self.assertNotIn(qid, processed_ids(w.shard))
            at = w.submit(request(sends, qid), value=value)
            self.assertExit(at, 0)
            self.assertTrue(at["action"]["success"])
            self.assertEqual(len(at["out"]), n + 1)  # the refund went out too
            self.assertIn(qid, processed_ids(w.shard))
            REPORT[f"required_value_{n}"] = value
            # the getter a relayer reads quotes exactly this threshold
            self.assertEqual(self.getter(w, "get_required_value", n), [value])

    def run_deploy_script(self, tmp, *args):
        build = Path(ARGS.build).resolve()
        include = f"{ROOT}/crypto/fift/lib:{ROOT}/crypto/smartcont:{build}/crypto/smartcont"
        script = ROOT / "crypto/smartcont/new-pq-highload-wallet.fif"
        return subprocess.run(
            [str(build / "crypto/fift"), "-I", include, "-s", str(script), *map(str, args)],
            cwd=tmp,
            capture_output=True,
            text=True,
        )

    def test_deploy_script_embeds_this_build(self):
        # A build-consistency check, not a behaviour test: mutations.py does not count it
        # as evidence, since any change to the compiled source makes it fail.
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "owner.pk"
            key.write_bytes(pqtest.public_key(OWNER_KEY))
            result = self.run_deploy_script(tmp, SUBWALLET, TIMEOUT, key, "pqw")
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            init = pqtest.from_boc((Path(tmp) / "pqw.init.boc").read_bytes())
            self.assertEqual(init.refs[0].hash, CODE.hash)

    def test_deploy_script_builds_a_working_wallet(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "owner.pk"
            key.write_bytes(pqtest.public_key(OWNER_KEY))
            result = self.run_deploy_script(tmp, SUBWALLET, TIMEOUT, key, "pqw")
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            init = pqtest.from_boc((Path(tmp) / "pqw.init.boc").read_bytes())
            address = (0, int.from_bytes(init.hash, "big"))
            self.assertIn(f"0:{address[1]:064x}", result.stdout)
            # it ran the wallet's own check and reports the key id that check derived
            self.assertIn(
                f"Key id: {pqtest.key_id(pqtest.public_key(OWNER_KEY)):064x}", result.stdout
            )
            # deploy with a real StateInit, at the address it derives
            w = Wallet()
            w.address = address
            w.shard = Cell().ref(Cell().uint(0, 1)).uint(0, 256).uint(0, 64)  # account_none
            deploy = (
                Cell()
                .uint(4, 4)
                .addr(RELAYER)
                .addr(address)
                .coins(100 * 10**9)
                .uint(0, 1)
                .coins(0)
                .coins(0)
                .uint(0, 64)
                .uint(native.NOW, 32)
                .uint(1, 1)
                .uint(1, 1)
                .ref(init)
                .uint(0, 1)
            )
            result = w.emulator.send(w.shard, deploy)
            self.assertTrue(result["success"], result)
            w.shard = pqtest.from_boc(result["shard_account"])
            relay = relayed(submission(request([(1, pay(10**9, 1))], 70, wallet=address)), GENEROUS)
            relay = Cell(
                relay.bits.replace(Cell().addr(WALLET).bits, Cell().addr(address).bits, 1),
                relay.refs,
            )
            d = w.send(relay)
            self.assertExit(d, 0)
            self.assertEqual([o["dest"] for o in d["out"]], [RELAYER, PAYEE])
            self.assertIn(70, processed_ids(w.shard))
            # refused inputs
            for args, message in (
                ((SUBWALLET, 0, key, "x"), "timeout"),
                ((SUBWALLET, 1 << 22, key, "x"), "timeout"),
                ((1 << 32, TIMEOUT, key, "x"), "subwallet"),
            ):
                result = self.run_deploy_script(tmp, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
            short = Path(tmp) / "short.pk"
            short.write_bytes(pqtest.public_key(OWNER_KEY)[:-1])
            result = self.run_deploy_script(tmp, SUBWALLET, TIMEOUT, short, "x")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("1312 bytes", result.stderr)

    def getter(self, w, method, *args):
        data, balance = native.account_data(w.shard)
        code, values = pqtest.get_method(CODE, data, w.address, method, args, balance=balance)
        self.assertEqual(code, 0, (method, values))
        return values

    def test_getters(self):
        w = Wallet()
        self.assertEqual(
            self.getter(w, "get_key_id"), [pqtest.key_id(pqtest.public_key(OWNER_KEY))]
        )
        self.assertEqual(self.getter(w, "get_subwallet_id"), [SUBWALLET])
        self.assertEqual(self.getter(w, "get_timeout"), [TIMEOUT])
        self.assertEqual(
            self.getter(w, "get_checked_config"), [pqtest.key_id(pqtest.public_key(OWNER_KEY))]
        )
        self.assertEqual(self.getter(w, "processed?", 80, 0), [0])
        self.assertExit(w.submit(request([(1, pay(10**9, 1))], 80)), 0)
        self.assertEqual(self.getter(w, "processed?", 80, 0), [-1])
        self.assertEqual(self.getter(w, "processed?", 1023, 0), [0])
        self.assertEqual(self.getter(w, "get_last_clean_time"), [native.NOW])
        # a state the wallet could never serve is refused
        short_key = (
            Cell()
            .ref(pqtest.stored(b"x" * 1311))
            .uint(SUBWALLET, 32)
            .uint(0, 1)
            .uint(0, 1)
            .uint(0, 64)
        ).uint(TIMEOUT, 22)
        for data in (wallet_data(timeout=0), short_key):
            code, _ = pqtest.get_method(CODE, data, WALLET, "get_checked_config")
            self.assertNotEqual(code, 0)

    def test_external_messages_refused(self):
        w = Wallet()
        result = w.emulator.send(w.shard, native.external(WALLET, Cell().uint(0, 32)))
        self.assertFalse(result["success"])


if __name__ == "__main__":
    sys.exit(pqtest.run(REPORT, [sys.argv[0]] + REST, ARGS.results, ARGS.report))
