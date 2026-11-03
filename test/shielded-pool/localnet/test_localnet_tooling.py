"""The gate's adjudication, redaction and evidence checks, each shown to fail.

Nothing here needs a chain. Every positive decision the live driver makes is
exercised with the shape the driver feeds it, and then again with one fact
wrong, so the live run's PASS means the checks were able to say FAIL.
"""

from __future__ import annotations

import dataclasses
import json
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / "test/bonded-relayer"))
sys.path.insert(0, str(HERE.parents[2] / "tools/bonded-relayer"))

import adjudicate as adj  # noqa: E402
import evidence  # noqa: E402
from connection_trace import Connect, adjudicate_connections, parse_connects  # noqa: E402
from localnet_common import (  # noqa: E402
    PROVENANCE_BINARIES,
    Completed,
    LeakedSecret,
    LocalnetError,
    Receipts,
    nanotos,
    run_measured,
    tos_text,
)
from socks_peer import GatedSocksPeer, path_class, serve  # noqa: E402

ONION = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
TOS = 10**9
POOL = "0:" + "aa" * 32

BALANCE_OUTPUT = """Instance "s": pool 0:aa on local (global id 3)
Synced: verified to lt 5 at masterchain 9 (2026-11-03 00:00:00 UTC), 7 transactions replayed
Balance: 20 TOS in 2 spendable notes
Indices: next 2, 0 reused; diagnostics: 0
Pending deposits: none
Pending spends: none
  index      0  leaf          0  ordinary                     10 TOS
  index      1  leaf          1  ordinary                     10 TOS
  index      2  leaf          7  recovery            9.979999999 TOS  spent
"""

SPEND_OUTPUT = """
Spend summary:
  Kind:        Transfer
  To:          descriptor index 0
  Amount:      15 TOS
  Pool fee:    0 TOS (withdrawal fee, from the notes)
  Inputs:      10 TOS (leaf 0) + 10 TOS (leaf 1)
  Change:      4.7 TOS (back to this instance)
  Anchor:      preserved root version 3
  Broadcast:   f (0:bb) to pool 0:aa
  Message:     0.1 TOS (transact gas at current prices)
  Wallet fees: 0.05 TOS (upper bound, paid by the wallet on top)
OK request 0a1b2c submitted; the relayer claims it is accepted (message deadbeef)
"""

RELAYED_SPEND_OUTPUT = """
Spend summary:
  Kind:        Transfer, relayed
  To:          descriptor index 1
  Amount:      3 TOS
  Relayer fee: 0.3 TOS (a note to the relayer's descriptor index 0, slot 1, from the notes)
  Inputs:      3 TOS (leaf 2) + 1 TOS (leaf 3)
  Change:      0.7 TOS (back to this instance)
  Anchor:      the current root
  Relayer:     Bond 0:fa via pg6m.onion:80
  Funding:     up to 0.25 TOS from the relayer's wallet, the quoted maximum (the pool's transact fee is 0.01 TOS)
  Quote:       baef52, window ends 2026-11-03 02:05:05 UTC
OK request a1be9b submitted; the relayer claims it is accepted
"""

SYNC_LINE = (
    "OK verified at masterchain 301 (2026-11-03 00:00:00 UTC): 9 transactions replayed "
    "(8 applied, 1 without state change), 2 new notes, 2 notes in all"
)


def note(
    index: int, leaf: int | None, amount: int, kind: str = "ordinary", spent: bool = False
) -> adj.Note:
    return adj.Note(index, leaf, kind, amount, spent)


class ParsingTests(unittest.TestCase):
    def test_amounts_round_trip(self):
        self.assertEqual(nanotos("4.7"), 4_700_000_000)
        self.assertEqual(nanotos("9.979999999"), 9_979_999_999)
        self.assertEqual(tos_text(4_700_000_000), "4.7")
        self.assertEqual(tos_text(10 * TOS), "10")
        with self.assertRaises(LocalnetError):
            nanotos("1.0000000001")

    def test_notes_and_balance(self):
        notes = adj.parse_notes(BALANCE_OUTPUT)
        self.assertEqual([n.leaf for n in notes], [0, 1, 7])
        self.assertEqual(notes[2].kind, "recovery")
        self.assertTrue(notes[2].spent)
        self.assertEqual(notes[2].amount, 9_979_999_999)
        self.assertEqual(adj.parse_balance(BALANCE_OUTPUT), (20 * TOS, 2))

    def test_spend_plan_and_request(self):
        plan = adj.parse_spend_plan(SPEND_OUTPUT)
        self.assertEqual(plan.inputs, [(10 * TOS, 0), (10 * TOS, 1)])
        self.assertEqual(plan.change, 4_700_000_000)
        self.assertEqual(adj.parse_request(SPEND_OUTPUT), ("0a1b2c", "accepted"))

    def test_relayed_spend_plan_names_the_pool_fee_in_its_funding_line(self):
        plan = adj.parse_spend_plan(RELAYED_SPEND_OUTPUT)
        self.assertEqual(plan.inputs, [(3 * TOS, 2), (1 * TOS, 3)])
        self.assertEqual((plan.change, plan.pool_fee), (700_000_000, 10_000_000))
        adj.require_two_real_inputs(plan, 3 * TOS, 300_000_000)
        self.assertEqual(adj.parse_request(RELAYED_SPEND_OUTPUT), ("a1be9b", "accepted"))

    def test_sync_line(self):
        report = adj.parse_sync(SYNC_LINE)
        self.assertTrue(report["verified"])
        self.assertEqual((report["new_notes"], report["notes_in_all"]), (2, 2))
        self.assertFalse(adj.parse_sync(SYNC_LINE.replace("verified", "UNVERIFIED"))["verified"])


class ImportAndSpendTests(unittest.TestCase):
    def test_exactly_one_import_and_its_controls(self):
        before = [note(0, 0, 10 * TOS)]
        after = [*before, note(1, 5, 15 * TOS)]
        imported = adj.require_exactly_one_import(before, after, 15 * TOS, "ordinary")
        self.assertEqual(imported.leaf, 5)
        with self.assertRaisesRegex(adj.Adjudication, "exactly one"):
            adj.require_exactly_one_import(before, before, 15 * TOS, "ordinary")
        two = [*after, note(2, 6, 15 * TOS)]
        with self.assertRaisesRegex(adj.Adjudication, "exactly one"):
            adj.require_exactly_one_import(before, two, 15 * TOS, "ordinary")
        with self.assertRaisesRegex(adj.Adjudication, "carries"):
            adj.require_exactly_one_import(before, after, 14 * TOS, "ordinary")
        with self.assertRaisesRegex(adj.Adjudication, "is a ordinary"):
            adj.require_exactly_one_import(before, after, 15 * TOS, "recovery")

    def test_inputs_spent(self):
        before = [note(0, 0, 10 * TOS), note(1, 1, 10 * TOS)]
        after = [note(0, 0, 10 * TOS, spent=True), note(1, 1, 10 * TOS, spent=True)]
        adj.require_inputs_spent(before, after, [0, 1])
        with self.assertRaisesRegex(adj.Adjudication, "not spent"):
            adj.require_inputs_spent(before, before, [0, 1])
        with self.assertRaisesRegex(adj.Adjudication, "already spent"):
            adj.require_inputs_spent(after, after, [0])

    def test_two_real_inputs(self):
        plan = adj.SpendPlan([(10 * TOS, 0), (10 * TOS, 1)], 4_700_000_000, 0)
        adj.require_two_real_inputs(plan, 15 * TOS, 300_000_000)
        one = adj.SpendPlan([(20 * TOS, 0)], 4_700_000_000, 0)
        with self.assertRaisesRegex(adj.Adjudication, "not two"):
            adj.require_two_real_inputs(one, 15 * TOS, 300_000_000)
        covering = adj.SpendPlan([(16 * TOS, 0), (10 * TOS, 1)], 10_700_000_000, 0)
        with self.assertRaisesRegex(adj.Adjudication, "alone covers"):
            adj.require_two_real_inputs(covering, 15 * TOS, 300_000_000)
        wrong_change = adj.SpendPlan([(10 * TOS, 0), (10 * TOS, 1)], 4 * TOS, 0)
        with self.assertRaisesRegex(adj.Adjudication, "change"):
            adj.require_two_real_inputs(wrong_change, 15 * TOS, 300_000_000)

    def test_withdrawal_plan_charges_the_fee_on_top(self):
        plan = adj.SpendPlan([(15 * TOS, 5)], 4_980_000_000, 20_000_000)
        adj.require_withdrawal_plan(plan, 10 * TOS, 20_000_000)
        with self.assertRaisesRegex(adj.Adjudication, "pool fee"):
            adj.require_withdrawal_plan(plan, 10 * TOS, 30_000_000)
        short = adj.SpendPlan([(15 * TOS, 5)], 5 * TOS, 20_000_000)
        with self.assertRaisesRegex(adj.Adjudication, "change"):
            adj.require_withdrawal_plan(short, 10 * TOS, 20_000_000)


class FeeCreditTests(unittest.TestCase):
    before = [adj.FeeNote("00" * 32, 3)]
    after = [adj.FeeNote("00" * 32, 3), adj.FeeNote("ab" * 32, 9)]

    def credit(self, **over: Any) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema": "tos.relayer.fee-credit.v1",
            "note_key_index": 4,
            "slot": 2,
            "amount": "300000000",
            "transaction": "ab" * 32,
            "leaf_index": 9,
        }
        value.update(over)
        return value

    def check(
        self,
        after: list[adj.FeeNote],
        credits: list[dict[str, Any]],
        *,
        note_key_index: int = 4,
        amount: int = 300_000_000,
    ) -> dict[str, Any]:
        return adj.require_exactly_one_fee_credit(
            self.before,
            after,
            credits,
            note_key_index=note_key_index,
            slot=2,
            amount=amount,
            transaction_hash="ab" * 32,
        )

    def test_exactly_one_fee_credit_and_its_controls(self):
        good = self.credit()
        self.check(self.after, [good])
        with self.assertRaisesRegex(adj.Adjudication, "exactly one new fee note"):
            self.check([*self.after, adj.FeeNote("ab" * 32, 10)], [good])
        with self.assertRaisesRegex(adj.Adjudication, "exactly one new fee note"):
            self.check(self.before, [good])
        with self.assertRaisesRegex(adj.Adjudication, "note key index"):
            self.check(self.after, [good], note_key_index=5)
        with self.assertRaisesRegex(adj.Adjudication, "slot"):
            self.check(self.after, [self.credit(slot=1)])
        with self.assertRaisesRegex(adj.Adjudication, "amount"):
            self.check(self.after, [good], amount=200_000_000)
        with self.assertRaisesRegex(adj.Adjudication, "leaf"):
            self.check(self.after, [self.credit(leaf_index=8)])
        with self.assertRaisesRegex(adj.Adjudication, "one fee-credit record"):
            self.check(self.after, [good, good])


class RecoveryTests(unittest.TestCase):
    before = [note(0, 3, 15 * TOS, spent=True), note(1, 5, 4_980_000_000)]
    template = note(2, None, 0, "recovery")
    recovered = note(2, 8, 9_990_000_000 - 10_000_000, "recovery")

    def bounce(self, **over: Any) -> adj.Bounce:
        base = adj.Bounce("t1", 100, "0:" + "dd" * 32, 9_990_000_000, True)
        return dataclasses.replace(base, **over)

    def recovery(self, bounce: adj.Bounce | None, after: list[adj.Note]) -> adj.Note:
        return adj.require_recovery(
            bounce=bounce,
            payout_destination="0:" + "dd" * 32,
            payout_value=10 * TOS,
            recovery_charge=10_000_000,
            before=self.before,
            after=after,
            prior_leaf_count=8,
        )

    def test_recovery_and_its_controls(self):
        after = [*self.before, self.template, self.recovered]
        self.assertEqual(self.recovery(self.bounce(), after).leaf, 8)
        with self.assertRaisesRegex(adj.Adjudication, "recovery template"):
            self.recovery(self.bounce(), [*self.before, self.recovered])
        with self.assertRaisesRegex(adj.Adjudication, "recovery template"):
            self.recovery(
                self.bounce(), [*self.before, note(2, None, 1, "recovery"), self.recovered]
            )
        with self.assertRaisesRegex(adj.Adjudication, "not the template's"):
            self.recovery(
                self.bounce(), [*self.before, note(3, None, 0, "recovery"), self.recovered]
            )
        with self.assertRaisesRegex(adj.Adjudication, "no bounce"):
            self.recovery(None, after)
        with self.assertRaisesRegex(adj.Adjudication, "not a bounce"):
            self.recovery(self.bounce(bounced=False), after)
        with self.assertRaisesRegex(adj.Adjudication, "destination"):
            self.recovery(self.bounce(source="0:" + "ee" * 32), after)
        with self.assertRaisesRegex(adj.Adjudication, "carries"):
            self.recovery(self.bounce(value=9_980_000_000), after)
        with self.assertRaisesRegex(adj.Adjudication, "exactly one new recovery"):
            self.recovery(self.bounce(), [*self.before, self.template])
        early = [*self.before, self.template, note(2, 4, 9_990_000_000 - 10_000_000, "recovery")]
        with self.assertRaisesRegex(adj.Adjudication, "not after"):
            self.recovery(self.bounce(), early)

    def test_the_later_spend_must_consume_the_recovered_leaf(self):
        both = adj.SpendPlan([(4_980_000_000, 5), (9_980_000_000, 8)], 2_960_000_000, 0)
        adj.require_spends_leaf(both, 8)
        with self.assertRaisesRegex(adj.Adjudication, "recovered leaf"):
            adj.require_spends_leaf(adj.SpendPlan([(4_980_000_000, 5)], 0, 0), 8)


class ProfileRefusalTests(unittest.TestCase):
    GENUINE = "ce3b21bc64e392e14065e68665228bcb10e40dd83836ef00574dd90e5ce057cd"
    PLANTED = "00" * 32
    REFUSAL = f"command failed: the pool's code hash {GENUINE} is not the profile's {PLANTED}\n"

    def test_the_planted_hash_is_refused_against_the_genuine_one(self):
        facts = adj.require_profile_refusal(
            1, self.REFUSAL, planted=self.PLANTED, genuine=self.GENUINE
        )
        self.assertEqual(facts["chain_code_hash"], self.GENUINE)
        self.assertEqual(facts["refused_profile_code_hash"], self.PLANTED)

    def test_an_accepted_profile_is_not_red(self):
        with self.assertRaisesRegex(adj.Adjudication, "accepted"):
            adj.require_profile_refusal(0, "", planted=self.PLANTED, genuine=self.GENUINE)

    def test_an_unrelated_failure_is_not_evidence(self):
        for stderr in (
            "command failed: connection refused by the lite server\n",
            "command failed: the proof verifier exited with status 2\n",
            "",
        ):
            with self.assertRaisesRegex(adj.Adjudication, "not because of the profile's code hash"):
                adj.require_profile_refusal(1, stderr, planted=self.PLANTED, genuine=self.GENUINE)

    def test_a_refusal_of_another_hash_is_not_this_control(self):
        other = "11" * 32
        wrong_profile = self.REFUSAL.replace(self.PLANTED, other)
        with self.assertRaisesRegex(adj.Adjudication, "did not plant"):
            adj.require_profile_refusal(
                1, wrong_profile, planted=self.PLANTED, genuine=self.GENUINE
            )
        wrong_chain = self.REFUSAL.replace(self.GENUINE, other)
        with self.assertRaisesRegex(adj.Adjudication, "not the genuine"):
            adj.require_profile_refusal(1, wrong_chain, planted=self.PLANTED, genuine=self.GENUINE)


class MeasuredCommandTests(unittest.TestCase):
    def test_a_timeout_kills_the_command_and_its_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pid"
            script = (
                "import subprocess, sys\n"
                "child = subprocess.Popen(['sleep', '60'])\n"
                "open(sys.argv[1], 'w').write(str(child.pid))\n"
                "child.wait()\n"
            )
            started = time.monotonic()
            with self.assertRaisesRegex(LocalnetError, "timed out"):
                run_measured([sys.executable, "-c", script, str(pid_file)], timeout=1.0)
            self.assertLess(time.monotonic() - started, 10.0)
            self.assert_gone(int(pid_file.read_text()))

    def test_a_command_that_exits_at_once_but_leaves_a_child_on_its_pipes_times_out(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pid"
            script = (
                "import subprocess, sys\n"
                "child = subprocess.Popen(['sleep', '60'])\n"
                "open(sys.argv[1], 'w').write(str(child.pid))\n"
            )
            started = time.monotonic()
            with self.assertRaisesRegex(LocalnetError, "timed out"):
                run_measured([sys.executable, "-c", script, str(pid_file)], timeout=1.0)
            self.assertLess(time.monotonic() - started, 10.0)
            self.assert_gone(int(pid_file.read_text()))

    def assert_gone(self, pid: int) -> None:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{pid}/status").read_text()
            except FileNotFoundError:
                return
            if "State:\tZ" in state:
                return
            time.sleep(0.05)
        self.fail("the descendant sleep survived the timeout")

    def test_a_finished_command_reports_its_output_and_usage(self):
        completed = run_measured([sys.executable, "-c", "print('out'); raise SystemExit(3)"])
        self.assertEqual(completed.returncode, 3)
        self.assertEqual(completed.stdout, "out\n")
        self.assertGreater(completed.max_rss_kib, 0)


class PayoutTests(unittest.TestCase):
    payout = adj.Payout("t", POOL, 1 * TOS, False, 1_000_000)

    def check(self, payout: adj.Payout | None, amount: int, before: int, after: int) -> None:
        adj.require_public_payout(
            payout=payout, pool=POOL, amount=amount, balance_before=before, balance_after=after
        )

    def test_public_payout_and_its_controls(self):
        self.check(self.payout, 1 * TOS, 5 * TOS, 6 * TOS - 1_000_000)
        with self.assertRaisesRegex(adj.Adjudication, "no payout"):
            self.check(None, 1 * TOS, 0, 0)
        with self.assertRaisesRegex(adj.Adjudication, "carried"):
            self.check(self.payout, 2 * TOS, 5 * TOS, 6 * TOS - 1_000_000)
        with self.assertRaisesRegex(adj.Adjudication, "balance moved"):
            self.check(self.payout, 1 * TOS, 5 * TOS, 6 * TOS)
        other = adj.Payout("t", "0:" + "bb" * 32, 1 * TOS, False, 0)
        with self.assertRaisesRegex(adj.Adjudication, "from the pool"):
            self.check(other, 1 * TOS, 0, 1 * TOS)
        bounced = adj.Payout("t", POOL, 1 * TOS, True, 0)
        with self.assertRaisesRegex(adj.Adjudication, "bounce"):
            self.check(bounced, 1 * TOS, 0, 1 * TOS)


class SocksBoundaryTests(unittest.TestCase):
    def receipt(self, **over: Any) -> dict[str, Any]:
        value: dict[str, Any] = {
            "connection": 1,
            "authenticated": True,
            "isolation_group": 1,
            "target_allowed": True,
            "refused_target": False,
            "endpoint": "/v1/quote",
            "forwarded": True,
            "dropped": False,
        }
        value.update(over)
        return value

    def test_boundary_and_its_controls(self):
        receipts = [self.receipt(), self.receipt(connection=2, endpoint="/v1/submit")]
        summary = adj.require_socks_boundary(receipts, expected_groups=1)
        self.assertEqual(summary["forwarded"], 2)
        with self.assertRaisesRegex(adj.Adjudication, "no connection"):
            adj.require_socks_boundary([], expected_groups=1)
        with self.assertRaisesRegex(adj.Adjudication, "authenticate"):
            adj.require_socks_boundary([self.receipt(authenticated=False)], expected_groups=1)
        with self.assertRaisesRegex(adj.Adjudication, "another target"):
            adj.require_socks_boundary([self.receipt(target_allowed=False)], expected_groups=1)
        with self.assertRaisesRegex(adj.Adjudication, "isolation groups"):
            adj.require_socks_boundary(receipts, expected_groups=2)
        refused = self.receipt(
            connection=3, refused_target=True, target_allowed=False, forwarded=False
        )
        adj.require_socks_boundary([*receipts, refused], expected_groups=1)
        forwarded_anyway = [self.receipt(refused_target=True, forwarded=True)]
        with self.assertRaisesRegex(adj.Adjudication, "refused target was forwarded"):
            adj.require_socks_boundary(forwarded_anyway, expected_groups=1)

    def test_single_submission(self):
        receipts = [
            self.receipt(isolation_group=2, endpoint="/v1/quote"),
            self.receipt(isolation_group=2, endpoint="/v1/submit"),
            self.receipt(isolation_group=2, endpoint="/v1/status"),
        ]
        adj.require_single_submission(receipts, 2)
        twice = [*receipts, self.receipt(isolation_group=2, endpoint="/v1/submit")]
        with self.assertRaisesRegex(adj.Adjudication, "2 submits"):
            adj.require_single_submission(twice, 2)
        with self.assertRaisesRegex(adj.Adjudication, "0 submits"):
            adj.require_single_submission(receipts, 3)

    def test_path_classes_carry_no_identifier(self):
        self.assertEqual(path_class("/v1/status?request=abc&token=secret"), "/v1/status")
        self.assertEqual(path_class("/v1/submit"), "/v1/submit")
        self.assertEqual(path_class("/elsewhere"), "other")
        self.assertIsNone(path_class(None))


class GatedPeerTests(unittest.TestCase):
    """A live peer on loopback: the allowlist refuses before an upstream exists."""

    upstream: socket.socket  # pyright: ignore[reportUninitializedInstanceVariable]
    peer: GatedSocksPeer  # pyright: ignore[reportUninitializedInstanceVariable]
    sockets: list[socket.socket]  # pyright: ignore[reportUninitializedInstanceVariable]

    def setUp(self):
        self.sockets = []
        self.addCleanup(self.close_sockets)
        self.upstream = socket.socket()
        self.upstream.bind(("127.0.0.1", 0))
        self.upstream.listen(1)
        self.upstream.settimeout(2)
        self.peer = GatedSocksPeer(self.upstream.getsockname(), ONION, 80)
        self.peer.client_timeout = self.peer.upstream_timeout = 2.0
        thread = serve(self.peer)
        # Cleanups run last to first: stop accepting, close the sockets the test
        # opened so every handler ends, then join the serving thread.
        self.addCleanup(self.upstream.close)
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.peer.server_close)
        self.addCleanup(self.peer.shutdown)

    def close_sockets(self) -> None:
        for sock in self.sockets:
            sock.close()

    def connect(self, name: str, user: bytes = b"u1", password: bytes = b"p1") -> bytes:
        address = cast(tuple[str, int], self.peer.server_address)
        sock = socket.create_connection(address, timeout=2)
        self.sockets.append(sock)
        sock.sendall(b"\x05\x01\x02")
        self.assertEqual(sock.recv(2), b"\x05\x02")
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        self.assertEqual(sock.recv(2), b"\x01\x00")
        target = bytes([len(name)]) + name.encode() + (80).to_bytes(2, "big")
        sock.sendall(b"\x05\x01\x00\x03" + target)
        # The peer fragments its reply on purpose; read the whole of it.
        reply = bytearray()
        while len(reply) < 10:
            part = sock.recv(10 - len(reply))
            if not part:
                break
            reply.extend(part)
        return bytes(reply)

    def test_other_name_is_refused_before_any_upstream_connection(self):
        reply = self.connect("r" + ONION[1:])
        self.assertEqual(reply[:2], b"\x05\x02")
        with self.assertRaises(TimeoutError):
            self.upstream.accept()
        receipts = self.peer.snapshot()
        self.assertEqual(len(receipts), 1)
        self.assertTrue(receipts[0]["refused_target"])
        self.assertFalse(receipts[0]["forwarded"])
        self.assertFalse(receipts[0]["target_allowed"])
        self.assertFalse(receipts[0]["target_name_known"])
        self.assertNotIn("u1", json.dumps(receipts))
        self.assertNotIn("p1", json.dumps(receipts))

    def test_the_allowed_name_is_admitted_and_credentials_stay_in_memory(self):
        reply = self.connect(ONION, b"alpha", b"beta")
        self.assertEqual(reply[:3], b"\x05\x00\x00")
        # Another credential pair is another isolation group; the same pair the same group.
        self.connect("r" + ONION[1:], b"gamma", b"delta")
        self.connect("r" + ONION[1:], b"alpha", b"beta")
        self.doCleanups()
        receipts = self.peer.snapshot()
        self.assertEqual(len(receipts), 3)
        # Groups are numbered as connections end, so only their equality carries meaning:
        # the admitted connection shares its group with one refused connection.
        admitted = [r["isolation_group"] for r in receipts if r["target_allowed"]]
        refused = [r["isolation_group"] for r in receipts if r["refused_target"]]
        self.assertEqual(len(admitted), 1)
        self.assertEqual(sorted(refused.count(g) for g in set(refused)), [1, 1])
        self.assertEqual(refused.count(admitted[0]), 1)
        self.assertNotIn("alpha", json.dumps(receipts))
        self.assertNotIn("gamma", json.dumps(receipts))


class ConnectionTraceTests(unittest.TestCase):
    TRACE = (
        "1 connect(3, {sa_family=AF_INET, sin_port=htons(9150), "
        'sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
        "2 connect(4, {sa_family=AF_INET, sin_port=htons(34811), "
        'sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
        "2 connect(5, {sa_family=AF_INET, sin_port=htons(33103), "
        'sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
        '1 connect(6, {sa_family=AF_UNIX, sun_path="/run/nscd/socket"}, 110) = -1 ENOENT\n'
    )
    PERMITTED = frozenset({34811, 33103})

    def verdict(self, connects: list[Connect]):
        return adjudicate_connections(
            connects, socks_port=9150, operator_port=34910, permitted_ports=self.PERMITTED
        )

    def test_parse(self):
        connects = parse_connects(self.TRACE)
        self.assertEqual([c.port for c in connects], [9150, 34811, 33103, None])
        self.assertEqual(connects[3].family, "AF_UNIX")
        self.assertEqual(connects[3].address, "/run/nscd/socket")

    def test_adjudication_and_its_controls(self):
        connects = parse_connects(self.TRACE)
        self.assertTrue(self.verdict(connects).passed)
        bypass = self.verdict([*connects, Connect("AF_INET", "127.0.0.1", 34910)])
        self.assertFalse(bypass.passed)
        self.assertIn("direct", bypass.reason)
        foreign = self.verdict([*connects, Connect("AF_INET", "10.0.0.5", 443)])
        self.assertIn("left loopback", foreign.reason)
        stray = self.verdict([*connects, Connect("AF_INET", "127.0.0.1", 8080)])
        self.assertIn("unexpected", stray.reason)
        silent = self.verdict([c for c in connects if c.port != 9150])
        self.assertIn("never reached", silent.reason)


class RedactionTests(unittest.TestCase):
    def test_every_forbidden_value_is_redacted_or_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            receipts = Receipts(Path(directory) / "receipts")
            secrets = {
                "descriptor-r": "QkFTRTY0REVTQ1JJUFRPUkJZVEVT" * 2,
                "status-token": "7f" * 32,
                "mnemonic-s": "tornado nation tortoise cabbage cause render fury wine music",
                "socks-credential": "isolation-user-0123456789abcdef",
                "vault-master-key": "ab" * 32,
            }
            for label, value in secrets.items():
                receipts.add_secret(label, value)
            command = Completed(
                argv=["tosctl", "shield", "send", "--to", secrets["descriptor-r"]],
                returncode=0,
                stdout=f"token {secrets['status-token']} and {secrets['mnemonic-s']}",
                stderr=secrets["vault-master-key"],
                seconds=1.0,
                max_rss_kib=10,
            )
            parsed = {"user": secrets["socks-credential"]}
            receipt = receipts.build("send", command=command, parsed=parsed)
            text = json.dumps(receipt)
            for label, value in secrets.items():
                self.assertNotIn(value, text, label)
                self.assertIn(f"<{label}>", text)
            path = receipts.write(receipt)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            # A secret that reaches a receipt by a route the builder did not see is refused.
            for label, value in secrets.items():
                smuggled = dict(receipt)
                smuggled["facts"] = {"smuggled": value}
                with self.assertRaises(LeakedSecret, msg=label):
                    receipts.write(smuggled)
            with self.assertRaises(LocalnetError):
                receipts.add_secret("short", "abc")


class EvidenceIndexTests(unittest.TestCase):
    def index(self, root: Path) -> dict[str, Any]:
        receipts = root / "receipts"
        receipts.mkdir()
        traces = root / "traces"
        traces.mkdir()
        trace = traces / "01-connect.strace"
        trace.write_text("connect(3, ...)\n")
        step = receipts / "01-setup.json"
        step.write_text(
            json.dumps(
                {
                    "name": "setup",
                    "facts": {
                        "connections": {
                            "passed": True,
                            "trace": trace.name,
                            "trace_sha256": evidence.sha256_file(trace),
                        }
                    },
                }
            )
            + "\n"
        )
        control = receipts / "02-control.json"
        control.write_text('{"name": "control"}\n')
        source = {"commit": "c" * 40, "path": "tools/example"}
        return {
            "schema": evidence.INDEX_SCHEMA,
            "result": "PASS",
            "checked_utc": "2026-11-03T00:00:00+00:00",
            "base_commit": "b" * 40,
            "revisions": {},
            "binaries": {
                **{name: {"sha256": "aa" * 32, "source": source} for name in PROVENANCE_BINARIES},
                "strace": {"sha256": "ab" * 32},
            },
            "chain": {"global_id": 3, "zerostate_root": "11" * 32, "zerostate_file": "22" * 32},
            "pool": {
                "code_hash": "33" * 32,
                "initial_data_hash": "44" * 32,
                "pool_config_hash": "55" * 32,
                "profile_hash": "66" * 32,
                "groth16_vk_hash": "77" * 32,
                "development_verifying_key": False,
            },
            "bond": {},
            "tor": "offline SOCKS peer; transport boundary only",
            "amounts": {},
            "steps": [
                {
                    "name": "setup",
                    "outcome": "PASS",
                    "receipt": "receipts/01-setup.json",
                    "sha256": evidence.sha256_file(step),
                }
            ],
            "controls": [
                {
                    "name": "control",
                    "outcome": "RED",
                    "receipt": "receipts/02-control.json",
                    "sha256": evidence.sha256_file(control),
                }
            ],
            "proving": [],
            "raw_retention_root": str(root),
            "privacy": "index only",
        }

    def write(self, root: Path, index: dict[str, Any]) -> Path:
        """Write the index, then the retention record that retains it and
        every receipt and trace, the way the driver does."""
        path = root / "index.json"
        path.write_text(json.dumps(index))
        files = [
            {
                "path": str(p.relative_to(root)),
                "bytes": p.stat().st_size,
                "sha256": evidence.sha256_file(p),
            }
            for p in sorted(root.rglob("*"))
            if p.is_file() and p.name not in ("index.json", "EVIDENCE-RETENTION.json")
        ]
        retention = {
            "schema": evidence.RETENTION_SCHEMA,
            "index_sha256": evidence.sha256_file(path),
            "files": files,
        }
        (root / "EVIDENCE-RETENTION.json").write_text(json.dumps(retention) + "\n")
        return path

    def test_structure_verified_and_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index = self.index(root)
            path = self.write(root, index)
            self.assertEqual(evidence.verify(path, None), ("structure-only", []))
            self.assertEqual(evidence.verify(path, root), ("verified", []))
            # A flipped receipt digest is refused.
            flipped = json.loads(json.dumps(index))
            flipped["steps"][0]["sha256"] = "00" * 32
            path.write_text(json.dumps(flipped))
            level, problems = evidence.verify(path, root)
            self.assertEqual(level, "structure-only")
            self.assertTrue(any("does not match" in p for p in problems))
            # The retention record retains one index; another is not it.
            path.write_text(json.dumps(index) + " ")
            level, problems = evidence.verify(path, root)
            self.assertEqual(level, "structure-only")
            self.assertTrue(any("does not retain this index" in p for p in problems))
            self.write(root, index)
            # A missing retained file is never verified.
            (root / "receipts/01-setup.json").unlink()
            level, problems = evidence.verify(path, root)
            self.assertEqual(level, "structure-only")
            self.assertTrue(any("missing" in p for p in problems))

    def test_connection_traces_are_verified_with_the_receipts_that_cite_them(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index = self.index(root)
            path = self.write(root, index)
            self.assertEqual(evidence.verify(path, root), ("verified", []))
            trace = root / "traces/01-connect.strace"
            original = trace.read_bytes()
            # A tampered trace fails both the receipt's citation and the record.
            trace.write_bytes(original + b"connect(4, ...)\n")
            level, problems = evidence.verify(path, root)
            self.assertEqual(level, "structure-only")
            self.assertTrue(
                any("cited trace 01-connect.strace does not match" in p for p in problems)
            )
            self.assertTrue(any("traces/01-connect.strace does not match" in p for p in problems))
            # A deleted trace fails them too.
            trace.unlink()
            level, problems = evidence.verify(path, root)
            self.assertEqual(level, "structure-only")
            self.assertTrue(any("cited trace 01-connect.strace is missing" in p for p in problems))
            self.assertTrue(any("traces/01-connect.strace is missing" in p for p in problems))
            trace.write_bytes(original)
            # A trace the record does not retain is reported.
            (root / "traces/02-connect.strace").write_text("connect(5, ...)\n")
            level, problems = evidence.verify(path, root)
            self.assertEqual(level, "structure-only")
            self.assertTrue(any("not retained by the record" in p for p in problems))
            (root / "traces/02-connect.strace").unlink()
            # A receipt whose verdict cites no trace is refused.
            receipt = root / "receipts/01-setup.json"
            facts = json.loads(receipt.read_text())
            del facts["facts"]["connections"]["trace_sha256"]
            receipt.write_text(json.dumps(facts) + "\n")
            index["steps"][0]["sha256"] = evidence.sha256_file(receipt)
            path = self.write(root, index)
            level, problems = evidence.verify(path, root)
            self.assertTrue(any("cites no trace" in p for p in problems))

    def test_structural_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            index = self.index(Path(directory))
            cases: list[tuple[str, str]] = [
                ('["steps"][0]["outcome"] = "FAIL"', "PASS with failed steps"),
                ('["controls"][0]["outcome"] = "GREEN"', "did not go red"),
                ('["pool"]["development_verifying_key"] = True', "ceremony key"),
                ('["binaries"]["tosctl"]["source"] = {"commit": "c" * 40}', "which commit"),
                ('["binaries"]["tosctl"].pop("source")', "which commit"),
                ('["binaries"]["tosctl"]["source"]["commit"] = "x" * 40', "which commit"),
                ('["binaries"]["tosctl"]["source"]["commit"] = "C" * 40', "which commit"),
                ('["base_commit"] = "x" * 40', "full commit id"),
                ('["binaries"]["strace"]["source"] = {"commit": "c" * 40}', "which commit"),
                ('["binaries"].pop("tos-proof-verify")', "missing from the index"),
                ('["chain"]["global_id"] = 2', "isolated local network"),
                ('["tor"] = "real Tor"', "offline"),
                ('["schema"] = "other"', "schema"),
            ]
            for assignment, expect in cases:
                broken: dict[str, Any] = json.loads(json.dumps(index))
                exec(f"broken{assignment}", {"broken": broken})  # noqa: S102 - test-local literal
                problems = evidence.check_structure(broken)
                self.assertTrue(any(expect in p for p in problems), (expect, problems))


if __name__ == "__main__":
    unittest.main()
