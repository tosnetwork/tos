"""Crash-boundary tests for the real candidate driver, with a fake transport.

The driver builds real stake BOCs. Wallet/TL-B correlation is covered separately
by test_local_pq_transactions and test_local_pq_election_evidence, not mocked here
and misrepresented as a live chain.
"""
import asyncio
import base64
import importlib.util
from pathlib import Path
from types import SimpleNamespace as Obj

import pytest
from pytosiq_core import Cell

from local_pq_test_wire import address
from local_pq_transactions import read_json

SPEC = importlib.util.spec_from_file_location(
    "resume_elections", Path(__file__).with_name("local-pq-elections.py")
)
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)
NANO = 10**9
ELECTION = 1791257021
QUERY = (1 << 63) + 1
NETWORK = dict(global_id=3, zerostate_root="aa" * 32)
CANDIDATE = dict(controller=address(3).to_str(is_user_friendly=False),
                 adnl_id="04" * 32, key_id="05" * 32, public_key="06" * 1312,
                 witness_b64=base64.b64encode(Cell.empty().to_boc()).decode())
ACCEPTED = dict(kind="accepted", reply=[0xF374484C, 0])


class Transport:
    def __init__(self, directory, pool_balance=11020 * NANO):
        self.directory = directory
        self.pool_balance = pool_balance
        self.records = {}
        self.payments = []
        self.crash_after = None
        self.wallet = Obj(address=address(1))

    async def raw_get_account_state(self, account):
        return Obj(balance=self.pool_balance, last_transaction_id=Obj(lt=0, hash=bytes(32)))

    def record(self, label):
        return self.records.get(label)

    async def transfer(self, label, dest, amount, body=None):
        # Even the first capital send must be preceded by durable business intent.
        intent = read_json(self.directory / "candidate-intent-1.json")
        assert intent["state"] == "prepared"
        if label not in self.records:
            self.payments.append((label, amount, body.hash if body else None))
            self.records[label] = dict(label=label, ok=True, exit_code=0, action_code=None)
        if self.crash_after == label:
            self.crash_after = None
            raise OSError("crash after payment inclusion")
        return self.records[label]


@pytest.fixture
def harness(tmp_path, monkeypatch):
    monkeypatch.setattr(driver, "OUT", tmp_path)
    pool = Obj(address=address(2))
    transport = Transport(tmp_path)
    observed = dict(funding=0, authorization=0, evidence=0, fail_evidence=False)

    async def funding(*args, **kwargs):
        observed["funding"] += 1

    async def lite(*args, **kwargs):
        return QUERY

    async def history(*args, **kwargs):
        return []

    def result(*args, **kwargs):
        observed["evidence"] += 1
        if observed["fail_evidence"]:
            observed["fail_evidence"] = False
            raise OSError("crash before business receipt persistence")
        return ACCEPTED.copy()

    class Request:
        def __init__(self, **kwargs):
            pass

        def parse_result(self, response):
            return response

    class Console:
        async def request_with_raw(self, request):
            observed["authorization"] += 1
            auth = Obj(validator_id=address(3).hash_part, key_id=bytes.fromhex("05" * 32),
                       public_key=bytes.fromhex("06" * 1312), algorithm_id=1,
                       signature=b"\x07" * 2420)
            return auth, b"", b"{}"

    monkeypatch.setattr(driver, "ensure_operations", funding)
    monkeypatch.setattr(driver, "lite_int", lite)
    monkeypatch.setattr(driver, "history_since", history)
    monkeypatch.setattr(driver, "election_result", result)
    monkeypatch.setattr(driver.tos_api, "Engine_validator_createPqStakeAuthorizationRequest", Request)

    def run(election=ELECTION, network=NETWORK):
        return asyncio.run(driver.submit_candidate(transport, transport, Console(),
                                                   CANDIDATE, pool, election, 1, network))
    return transport, observed, run


def test_completed_candidate_is_not_paid_again_after_partial_round(harness):
    transport, observed, run = harness
    assert run() == run() == ACCEPTED
    assert len(transport.payments) == 1
    assert observed == dict(funding=1, authorization=1, evidence=1, fail_evidence=False)


@pytest.mark.parametrize("boundary", ["capital", "stake", "receipt"])
def test_crash_never_adds_another_payment_or_authorization(harness, boundary):
    transport, observed, run = harness
    transport.pool_balance = 11000 * NANO
    if boundary == "receipt":
        observed["fail_evidence"] = True
    else:
        label = "pool-capital" if boundary == "capital" else "stake"
        transport.crash_after = f"{label}-{ELECTION}-1"
    with pytest.raises(OSError):
        run()
    assert run() == ACCEPTED
    assert len(transport.payments) == 2
    assert transport.payments[0][1] == 20 * NANO  # only the deficit
    assert observed["funding"] == observed["authorization"] == 1


def test_old_broadcast_is_reconciled_before_the_next_round(harness):
    transport, observed, run = harness
    observed["fail_evidence"] = True
    with pytest.raises(OSError):
        run()
    assert run(ELECTION + 600) == ACCEPTED
    assert observed["evidence"] == 3
    assert len(transport.payments) == 2
    assert (transport.directory / f"intent-history-{ELECTION}-1.json").exists()


def test_chain_identity_mismatch_never_sends(harness):
    transport, _, run = harness
    run()
    with pytest.raises(ValueError, match="different chain"):
        run(network=dict(NETWORK, zerostate_root="bb" * 32))
    assert len(transport.payments) == 1


def test_persisted_refusal_is_not_repaid(harness, monkeypatch):
    transport, _, run = harness
    refusal = dict(kind="controller_bounced", exit_code=180, action_code=None)
    monkeypatch.setattr(driver, "election_result", lambda *args, **kwargs: refusal.copy())
    assert run() == run() == refusal
    assert len(transport.payments) == 1
