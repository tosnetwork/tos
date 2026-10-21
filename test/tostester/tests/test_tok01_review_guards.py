"""Receipt guard tests use synthetic public cells, not a claim of native execution."""

import asyncio
import base64
import copy
import importlib.util
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pytosiq_core import Cell, begin_cell

ROOT = Path(__file__).resolve().parents[3]
ACCOUNT = "0:" + "11" * 32
OTHER_ACCOUNT = "0:" + "22" * 32


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/{name}.py")
    assert spec is not None and spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


oracle = module("tok01-oracle")
lifecycle = module("tok01-lifecycle")


def transaction(message_hash, exit_code=0):
    return {
        "data": base64.b64encode(Cell.empty().to_boc()).decode(),
        "transaction_id": {"hash": base64.b64encode(Cell.empty().hash).decode(), "lt": "10"},
        "block_id": dict.fromkeys(("root_hash", "file_hash", "seqno", "workchain", "shard"), 0),
        "in_msg": {"hash": message_hash, "source": ACCOUNT},
        "compute": {"exit_code": exit_code},
        "aborted": exit_code != 0,
        "action": {"success": True} if exit_code == 0 else None,
    }


@pytest.fixture
def records():
    field = {"getter": 1, "rpc_or_expected": 1, "pass": True, "field": "synthetic"}
    steps = []
    for index, name in enumerate(oracle.REQUIRED_STEPS):
        tx = transaction(f"message-{index}", oracle.EXPECTED_EXIT.get(name, 0))
        steps.append(
            {
                "step": name,
                "target": copy.deepcopy(tx),
                "message_hash": f"message-{index}",
                "destination": "account",
                "expected_exit": oracle.EXPECTED_EXIT.get(name, 0),
                "transactions": {"account": [copy.deepcopy(tx)]},
                "comparisons": [field],
            }
        )
    head = "ab" * 20
    return {
        "provenance.json": {
            "run_id": "run-1",
            "source_head": head,
            "source_head_after": head,
            "completed": True,
            "global_id": 3,
        },
        "summary.jsonl": [
            {
                "run_id": "run-1",
                "pass": True,
                "failures": [],
                "steps": list(oracle.REQUIRED_STEPS),
            }
        ],
        "steps.jsonl": steps,
        "checks.jsonl": [field],
        "invariants.jsonl": [
            {
                "step": name,
                "supply": 1,
                "expected_supply": 1,
                "balances": [1],
                "sum": 1,
                "pass": True,
            }
            for name in oracle.REQUIRED_STEPS
        ],
        "bounce.jsonl": [
            {
                "incoming": 1,
                "returned": 1,
                "transaction_fees": 0,
                "storage_fees_from_existing_balance": 0,
                "forwarding_remainder": 0,
                "checks": [field, field],
            }
            for _ in range(2)
        ],
        "notifications.jsonl": [{"transactions": [steps[0]["target"]["transaction_id"]]}],
    }


def test_complete_receipt(records):
    assert oracle.verify(None, records)["pass"]


@pytest.mark.parametrize("where", ["steps.jsonl", "summary.jsonl", "invariants.jsonl"])
@pytest.mark.parametrize("change", ["duplicate", "replace", "reorder"])
def test_exact_step_coverage(records, where, change):
    assert oracle.verify(None, records)["pass"]
    rows = records[where][0]["steps"] if where == "summary.jsonl" else records[where]
    if change == "reorder":
        rows[7], rows[8] = rows[8], rows[7]
    elif change == "duplicate":
        rows[8] = copy.deepcopy(rows[7])
    elif where == "summary.jsonl":
        rows[8] = "replacement"
    else:
        rows[8]["step"] = "replacement"
    with pytest.raises(AssertionError, match="steps"):
        oracle.verify(None, records)


@pytest.mark.parametrize("change", ["empty", "removed", "unrelated", "destination", "bad_target"])
def test_destination_transaction_required(records, change):
    assert oracle.verify(None, records)["pass"]
    step = records["steps.jsonl"][8]
    if change == "empty":
        step["transactions"]["account"] = []
    elif change == "removed":
        step["transactions"] = {}
    elif change == "unrelated":
        step["transactions"]["account"][0]["transaction_id"]["hash"] = base64.b64encode(
            bytes(32)
        ).decode()
    elif change == "destination":
        step["destination"] = "another account"
    else:
        step["target"]["transaction_id"]["hash"] = base64.b64encode(bytes(32)).decode()
    with pytest.raises(AssertionError, match="transaction"):
        oracle.verify(None, records)


def test_target_must_consume_the_step_message(records):
    assert oracle.verify(None, records)["pass"]
    # A retained transaction that is not the one the step's message produced (a bounce,
    # an unrelated inbound message) cannot stand in as the receipt.
    records["steps.jsonl"][3]["message_hash"] = "a later unrelated message"
    with pytest.raises(AssertionError, match="consume the step's message"):
        oracle.verify(None, records)


@pytest.mark.parametrize(
    "change,reason",
    [
        ("runner_expected", "runner expected outcome"),
        ("compute_exit", "compute exit"),
        ("aborted", "aborted flag"),
        ("action", "action phase failed"),
        ("summary_hides_refusal", "compute exit"),
    ],
)
def test_outcomes_checked_against_the_contract_not_the_summary(records, change, reason):
    assert oracle.verify(None, records)["pass"]
    refused = records["steps.jsonl"][7]
    assert refused["step"] == "insufficient balance"
    first = records["steps.jsonl"][0]
    if change == "runner_expected":
        refused["expected_exit"] = 0
    elif change == "compute_exit":
        first["target"]["compute"]["exit_code"] = 1
    elif change == "aborted":
        first["target"]["aborted"] = True
    elif change == "action":
        first["target"]["action"] = {"success": False}
    else:
        # The runner's summary still says pass while the chain refused the deploy.
        first["target"]["compute"]["exit_code"] = 706
        first["target"]["aborted"] = True
    # The runner retains the same transaction under the destination account.
    first["transactions"]["account"][0] = copy.deepcopy(first["target"])
    with pytest.raises(AssertionError, match=reason):
        oracle.verify(None, records)


@pytest.mark.parametrize(
    "change,reason",
    [
        ("missing", "provenance missing"),
        ("incomplete", "did not complete"),
        ("head_changed", "source head changed"),
        ("not_a_commit", "not a commit"),
        ("other_run", "does not belong to this run"),
        ("no_network", "network identity missing"),
    ],
)
def test_provenance_binds_the_evidence(records, change, reason):
    assert oracle.verify(None, records)["pass"]
    provenance = records["provenance.json"]
    if change == "missing":
        records["provenance.json"] = None
    elif change == "incomplete":
        provenance["completed"] = False
    elif change == "head_changed":
        provenance["source_head_after"] = "0" * 40
    elif change == "not_a_commit":
        provenance["source_head"] = provenance["source_head_after"] = "dirty"
    elif change == "other_run":
        provenance["run_id"] = "run-2"
    else:
        del provenance["global_id"]
    with pytest.raises(AssertionError, match=reason):
        oracle.verify(None, records)


def test_red_control_must_fail_for_its_stated_reason():
    def validate(row):
        oracle.require(row["ok"], "a different reason")

    receipts = []
    oracle.exercise(
        receipts, "stated", {"ok": True}, validate, lambda row: row.update(ok=False), "different"
    )
    assert receipts[0]["control"] == "stated"
    with pytest.raises(AssertionError, match="another reason"):
        oracle.exercise(
            receipts,
            "misstated",
            {"ok": True},
            validate,
            lambda row: row.update(ok=False),
            "expected",
        )
    with pytest.raises(AssertionError, match="did not turn red"):
        oracle.exercise(receipts, "inert", {"ok": True}, validate, lambda row: None, "different")


def test_select_target_by_inbound_message_hash():
    wanted = {"transaction_id": {"lt": "11"}, "in_msg": {"hash": "step message"}}
    bounce = {"transaction_id": {"lt": "12"}, "in_msg": {"hash": "bounce"}}
    unrelated = {"transaction_id": {"lt": "13"}, "in_msg": {"hash": "someone else"}}
    assert lifecycle.select_target([bounce, unrelated, wanted], "step message") is wanted
    assert lifecycle.select_target([bounce, unrelated], "step message") is None
    assert lifecycle.select_target([{"transaction_id": {"lt": "14"}}], "step message") is None
    with pytest.raises(RuntimeError, match="several transactions"):
        lifecycle.select_target([wanted, copy.deepcopy(wanted)], "step message")


def test_outgoing_message_hash_selects_the_destination():
    sender_transactions = [
        {"out_msgs": [{"destination": OTHER_ACCOUNT, "hash": "elsewhere"}]},
        {
            "out_msgs": [
                {"destination": "", "hash": "external"},
                {"destination": ACCOUNT, "hash": "ours"},
            ]
        },
    ]
    assert lifecycle.outgoing_message_hash(sender_transactions, ACCOUNT) == "ours"
    assert lifecycle.outgoing_message_hash(sender_transactions[:1], ACCOUNT) is None
    assert lifecycle.outgoing_message_hash([{"out_msgs": []}], ACCOUNT) is None
    with pytest.raises(RuntimeError, match="several messages"):
        lifecycle.outgoing_message_hash(sender_transactions * 2, ACCOUNT)


def test_endpoint_network_guard():
    assert lifecycle.check_global_id(3, {3}) == 3
    with pytest.raises(RuntimeError, match="not in the allowed set"):
        lifecycle.check_global_id(1, {3})
    with pytest.raises(RuntimeError, match="not in the allowed set"):
        lifecycle.check_global_id(2, set())
    param = base64.b64encode(begin_cell().store_int(-7, 32).end_cell().to_boc()).decode()
    assert lifecycle.decode_global_id(param) == -7
    trailing = base64.b64encode(
        begin_cell().store_int(3, 32).store_uint(1, 1).end_cell().to_boc()
    ).decode()
    with pytest.raises(RuntimeError, match="trailing data"):
        lifecycle.decode_global_id(trailing)


def test_signer_adapter_is_bounded_by_a_deadline():
    killed = []

    class Process:
        returncode = None

        async def communicate(self, _data):
            await asyncio.Event().wait()

        def kill(self):
            killed.append(True)

        async def wait(self):
            return 0

    async def spawn(*_args, **_kwargs):
        return Process()

    message = SimpleNamespace(send_mode=3, message=SimpleNamespace(serialize=Cell.empty))
    send = lifecycle.make_sender("signer-adapter", 0.05)
    with patch.object(lifecycle.asyncio, "create_subprocess_exec", spawn):
        with pytest.raises(TimeoutError, match="did not answer"):
            asyncio.run(send(ACCOUNT, message))
    assert killed == [True]


def test_snapshot_requires_deployed_contracts_to_stay_active():
    harness = object.__new__(lifecycle.Harness)
    harness.master = ACCOUNT
    harness.collection = OTHER_ACCOUNT
    harness.item = None
    harness.expected_active = {lifecycle.raw(ACCOUNT)}
    with patch.object(harness, "rpc", return_value="uninit"):
        with pytest.raises(AssertionError, match="token master active after NFT mint"):
            asyncio.run(harness.snapshot("NFT mint"))


@pytest.mark.parametrize("staged", [False, True])
def test_dirty_source_refused(tmp_path, staged):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path, text=True).strip()

    git("init", "-q")
    source = tmp_path / "source.py"
    source.write_text("original\n")
    git("add", "source.py")
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "Fixture",
    )
    head = lifecycle.clean_source_head(tmp_path)
    assert head == git("rev-parse", "HEAD")
    source.write_text("changed\n")
    if staged:
        git("add", "source.py")
    with pytest.raises(RuntimeError, match="clean tracked source tree"):
        lifecycle.clean_source_head(tmp_path)
    git("restore", "--source=HEAD", "--staged", "--worktree", "source.py")
    assert lifecycle.clean_source_head(tmp_path) == head


@pytest.mark.parametrize("method,key", [("getAccountTokens", "tokens"), ("getAccountNfts", "nfts")])
@pytest.mark.parametrize(
    "status", [{}, {"index_state": {"complete": False}}, {"index_state": {"complete": "true"}}]
)
def test_incomplete_index_never_means_absent(method, key, status):
    harness = object.__new__(lifecycle.Harness)
    owner = ACCOUNT
    incomplete = {key: [], **status}
    complete = {key: [], "index_state": {"complete": True}}

    async def wait(predicate):
        assert predicate() is None, "incomplete index accepted"
        assert predicate() == complete
        return complete

    with (
        patch.object(harness, "rpc", side_effect=[incomplete, complete]),
        patch.object(harness, "wait", wait),
    ):
        assert asyncio.run(harness.complete_index(method, owner)) == complete


def test_permanently_incomplete_index_fails():
    harness = object.__new__(lifecycle.Harness)

    async def wait(predicate):
        assert predicate() is None
        raise TimeoutError("index did not complete")

    with (
        patch.object(
            harness, "rpc", return_value={"tokens": [], "index_state": {"complete": False}}
        ),
        patch.object(harness, "wait", wait),
    ):
        with pytest.raises(TimeoutError, match="index did not complete"):
            asyncio.run(harness.complete_index("getAccountTokens", ACCOUNT))
