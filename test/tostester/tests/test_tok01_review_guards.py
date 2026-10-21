"""Receipt guard tests use synthetic records and retained public cells, not native evidence."""

import asyncio
import base64
import copy
import importlib.util
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pytosiq_core import Cell, begin_cell

ROOT = Path(__file__).resolve().parents[3]
ACCOUNT = "0:" + "11" * 32
OTHER_ACCOUNT = "0:" + "22" * 32
OWNERS = [ACCOUNT, OTHER_ACCOUNT, "0:" + "33" * 32]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/{name}.py")
    assert spec is not None and spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


oracle = module("tok01-oracle")
lifecycle = module("tok01-lifecycle")
fixture_transactions = module("../test/tostester/tests/tok01_fixture_transactions")


def rendered(data, exit_code) -> dict[str, Any]:
    """A retained transaction as the runner stores it: the BOC plus the RPC rendering of it."""
    edges = oracle.decoded_edges({"data": data})
    return {
        "data": data,
        "transaction_id": {
            "hash": base64.b64encode(Cell.one_from_boc(base64.b64decode(data)).hash).decode(),
            "lt": "10",
        },
        "block_id": dict.fromkeys(("root_hash", "file_hash", "seqno", "workchain", "shard"), 0),
        "in_msg": {"hash": edges["in_msg"]},
        "out_msgs": [{"hash": h, "destination": d} for h, d in edges["out_msgs"]],
        "compute": {"exit_code": exit_code},
        "aborted": exit_code != 0,
        "action": {"success": True} if exit_code == 0 else None,
    }


def comparison_rows(name, destination):
    """Synthetic comparisons shaped like the runner's complete per-step output."""
    fields = [
        "total_supply",
        "mintable",
        "admin_address",
        "token_content",
        "token_wallet_code",
        "expected supply",
        "expected admin",
        "supply equals wallet sum",
    ]
    for owner in OWNERS:
        fields.extend(
            [
                "expected balance " + owner,
                "nonnegative balance",
                "indexed wallet",
                "wallet owner",
                "wallet master",
                "wallet code",
            ]
        )
    if name != "token deploy":
        fields.extend(["collection next index", "collection owner", "collection metadata"])
    if name.startswith("NFT "):
        fields.extend(
            [
                "item initialized",
                "item index",
                "item collection",
                "item owner",
                "expected NFT owner",
                "item metadata",
                "NFT indexed collection",
            ]
        )
        fields.extend("NFT owner index " + owner for owner in OWNERS)
    if name == "transfer payload notification":
        fields.extend(
            [
                "notification query",
                "notification amount",
                "notification from",
                "notification payload marker",
                "notification payload",
                "notification source",
                "notification count",
            ]
        )
    if name in ("insufficient balance", "NFT non-owner refused"):
        fields.extend(
            [
                "refused operation persistent data " + destination,
                "bounce value conservation",
                "bounce receipt count",
            ]
        )
    return [{"getter": 1, "rpc_or_expected": 1, "pass": True, "field": f} for f in fields]


def step_record(name) -> dict[str, Any]:
    """One lifecycle step built from the retained sender and target pair of its outcome."""
    exit_code = oracle.EXPECTED_EXIT.get(name, 0)
    real = fixture_transactions.STEPS[exit_code]
    target = rendered(real["target_tx"], exit_code)
    return {
        "step": name,
        "target": copy.deepcopy(target),
        "sender": real["sender"],
        "message_hash": real["message_hash"],
        "destination": real["destination"],
        "expected_exit": exit_code,
        "transactions": {
            real["destination"]: [copy.deepcopy(target)],
            real["sender"]: [rendered(real["sender_tx"], 0)],
        },
        "comparisons": comparison_rows(name, real["destination"]),
    }


@pytest.fixture
def records():
    field = {"getter": 1, "rpc_or_expected": 1, "pass": True, "field": "synthetic"}
    steps = [step_record(name) for name in oracle.REQUIRED_STEPS]
    head = "ab" * 20
    return {
        "provenance.json": {
            "run_id": "run-1",
            "source_head": head,
            "source_head_after": head,
            "completed": True,
            "global_id": 3,
            "owners": OWNERS,
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
        "checks.jsonl": [
            dict(row, step=step["step"]) for step in steps for row in step["comparisons"]
        ],
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


def test_comparison_red_controls_fail_for_their_stated_reasons(records):
    receipts = []
    original = copy.deepcopy(records)
    oracle.comparison_controls(
        records,
        lambda name, baseline, validate, mutate, reason: oracle.exercise(
            receipts, name, baseline, validate, mutate, reason
        ),
    )
    assert len(receipts) == 7
    assert all(row["baseline_exit"] == row["restored_exit"] == 0 for row in receipts)
    assert all(row["mutant_exit"] == 1 for row in receipts)
    assert records == original


@pytest.mark.parametrize(
    "change,reason",
    [
        ("empty_checks", "missing comparison receipts"),
        ("missing_step_checks", "comparison receipts differ"),
        ("empty_step_comparisons", "missing getter/RPC comparisons"),
        ("missing_one_check", "comparison receipts differ"),
    ],
)
def test_comparison_receipts_cannot_be_missing(records, change, reason):
    assert oracle.verify(None, records)["pass"]
    if change == "empty_checks":
        records["checks.jsonl"] = []
    elif change == "missing_step_checks":
        records["checks.jsonl"] = [r for r in records["checks.jsonl"] if r["step"] != "burn"]
    elif change == "empty_step_comparisons":
        records["steps.jsonl"][8]["comparisons"] = []
    else:
        records["checks.jsonl"].pop()
    with pytest.raises(AssertionError, match=reason):
        oracle.verify(None, records)


@pytest.mark.parametrize("where", ["step", "checks", "both"])
@pytest.mark.parametrize(
    "change,reason", [("value", "field mismatch"), ("flag", "field marked failed")]
)
def test_failed_comparison_receipts_are_rejected(records, where, change, reason):
    assert oracle.verify(None, records)["pass"]
    rows = []
    if where in ("step", "both"):
        rows.append(records["steps.jsonl"][8]["comparisons"][0])
    if where in ("checks", "both"):
        rows.append(next(r for r in records["checks.jsonl"] if r["step"] == "burn"))
    for row in rows:
        if change == "value":
            row["getter"] = 999
        else:
            row["pass"] = False
    with pytest.raises(AssertionError, match=reason):
        oracle.verify(None, records)


@pytest.mark.parametrize(
    "change", ["checks_value", "step_value", "field", "step", "order", "duplicate"]
)
def test_comparison_records_must_agree(records, change):
    assert oracle.verify(None, records)["pass"]
    if change == "checks_value":
        records["checks.jsonl"][0].update(getter=2, rpc_or_expected=2)
    elif change == "step_value":
        records["steps.jsonl"][0]["comparisons"][0].update(getter=2, rpc_or_expected=2)
    elif change == "field":
        records["checks.jsonl"][0]["field"] = "another valid-looking field"
    elif change == "step":
        records["checks.jsonl"][0]["step"] = "burn"
    elif change == "order":
        records["checks.jsonl"][0:2] = records["checks.jsonl"][1::-1]
    else:
        records["checks.jsonl"].append(copy.deepcopy(records["checks.jsonl"][-1]))
    with pytest.raises(AssertionError, match="comparison receipts differ"):
        oracle.verify(None, records)


@pytest.mark.parametrize(
    "step_name,field",
    [
        ("burn", "total_supply"),
        ("collection deploy", "collection metadata"),
        ("NFT transfer", "expected NFT owner"),
        ("transfer payload notification", "notification payload"),
        ("insufficient balance", "bounce receipt count"),
    ],
)
def test_required_comparison_cannot_be_deleted_from_both_records(records, step_name, field):
    assert oracle.verify(None, records)["pass"]
    step = next(s for s in records["steps.jsonl"] if s["step"] == step_name)
    step["comparisons"] = [r for r in step["comparisons"] if r["field"] != field]
    records["checks.jsonl"] = [
        r for r in records["checks.jsonl"] if (r["step"], r["field"]) != (step_name, field)
    ]
    with pytest.raises(AssertionError, match="required comparison missing or duplicated"):
        oracle.verify(None, records)


@pytest.mark.parametrize("owners", [None, [], OWNERS[:2], [OWNERS[0]] * 3])
def test_comparison_coverage_requires_three_distinct_owners(records, owners):
    assert oracle.verify(None, records)["pass"]
    records["provenance.json"]["owners"] = owners
    with pytest.raises(AssertionError, match="comparison owners missing or invalid"):
        oracle.verify(None, records)


@pytest.mark.parametrize(
    "field,reason",
    [
        ("nonnegative balance", "wallet balance comparisons missing"),
        ("indexed wallet", "wallet index comparisons missing"),
        ("wallet code", "wallet identity comparisons missing"),
    ],
)
def test_wallet_comparison_coverage_cannot_be_shortened_in_both_records(records, field, reason):
    assert oracle.verify(None, records)["pass"]
    rows = records["steps.jsonl"][8]["comparisons"]
    rows.pop(next(i for i, row in enumerate(rows) if row["field"] == field))
    records["checks.jsonl"] = [
        dict(row, step=step["step"])
        for step in records["steps.jsonl"]
        for row in step["comparisons"]
    ]
    with pytest.raises(AssertionError, match=reason):
        oracle.verify(None, records)


def test_required_comparison_cannot_be_duplicated_in_both_records(records):
    assert oracle.verify(None, records)["pass"]
    rows = records["steps.jsonl"][8]["comparisons"]
    rows.append(copy.deepcopy(rows[0]))
    records["checks.jsonl"] = [
        dict(row, step=step["step"])
        for step in records["steps.jsonl"]
        for row in step["comparisons"]
    ]
    with pytest.raises(AssertionError, match="required comparison missing or duplicated"):
        oracle.verify(None, records)


@pytest.mark.parametrize(
    "label,exit_code",
    [
        ("token deploy", 0),
        ("transfer payload notification", 0),
        ("insufficient balance", 706),
    ],
)
def test_runner_persists_all_comparisons_in_both_records(tmp_path, label, exit_code):
    real = fixture_transactions.STEPS[exit_code]
    target = rendered(real["target_tx"], exit_code)
    owners = [real["sender"], OTHER_ACCOUNT, OWNERS[2]]
    harness = lifecycle.Harness("unused", tmp_path / "evidence", AsyncMock(), owners)
    harness.master = real["destination"]
    harness.collection = ACCOUNT
    harness.lt = lambda _account: 0
    harness.rpc = lambda method, **_params: (
        {"data": "unchanged"} if method == "getAddressInformation" else {"last": {"seqno": 10}}
    )
    harness.transfer = AsyncMock()
    harness.wait = AsyncMock(side_effect=[real["message_hash"], target, True])
    transactions = {
        real["destination"]: [target],
        real["sender"]: [rendered(real["sender_tx"], 0)],
    }
    harness.new_transactions = lambda account, _before: transactions.get(account, [])

    async def snapshot(_label):
        return [harness.compare("snapshot field", 1, 1)]

    async def extra(_target):
        harness.compare("extra callback field", 2, 2)

    harness.snapshot = snapshot
    harness.notification = lambda _transactions: harness.compare("notification field", 3, 3)
    harness.bounce_accounting = lambda *_args: harness.compare("bounce field", 4, 4)
    with patch.object(lifecycle.asyncio, "sleep", AsyncMock()):
        asyncio.run(
            harness.step(
                label,
                real["sender"],
                real["destination"],
                Cell.empty(),
                expected_exit=exit_code,
                extra=extra,
            )
        )
    checks = oracle.load(harness.output, "checks.jsonl")
    (step,) = oracle.load(harness.output, "steps.jsonl")
    assert checks == [dict(row, step=label) for row in step["comparisons"]]
    fields = [row["field"] for row in step["comparisons"]]
    assert "snapshot field" in fields and "extra callback field" in fields
    if exit_code:
        assert "bounce field" in fields
        assert "refused operation persistent data " + real["destination"] in fields
    if label == "transfer payload notification":
        assert "notification field" in fields
    assert not harness.failures


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
    retained = step["transactions"][step["destination"]]
    if change == "empty":
        retained.clear()
    elif change == "removed":
        step["transactions"] = {}
    elif change == "unrelated":
        retained[0]["transaction_id"]["hash"] = base64.b64encode(bytes(32)).decode()
    elif change == "destination":
        step["destination"] = OTHER_ACCOUNT
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
        ("fabricated_sender_edge", "RPC message rendering disagrees"),
        ("relabelled_target", "consume the step's message"),
        ("target_of_another_account", "belongs to another account"),
        ("sender_of_another_account", "sender transaction belongs to another account"),
    ],
)
def test_message_edges_are_decoded_from_the_transactions(records, change, reason):
    assert oracle.verify(None, records)["pass"]
    step = records["steps.jsonl"][4]
    other = records["steps.jsonl"][7]
    if change == "fabricated_sender_edge":
        # The rendering claims the step message among the sender's messages while the
        # retained sender transaction, decoded, emitted nothing of the kind.
        donor = copy.deepcopy(step["target"])
        donor["out_msgs"] = [{"destination": step["destination"], "hash": step["message_hash"]}]
        step["transactions"][step["sender"]] = [donor]
    elif change == "relabelled_target":
        # Another real transaction, with the rendering claiming this step's message.
        donor = copy.deepcopy(other["target"])
        donor["in_msg"] = {"hash": step["message_hash"]}
        step["target"] = donor
        step["transactions"][step["destination"]] = [copy.deepcopy(donor)]
    elif change == "target_of_another_account":
        step["transactions"][OTHER_ACCOUNT] = step["transactions"].pop(step["destination"])
        step["destination"] = OTHER_ACCOUNT
    else:
        step["transactions"][OTHER_ACCOUNT] = step["transactions"].pop(step["sender"])
        step["sender"] = OTHER_ACCOUNT
    with pytest.raises(AssertionError, match=reason):
        oracle.verify(None, records)


def test_message_sent_to_another_destination_is_refused(records):
    # With consistent BOCs the message's destination is the target account, so this
    # requirement can only be reached through decoding; drive it with decoded edges.
    step = records["steps.jsonl"][0]
    real = oracle.decoded_edges

    def edges(tx):
        decoded = real(tx)
        if tx["data"] == step["transactions"][step["sender"]][0]["data"]:
            decoded["out_msgs"] = [(h, OTHER_ACCOUNT) for h, _ in decoded["out_msgs"]]
        return decoded

    with patch.object(oracle, "decoded_edges", edges):
        with pytest.raises(AssertionError, match="sent to another destination"):
            oracle.check_message_edges(step)


@pytest.mark.parametrize(
    "change,reason",
    [
        ("runner_expected", "runner expected outcome"),
        ("rpc_compute_exit", "RPC outcome rendering disagrees"),
        ("rpc_aborted", "RPC outcome rendering disagrees"),
        ("rpc_action", "RPC outcome rendering disagrees"),
    ],
)
def test_outcomes_decoded_from_the_transaction_not_the_summary(records, change, reason):
    assert oracle.verify(None, records)["pass"]
    refused = records["steps.jsonl"][7]
    assert refused["step"] == "insufficient balance"
    first = records["steps.jsonl"][0]
    if change == "runner_expected":
        refused["expected_exit"] = 0
    elif change == "rpc_compute_exit":
        first["target"]["compute"]["exit_code"] = 1
    elif change == "rpc_aborted":
        first["target"]["aborted"] = True
    else:
        first["target"]["action"] = {"success": False}
    # The runner retains the same transaction under the destination account.
    first["transactions"][first["destination"]][0] = copy.deepcopy(first["target"])
    with pytest.raises(AssertionError, match=reason):
        oracle.verify(None, records)


def test_decoded_outcome_reads_the_phases_from_the_boc():
    deploy = fixture_transactions.STEPS[0]["target_tx"]
    refused = fixture_transactions.STEPS[706]["target_tx"]
    assert oracle.decoded_outcome({"data": deploy}) == {
        "exit_code": 0,
        "aborted": False,
        "action_success": True,
    }
    assert oracle.decoded_outcome({"data": refused}) == {
        "exit_code": 706,
        "aborted": True,
        "action_success": None,
    }
    assert (
        oracle.decoded_outcome({"data": fixture_transactions.STEPS[401]["target_tx"]})["exit_code"]
        == 401
    )
    # The summary may say pass; the decoded transaction decides.
    with pytest.raises(AssertionError, match="compute exit differs"):
        oracle.check_outcome(
            {"step": "token deploy", "expected_exit": 0, "target": rendered(refused, 706)}
        )


@pytest.mark.parametrize("change", ["no_sender", "not_sent", "sent_twice"])
def test_step_message_must_come_from_the_sender(records, change):
    assert oracle.verify(None, records)["pass"]
    step = records["steps.jsonl"][2]
    if change == "no_sender":
        del step["sender"]
        reason = "step sender missing"
    elif change == "not_sent":
        step["transactions"][step["sender"]] = [copy.deepcopy(step["target"])]
        reason = "missing from the sender's outgoing messages"
    else:
        step["transactions"][step["sender"]].append(
            copy.deepcopy(step["transactions"][step["sender"]][0])
        )
        reason = "more than once"
    with pytest.raises(AssertionError, match=reason):
        oracle.verify(None, records)


def test_oracle_reports_and_checks_what_it_accepted(records):
    result = oracle.verify(None, records)
    assert (result["source_head"], result["global_id"], result["run_id"]) == (
        "ab" * 20,
        3,
        "run-1",
    )
    assert oracle.verify(None, records, expect_source_head="ab" * 20, expect_global_id=3)["pass"]
    with pytest.raises(AssertionError, match="sealed at another source head"):
        oracle.verify(None, records, expect_source_head="cd" * 20)
    with pytest.raises(AssertionError, match="another network"):
        oracle.verify(None, records, expect_global_id=1)


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


def test_rpc_reads_retry_transport_stalls_a_bounded_number_of_times():
    harness = object.__new__(lifecycle.Harness)
    harness.endpoint = "http://127.0.0.1:1/jsonRPC"
    recorded = []
    harness.record = lambda name, value: recorded.append((name, value))
    answers = [TimeoutError("timed out"), OSError("connection reset"), ({}, {"result": 7})]

    def rpc_call(endpoint, method, **params):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    with patch.object(lifecycle, "rpc_call", rpc_call):
        assert harness.rpc("getMasterchainInfo") == 7
    assert [value.get("attempt") for name, value in recorded if "error" in value] == [1, 2]

    def always(endpoint, method, **params):
        raise TimeoutError("timed out")

    with patch.object(lifecycle, "rpc_call", always):
        with pytest.raises(TimeoutError):
            harness.rpc("getMasterchainInfo")
    assert (
        sum(1 for name, value in recorded if "error" in value) == 2 + lifecycle.Harness.RPC_ATTEMPTS
    )

    # A JSON-RPC error answer is final and is not retried.
    def refused(endpoint, method, **params):
        raise RuntimeError("getMasterchainInfo: refused")

    before = len(recorded)
    with patch.object(lifecycle, "rpc_call", refused):
        with pytest.raises(RuntimeError):
            harness.rpc("getMasterchainInfo")
    assert len(recorded) == before + 1


def test_launcher_reads_the_network_identity_from_the_node():
    param = base64.b64encode(begin_cell().store_int(3, 32).end_cell().to_boc()).decode()
    seen = {}

    def rpc_call(endpoint, method, **params):
        seen.update(endpoint=endpoint, method=method, params=params)
        return {}, {"result": {"config": {"bytes": param}}}

    with patch.object(lifecycle, "rpc_call", rpc_call):
        assert lifecycle.read_global_id("http://127.0.0.1:1/jsonRPC") == 3
    assert seen == {
        "endpoint": "http://127.0.0.1:1/jsonRPC",
        "method": "getConfigParam",
        "params": {"param": 19},
    }


def test_signer_adapter_is_bounded_by_a_deadline():
    killed = []
    spawned = {}

    class Process:
        returncode = None
        pid = 4242

        async def communicate(self, _data):
            await asyncio.Event().wait()

        async def wait(self):
            return 0

    async def spawn(*_args, **kwargs):
        spawned.update(kwargs)
        return Process()

    message = SimpleNamespace(send_mode=3, message=SimpleNamespace(serialize=Cell.empty))
    send = lifecycle.make_sender("signer-adapter", 0.05)
    with (
        patch.object(lifecycle.asyncio, "create_subprocess_exec", spawn),
        patch.object(lifecycle.os, "killpg", lambda pid, sig: killed.append((pid, sig))),
    ):
        with pytest.raises(TimeoutError, match="submission state unknown"):
            asyncio.run(send(ACCOUNT, message))
    # The adapter runs in its own process group, and the whole group is killed.
    assert spawned.get("start_new_session") is True
    assert killed == [(4242, lifecycle.signal.SIGKILL)]


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
