"""Receipt guard tests use synthetic public cells, not a claim of native execution."""

import asyncio
import base64
import copy
import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from pytosiq_core import Cell

ROOT = Path(__file__).resolve().parents[3]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/{name}.py")
    assert spec is not None and spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


oracle = module("tok01-oracle")
lifecycle = module("tok01-lifecycle")


@pytest.fixture
def records():
    tx = {
        "data": base64.b64encode(Cell.empty().to_boc()).decode(),
        "transaction_id": {"hash": base64.b64encode(Cell.empty().hash).decode()},
        "block_id": dict.fromkeys(("root_hash", "file_hash", "seqno", "workchain", "shard"), 0),
    }
    field = {"getter": 1, "rpc_or_expected": 1, "pass": True, "field": "synthetic"}
    return {
        "summary.jsonl": [{"pass": True, "failures": [], "steps": list(oracle.REQUIRED_STEPS)}],
        "steps.jsonl": [
            {
                "step": name,
                "target": copy.deepcopy(tx),
                "destination": "account",
                "transactions": {"account": [copy.deepcopy(tx)]},
                "comparisons": [field],
            }
            for name in oracle.REQUIRED_STEPS
        ],
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
        "notifications.jsonl": [{"transactions": [tx["transaction_id"]]}],
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
    owner = "0:" + "11" * 32
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
            asyncio.run(harness.complete_index("getAccountTokens", "0:" + "11" * 32))
