"""The N6 observer stays inside each liteserver connection's admission budget.

A liteserver admits a bounded number of queries per window on each connection and drops
the rest without answering, so a caller that bursts past it waits out a full query timeout.
"""

import asyncio
import re
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from tostester.n6_cluster import (
    LITE_ADMISSION_DROP_MARKER,
    LITE_CONNECTION_LIMITS_SOURCE,
    LITE_LAST_BLOCK_SYNC_FAILED,
    LITE_QUERIES_PER_HEIGHT_POLL,
    LITE_QUERIES_PER_LOOKUP,
    LiteConnectionBudget,
    LiteQueryPacer,
    SustainedObservationConfig,
    lite_admission_drop_warnings,
    lite_connection_budget,
    observe_sustained_consensus,
)

ROOT = Path(__file__).resolve().parents[4]


def write_limits(root: Path, declaration: str) -> Path:
    path = root / LITE_CONNECTION_LIMITS_SOURCE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"class AdnlInboundConnection {{\n  {declaration}\n}};\n", encoding="utf-8")
    return root


def test_budget_is_read_from_the_server_declaration(tmp_path: Path) -> None:
    root = write_limits(tmp_path, "ExtConnectionQueryLimits query_limits_{2.5, 40, 12};")
    assert lite_connection_budget(root) == LiteConnectionBudget(2.5, 40, 12)


def test_repository_declares_exactly_one_usable_budget() -> None:
    budget = lite_connection_budget(ROOT)
    assert budget.window_seconds > 0
    assert budget.max_queries_per_window >= 2 * LITE_QUERIES_PER_LOOKUP
    source = (ROOT / LITE_CONNECTION_LIMITS_SOURCE).read_text(encoding="utf-8")
    assert f"{budget.max_queries_per_window}, {budget.max_inflight}}}" in source


@pytest.mark.parametrize(
    "declaration",
    [
        "",
        "ExtConnectionQueryLimits query_limits_{1.0, 64, 32};"
        " ExtConnectionQueryLimits query_limits_{1.0, 64, 32};",
        "ExtConnectionQueryLimits query_limits_{0, 64, 32};",
        "ExtConnectionQueryLimits query_limits_{1.0, 5, 32};",
        "ExtConnectionQueryLimits query_limits_{1.0, 64, 2};",
    ],
)
def test_budget_refuses_a_missing_duplicated_or_unusable_declaration(
    tmp_path: Path, declaration: str
) -> None:
    root = write_limits(tmp_path, declaration)
    with pytest.raises(RuntimeError, match="N6_LITE_BUDGET_FAILURE"):
        lite_connection_budget(root)


def test_budget_refuses_an_unreadable_source(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="N6_LITE_BUDGET_FAILURE"):
        lite_connection_budget(tmp_path)


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def most_spent_in_any_window(spends: list[tuple[float, int]], window: float) -> int:
    return max(
        sum(cost for at, cost in spends if start <= at < start + window) for start, _ in spends
    )


def test_pacer_holds_a_burst_to_half_of_each_window() -> None:
    clock = FakeClock()
    pacer = LiteQueryPacer(LiteConnectionBudget(1.0, 64, 32), clock=clock, sleep=clock.sleep)
    spends: list[tuple[float, int]] = []

    async def burst() -> None:
        for _ in range(30):
            await pacer.acquire(LITE_QUERIES_PER_LOOKUP)
            spends.append((clock.now, LITE_QUERIES_PER_LOOKUP))

    asyncio.run(burst())
    assert pacer.capacity == 32
    assert most_spent_in_any_window(spends, 1.0) <= 32
    assert pacer.waited_seconds > 0 and sum(clock.sleeps) == pytest.approx(pacer.waited_seconds)


def test_pacer_never_waits_below_its_capacity() -> None:
    clock = FakeClock()
    pacer = LiteQueryPacer(LiteConnectionBudget(1.0, 64, 32), clock=clock, sleep=clock.sleep)

    async def steady() -> None:
        for _ in range(20):
            await pacer.acquire(LITE_QUERIES_PER_LOOKUP)
            await pacer.acquire(LITE_QUERIES_PER_HEIGHT_POLL)
            clock.now += 0.4

    asyncio.run(steady())
    assert clock.sleeps == [] and pacer.waited_seconds == 0


@pytest.mark.parametrize("cost", [0, -1, 33])
def test_pacer_refuses_a_cost_it_can_never_admit(cost: int) -> None:
    pacer = LiteQueryPacer(LiteConnectionBudget(1.0, 64, 32))
    with pytest.raises(ValueError, match="N6_LITE_BUDGET_FAILURE"):
        asyncio.run(pacer.acquire(cost))


class RecordingClient:
    """A liteserver connection that records when each native query would be sent."""

    def __init__(self, heights: list[int]) -> None:
        self.heights = iter(heights)
        self.last_height = 0
        self.sent: list[tuple[float, int]] = []

    async def get_masterchain_info(self):
        self.sent.append((time.monotonic(), LITE_QUERIES_PER_HEIGHT_POLL))
        self.last_height = next(self.heights, self.last_height)
        return SimpleNamespace(last=SimpleNamespace(seqno=self.last_height))

    async def lookup_block(self, *, workchain: int, shard: int, seqno: int):
        self.sent.append((time.monotonic(), LITE_QUERIES_PER_LOOKUP))
        return SimpleNamespace(
            workchain=workchain,
            shard=shard,
            seqno=seqno,
            root_hash=bytes.fromhex("11" * 32),
            file_hash=bytes.fromhex("22" * 32),
        )


class FakeNode:
    def __init__(self, name: str, client: RecordingClient) -> None:
        self.name = name
        self.client = client

    async def toslib_client(self) -> RecordingClient:
        return self.client


def test_catch_up_from_a_late_start_stays_inside_each_connection_budget() -> None:
    # A late start is the case that burst past the server's budget: every earlier height is
    # looked up before the first observation. A small window keeps the test fast.
    budget = LiteConnectionBudget(0.2, 12, 6)
    clients = [RecordingClient([30, 30, 31, 32]) for _ in range(4)]
    config = SustainedObservationConfig(
        blocks=2, seconds=None, target_block_rate_ms=400, slow_interval_factor=3.0
    )
    summary = asyncio.run(
        observe_sustained_consensus(
            [FakeNode(f"node-{index}", client) for index, client in enumerate(clients)],
            config,
            "zerostate-block-id",
            lite_budget=budget,
        )
    )
    capacity = budget.max_queries_per_window // 2
    for client in clients:
        lookups = sum(1 for _, cost in client.sent if cost == LITE_QUERIES_PER_LOOKUP)
        assert lookups >= 32
        # Scheduling jitter can only lengthen gaps, so the recorded times are a fair bound.
        assert most_spent_in_any_window(client.sent, budget.window_seconds * 0.95) <= capacity
    assert summary["lite_query_pacing"]["observer_queries_per_window"] == capacity
    assert summary["lite_query_pacing"]["waited_seconds"] > 0


def test_admission_drop_warnings_are_counted_per_node(tmp_path: Path) -> None:
    clean, dropped = tmp_path / "clean.log", tmp_path / "dropped.log"
    clean.write_bytes(b"[adnl-ext-server.cpp:53][!inconn] ADNL_EXT_QUERY admission=accepted\n")
    dropped.write_bytes(
        b"[2][t 0][adnl-ext-server.cpp:65][!inconn]\t"
        + LITE_ADMISSION_DROP_MARKER.encode()
        + b"127.0.0.1: per_connection_rate (answered)\n"
    )
    assert lite_admission_drop_warnings({"node-1": clean, "node-2": dropped}) == {
        "node-1": 0,
        "node-2": 1,
    }


def test_admission_drop_check_refuses_a_missing_log(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="N6_LITE_ADMISSION_CHECK_FAILURE"):
        lite_admission_drop_warnings({"node-1": tmp_path / "absent.log"})


def test_admission_drop_check_counts_a_marker_across_read_chunks(tmp_path: Path) -> None:
    path = tmp_path / "node.log"
    marker = LITE_ADMISSION_DROP_MARKER.encode()
    path.write_bytes(b"x" * (1024 * 1024 - 4) + marker + b"\n")
    assert lite_admission_drop_warnings({"node-1": path}) == {"node-1": 1}


def test_admission_drop_check_refuses_symlink_and_oversize(tmp_path: Path) -> None:
    path = tmp_path / "node.log"
    path.write_bytes(b"ready\n")
    (tmp_path / "link.log").symlink_to(path)
    with pytest.raises(RuntimeError, match="N6_LITE_ADMISSION_CHECK_FAILURE"):
        lite_admission_drop_warnings({"node-1": tmp_path / "link.log"})
    with path.open("r+b") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    with pytest.raises(RuntimeError, match="N6_LITE_ADMISSION_CHECK_FAILURE"):
        lite_admission_drop_warnings({"node-1": path})


def test_server_still_reports_the_first_drop_at_default_verbosity() -> None:
    # Nodes run at verbosity 3, which keeps warnings but not debug lines; if the first drop
    # moved to debug, the drop check above would count nothing and pass.
    source = (ROOT / "adnl/adnl-ext-server.cpp").read_text(encoding="utf-8")
    assert re.search(
        r"LOG\(WARNING\) << \"" + re.escape(LITE_ADMISSION_DROP_MARKER) + r"\"", source
    )


def test_toslib_still_wraps_last_block_failures_with_the_classified_prefix() -> None:
    client = (ROOT / "toslib/toslib/ToslibClient.cpp").read_text(encoding="utf-8")
    errors = (ROOT / "toslib/toslib/ToslibError.h").read_text(encoding="utf-8")
    wrapped = LITE_LAST_BLOCK_SYNC_FAILED.removeprefix("INTERNAL: ")
    assert f'ToslibError::Internal("{wrapped}")' in client
    assert 'Error(500, PSLICE() << "INTERNAL: " << message)' in errors
