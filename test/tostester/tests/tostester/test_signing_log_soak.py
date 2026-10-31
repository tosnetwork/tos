"""The soak's fd classification and its OFF/ON verdict, on synthetic samples."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[4]


def _soak() -> Any:
    path = ROOT / "test/integration/signing_log_soak.py"
    spec = importlib.util.spec_from_file_location("signing_log_soak", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


soak: Any = _soak()
MIB = 1024 * 1024


def test_classify() -> None:
    node = "/w/node2"
    cases = {
        "/w/node2/consensus/consensus.ABCD/db/000123.sst": "consensus_db",
        "/w/node2/consensus/consensus.ABCD/db/LOG": "consensus_db",
        "/w/node2/consensus/signing-ledger/log.ABCD": "signing_ledger",
        f"/w/node2/consensus/signing-ledger.{'A' * 64}/log.ABCD": "signing_ledger",
        "/w/node2/archive/packages/arch0000.pack": "archive",
        "/w/node2/celldb/MANIFEST-000005": "celldb",
        "/w/node2/state/x": "db_state",
        "/w/node3/celldb/x": "other",
        "socket:[123]": "socket",
        "pipe:[9]": "pipe",
        "anon_inode:[eventfd]": "anon_inode",
        "/dev/null": "other",
    }
    for target, kind in cases.items():
        assert soak.classify(target, node) == kind, target


def write(
    directory: Path, rss_growth_mib_per_h: float, ledger_fds: int, extra_on_class: int
) -> Path:
    directory.mkdir()
    (directory / "soak-meta.json").write_text(
        json.dumps(
            {
                "label": directory.name,
                "roles": {f"node{k}": "validator" if k <= 4 else "observer" for k in range(1, 7)},
                "duration": 7200,
                "interval": 300,
                "started_at": 1e9,
                "ended_at": 1e9 + 7200,
            }
        )
    )
    rows = []
    for i in range(25):
        age = i * 300.0
        rss = int((500 + rss_growth_mib_per_h * age / 3600.0) * MIB)
        nodes = {
            f"node{k}": {
                "role": "validator" if k <= 4 else "observer",
                "pid": 100 + k,
                "start_ticks": 1000 + k,
                "rss_bytes": rss,
                "fds": 100,
                "classes": {
                    "socket": 20,
                    "consensus_db": 40,
                    "signing_ledger": ledger_fds,
                    "other": i * extra_on_class,
                },
                "live_sessions": 4,
                "signing_ledger_log_fds": ledger_fds,
            }
            for k in range(1, 7)
        }
        rows.append({"age": age, "at": 1e9 + age, "nodes": nodes})
    (directory / "samples.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return directory


def test_equal_runs_pass(tmp_path: Path) -> None:
    verdict = soak.compare(write(tmp_path / "off", 2.0, 0, 0), write(tmp_path / "on", 3.0, 5, 0))
    assert verdict["passed"] is True
    assert abs(verdict["rss"]["validator"]["on_minus_off_mib_per_h"] - 1.0) < 1e-6


def test_rss_slope_beyond_ten_mib_per_hour_fails(tmp_path: Path) -> None:
    verdict = soak.compare(write(tmp_path / "off", 2.0, 0, 0), write(tmp_path / "on", 14.0, 5, 0))
    assert verdict["rss"]["validator"]["within_10_mib_per_h"] is False
    assert verdict["passed"] is False


def test_more_ledger_logs_than_sessions_fails(tmp_path: Path) -> None:
    verdict = soak.compare(write(tmp_path / "off", 2.0, 0, 0), write(tmp_path / "on", 2.0, 6, 0))
    assert verdict["signing_ledger_log_fd_violations"]
    assert verdict["passed"] is False


def test_a_class_growing_only_in_on_fails(tmp_path: Path) -> None:
    verdict = soak.compare(write(tmp_path / "off", 2.0, 0, 0), write(tmp_path / "on", 2.0, 5, 1))
    assert verdict["fd_classes_growing_only_in_on"] == ["other"]
    assert verdict["passed"] is False


@pytest.mark.parametrize("arm", ["off", "on"])
@pytest.mark.parametrize(
    "failure",
    ["missing", "omitted", "census", "pid", "start_ticks", "role", "classes", "gap", "short"],
)
def test_incomplete_or_restarted_processes_fail(tmp_path: Path, arm: str, failure: str) -> None:
    off = write(tmp_path / "off", 2.0, 0, 0)
    on = write(tmp_path / "on", 3.0, 5, 0)
    path = tmp_path / arm / "samples.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if failure == "gap":
        del rows[3:7]
    elif failure == "short":
        rows = rows[:10]
    else:
        for row in rows[1:]:
            if failure == "missing":
                for name in ("node1", "node2", "node3"):
                    row["nodes"][name] = None
            elif failure == "omitted":
                del row["nodes"]["node1"]
            elif failure == "census":
                del row["nodes"]["node1"]["rss_bytes"]
            elif failure in ("pid", "start_ticks"):
                row["nodes"]["node1"][failure] += 1
            elif failure == "role":
                row["nodes"]["node1"]["role"] = "observer"
            else:
                del row["nodes"]["node1"]["classes"]
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    verdict = soak.compare(off, on)
    assert verdict["passed"] is False
    assert verdict["sample_errors"][arm]


def test_missing_inventory_fails(tmp_path: Path) -> None:
    off = write(tmp_path / "off", 2.0, 0, 0)
    on = write(tmp_path / "on", 3.0, 5, 0)
    (on / "soak-meta.json").write_text("{}")
    verdict = soak.compare(off, on)
    assert verdict["passed"] is False
    assert verdict["sample_errors"]["on"]
