"""The soak's fd classification and its OFF/ON verdict, on synthetic samples."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

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
    (directory / "soak-meta.json").write_text(json.dumps({"label": directory.name}))
    rows = []
    for i in range(25):
        age = i * 300.0
        rss = int((500 + rss_growth_mib_per_h * age / 3600.0) * MIB)
        nodes = {
            f"node{k}": {
                "role": "validator" if k <= 4 else "observer",
                "pid": 100 + k,
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
