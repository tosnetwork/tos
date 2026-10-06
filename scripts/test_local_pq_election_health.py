import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "health", Path(__file__).with_name("check-local-pq-elections.py")
)
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)
NOW = 1800000000


def fixture(directory):
    (directory / "status.json").write_text(
        json.dumps(dict(at=NOW, healthy=True, activation_since=NOW - 100))
    )
    (directory / f"activation-{NOW - 100}.json").write_text(
        json.dumps(dict(config34=dict(utime_until=NOW + 500)))
    )
    for index in (1, 2, 3, 4, 7):
        (directory / f"operations-{index}.json").write_text(
            json.dumps(
                dict(
                    ready=True,
                    checked_at=NOW,
                    operating_state=dict(expires=NOW + 30 * 86400),
                    runway_seconds=30 * 86400,
                )
            )
        )


def test_healthy_persistent_driver(tmp_path):
    fixture(tmp_path)
    value = health.check(tmp_path, NOW)
    assert value["healthy"] and not value["warnings"]


@pytest.mark.parametrize(
    "fault", ["stale", "failure", "expired_set", "missing", "old_budget", "expired_auth"]
)
def test_liveness_failures_are_visible(tmp_path, fault):
    fixture(tmp_path)
    if fault in ("stale", "failure"):
        (tmp_path / "status.json").write_text(
            json.dumps(dict(at=NOW - 181 if fault == "stale" else NOW, healthy=fault != "failure"))
        )
    if fault == "expired_set":
        (tmp_path / f"activation-{NOW - 100}.json").write_text(
            json.dumps(dict(config34=dict(utime_until=NOW - 1)))
        )
    if fault == "missing":
        (tmp_path / "operations-7.json").unlink()
    if fault in ("old_budget", "expired_auth"):
        row = json.loads((tmp_path / "operations-1.json").read_text())
        if fault == "old_budget":
            row["checked_at"] = NOW - 1801
        else:
            row["operating_state"]["expires"] = NOW - 1
        (tmp_path / "operations-1.json").write_text(json.dumps(row))
    assert not health.check(tmp_path, NOW)["healthy"]


def test_budget_warning_precedes_exhaustion(tmp_path):
    fixture(tmp_path)
    row = json.loads((tmp_path / "operations-1.json").read_text())
    row["runway_seconds"] = 7 * 86400
    (tmp_path / "operations-1.json").write_text(json.dumps(row))
    result = health.check(tmp_path, NOW)
    assert result["healthy"] and result["warnings"]
