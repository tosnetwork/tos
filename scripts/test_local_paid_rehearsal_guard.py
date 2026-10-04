"""The local paid rehearsal deploys the deprecated escrow v1 only on explicit request."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "test/tostester/src"), str(ROOT / "scripts")]
spec = importlib.util.spec_from_file_location(
    "local_paid_rehearsal", ROOT / "scripts/tos-service-local-paid-rehearsal.py"
)
rehearsal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rehearsal)


def argv(output, *extra):
    return [
        "tos-service-local-paid-rehearsal.py",
        "--global-config",
        "unused.json",
        "--state-dir",
        "unused",
        "--network-id",
        "1",
        "--capability-evidence",
        "missing-capability.json",
        "--stablecoin-evidence",
        "missing-stablecoin.json",
        "--output-dir",
        str(output),
        *extra,
    ]


def test_without_the_flag_it_refuses_before_touching_anything(tmp_path, monkeypatch):
    output = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", argv(output))
    with pytest.raises(SystemExit, match="deprecated escrow v1"):
        rehearsal.main()
    assert not output.exists(), "the refusal must come before any output is created"


def test_with_the_flag_it_proceeds_past_the_guard(tmp_path, monkeypatch):
    output = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", argv(output, "--allow-deprecated-escrow-v1"))
    # Past the guard it reads its evidence files, which do not exist here.
    with pytest.raises(FileNotFoundError):
        rehearsal.main()
    assert output.exists()
