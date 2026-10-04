"""The root-service installer snapshots everything the services run, outside the checkout."""

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parent / "install-root-services.sh"
GENERATOR = "tools/shielded-pool-circuit/crosscheck/target/release/local_pool_traffic"
HEX = "crypto/smartcont/single-nominator-pool/single-nominator-code.hex"


def write(path, text="x\n", mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


@pytest.fixture
def checkout(tmp_path):
    repo = tmp_path / "repo"
    write(repo / "scripts/local-pq-elections.py", "print('driver')\n")
    write(repo / "scripts/__pycache__/stale.pyc")
    write(repo / "test/tostester/src/toslib/__init__.py")
    write(repo / HEX, "b5ee9c72\n")
    write(repo / GENERATOR, "#!/bin/sh\n", 0o755)
    library = write(repo / "build/toslib/libtoslibjson.so.0.5", "elf\n", 0o755)
    (repo / "build/toslib/libtoslibjson.so").symlink_to(library.name)
    # A stand-in for uv that records how it was called and creates the environment.
    record = tmp_path / "uv-call.json"
    fake = write(
        tmp_path / "uv",
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        f"Path({str(record)!r}).write_text(json.dumps({{'argv': sys.argv[1:], "
        "'env': {k: v for k, v in os.environ.items() if k.startswith('UV_')}}))\n"
        "Path(os.environ['UV_PROJECT_ENVIRONMENT'], 'bin').mkdir(parents=True)\n"
        # A file left world-writable, which the installer must not keep that way.
        "python = Path(os.environ['UV_PROJECT_ENVIRONMENT'], 'bin', 'python')\n"
        "python.write_text('')\n"
        "python.chmod(0o777)\n",
        0o755,
    )
    return repo, fake, record


def install(base, repo, uv, generator=None):
    return subprocess.run(
        [
            "bash",
            str(INSTALLER),
            str(base),
            str(repo),
            str(repo / "build"),
            str(generator or repo / GENERATOR),
        ],
        env={**os.environ, "UV": str(uv)},
        capture_output=True,
        text=True,
    )


def test_the_snapshot_holds_the_services_code_in_the_checkout_layout(tmp_path, checkout):
    repo, uv, record = checkout
    base = tmp_path / "services"
    result = install(base, repo, uv)
    assert result.returncode == 0, result.stderr
    dest = Path(result.stdout.strip())
    assert (base / "current").resolve() == dest.resolve()
    src = dest / "src"
    for relative in ("scripts/local-pq-elections.py", "test/tostester/src/toslib/__init__.py", HEX):
        assert (src / relative).read_bytes() == (repo / relative).read_bytes()
    library = src / "build/toslib/libtoslibjson.so"
    assert not library.is_symlink() and library.read_text() == "elf\n"
    assert os.access(src / GENERATOR, os.X_OK)
    assert not (src / "scripts/__pycache__").exists()
    for path in [dest, *dest.rglob("*")]:
        if not path.is_symlink():
            assert not path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH), path


def test_uv_installs_only_locked_dependencies_into_the_snapshot(tmp_path, checkout):
    repo, uv, record = checkout
    result = install(tmp_path / "services", repo, uv)
    assert result.returncode == 0, result.stderr
    dest = Path(result.stdout.strip())
    call = json.loads(record.read_text())
    assert call["argv"][:3] == ["sync", "--project", str(repo)]
    for flag in ("--frozen", "--no-dev", "--no-install-workspace"):
        assert flag in call["argv"]
    assert call["env"]["UV_PROJECT_ENVIRONMENT"] == str(dest / "venv")
    assert call["env"]["UV_PYTHON_INSTALL_DIR"] == str(dest / "python")
    assert call["env"]["UV_PYTHON_PREFERENCE"] == "only-managed"


def test_a_new_install_replaces_the_previous_snapshot(tmp_path, checkout):
    repo, uv, _ = checkout
    base = tmp_path / "services"
    first = Path(install(base, repo, uv).stdout.strip())
    write(repo / "scripts/local-pq-elections.py", "print('changed')\n")
    second = install(base, repo, uv)
    assert second.returncode == 0, second.stderr
    second = Path(second.stdout.strip())
    assert second != first and not first.exists()
    assert (base / "current").resolve() == second.resolve()
    assert sorted(p.name for p in base.iterdir()) == sorted(["current", second.name])
    assert "changed" in (base / "current/src/scripts/local-pq-elections.py").read_text()


@pytest.mark.parametrize(
    "missing", [GENERATOR, HEX, "build/toslib/libtoslibjson.so", "test/tostester/src"]
)
def test_a_missing_input_installs_nothing(tmp_path, checkout, missing):
    repo, uv, record = checkout
    target = repo / missing
    if target.is_dir():
        for child in sorted(target.rglob("*"), reverse=True):
            child.unlink() if not child.is_dir() else child.rmdir()
        target.rmdir()
    else:
        target.unlink()
    base = tmp_path / "services"
    result = install(base, repo, uv)
    assert result.returncode == 1
    assert result.stderr.strip() == f"missing {repo / missing}"
    assert not base.exists() or not any(base.iterdir()), "no partial snapshot is left behind"
    assert not record.exists(), "nothing may be installed after a refused input check"
