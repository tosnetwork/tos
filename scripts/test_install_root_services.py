"""The root-service installer snapshots everything the services run, outside the checkout,
and refuses a snapshot or a location that would still let anyone else change it."""

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parent / "install-root-services.sh"
GENERATOR = "tools/shielded-pool-circuit/crosscheck/target/release/local_pool_traffic"
HEX = "crypto/smartcont/single-nominator-pool/single-nominator-code.hex"
MARKER = ".tos-dev-services-snapshot"

# What the stand-in for uv does, selected per test through a file it reads.
STUB = """#!/usr/bin/env python3
import json, os, shutil, sys
from pathlib import Path
here = Path(__file__).resolve().parent
Path(here, "uv-call.json").write_text(json.dumps({"argv": sys.argv[1:], "env": dict(os.environ)}))
venv = Path(os.environ["UV_PROJECT_ENVIRONMENT"])
python = Path(os.environ["UV_PYTHON_INSTALL_DIR"])
(venv / "bin").mkdir(parents=True)
(python / "lib").mkdir(parents=True)
interpreter = venv / "bin" / "python"
interpreter.write_text("")
interpreter.chmod(0o777)  # left world-writable; the installer must not keep it so
(python / "lib" / "libtcl9.0.so").write_text("tk")
extra_file = Path(here, "uv-extra.json")
extra = json.loads(extra_file.read_text()) if extra_file.exists() else {}
if "escaping_link" in extra:
    (venv / "lib").mkdir()
    (venv / "lib" / "escape").symlink_to(extra["escaping_link"])
if "pth" in extra:
    (venv / "lib").mkdir(exist_ok=True)
    (venv / "lib" / "extra.pth").write_text(extra["pth"])
if "elf" in extra:
    (venv / "lib").mkdir(exist_ok=True)
    shutil.copy(extra["elf"], venv / "lib" / "native.so")
"""


def write(path, text="x\n", mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


@pytest.fixture
def setup(tmp_path):
    repo = tmp_path / "repo"
    write(repo / "scripts/local-pq-elections.py", "print('driver')\n")
    write(repo / "scripts/__pycache__/stale.pyc")
    write(repo / "test/tostester/src/toslib/__init__.py")
    write(repo / HEX, "b5ee9c72\n")
    write(repo / GENERATOR, "#!/bin/sh\n", 0o755)
    library = write(repo / "build/toslib/libtoslibjson.so.0.5", "elf\n", 0o755)
    (repo / "build/toslib/libtoslibjson.so").symlink_to(library.name)
    # The checker is the installer's own; run the real one from the fake checkout.
    shutil.copy(INSTALLER.with_name("install-root-services-check.py"), repo / "scripts")
    tools = tmp_path / "tools"
    write(tools / "uv", STUB, 0o755)
    base_parent = tmp_path / "opt"
    base_parent.mkdir()
    base_parent.chmod(0o755)
    return repo, tools, base_parent / "services"


def install(repo, tools, base, extra=None, env=None):
    if extra is not None:
        (tools / "uv-extra.json").write_text(json.dumps(extra))
    return subprocess.run(
        ["bash", str(INSTALLER), str(base), str(repo), str(repo / "build"), str(repo / GENERATOR)],
        env={**os.environ, "UV": str(tools / "uv"), **(env or {})},
        capture_output=True,
        text=True,
    )


def published(base):
    return (base / "current").exists()


def test_the_snapshot_holds_the_services_code_in_the_checkout_layout(setup):
    repo, tools, base = setup
    result = install(repo, tools, base)
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
    assert not (dest / "python/lib/libtcl9.0.so").exists(), "Tk bindings are not installed"
    assert (dest / MARKER).exists()
    for path in [dest, *dest.rglob("*")]:
        if not path.is_symlink():
            assert not path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH), path


def test_uv_runs_isolated_and_copies_into_the_snapshot(setup):
    repo, tools, base = setup
    caller = {"UV_INDEX_URL": "http://elsewhere", "UV_LINK_MODE": "symlink"}
    result = install(repo, tools, base, env=caller)
    assert result.returncode == 0, result.stderr
    dest = Path(result.stdout.strip())
    call = json.loads((tools / "uv-call.json").read_text())
    assert call["argv"][:3] == ["sync", "--project", str(repo)]
    for flag in ("--frozen", "--no-dev", "--no-install-workspace"):
        assert flag in call["argv"]
    env = call["env"]
    assert "UV_INDEX_URL" not in env, "the caller's uv settings must not reach the install"
    assert env["UV_LINK_MODE"] == "copy"
    assert env["UV_PROJECT_ENVIRONMENT"] == str(dest / "venv")
    assert env["UV_PYTHON_INSTALL_DIR"] == str(dest / "python")
    assert env["UV_PYTHON_PREFERENCE"] == "only-managed"
    assert not Path(env["UV_CACHE_DIR"]).is_relative_to(dest)
    assert not Path(env["UV_CACHE_DIR"]).exists(), "the throwaway cache is removed"


def test_a_new_install_replaces_only_marked_snapshots(setup):
    repo, tools, base = setup
    first = Path(install(repo, tools, base).stdout.strip())
    unrelated = base / "keep-me"
    unrelated.mkdir()
    unmarked = base / "20200101T000000Z-1"
    unmarked.mkdir()
    write(repo / "scripts/local-pq-elections.py", "print('changed')\n")
    result = install(repo, tools, base)
    assert result.returncode == 0, result.stderr
    second = Path(result.stdout.strip())
    assert second != first and not first.exists()
    assert unrelated.exists() and unmarked.exists(), "only marked snapshots are deleted"
    assert (base / "current").resolve() == second.resolve()
    assert "changed" in (base / "current/src/scripts/local-pq-elections.py").read_text()


@pytest.mark.parametrize(
    "missing", [GENERATOR, HEX, "build/toslib/libtoslibjson.so", "test/tostester/src"]
)
def test_a_missing_input_installs_nothing(setup, missing):
    repo, tools, base = setup
    target = repo / missing
    if target.is_dir() and not target.is_symlink():
        shutil.rmtree(target)
    else:
        target.unlink()
    result = install(repo, tools, base)
    assert result.returncode == 1
    assert result.stderr.strip() == f"missing {repo / missing}"
    assert not base.exists(), "nothing is created after a refused input check"
    assert not (tools / "uv-call.json").exists()


def test_a_symlink_in_a_copied_source_tree_is_refused(setup, tmp_path):
    repo, tools, base = setup
    outside = write(tmp_path / "writable/evil.py")
    (repo / "scripts/evil.py").symlink_to(outside)
    result = install(repo, tools, base)
    assert result.returncode != 0
    assert "evil.py: symlink in a copied source tree" in result.stderr
    assert not base.exists() and not (tools / "uv-call.json").exists()


@pytest.mark.parametrize(
    "weakness", ["group-writable base", "group-writable ancestor", "symlinked ancestor"]
)
def test_a_base_others_could_change_is_refused(setup, tmp_path, weakness):
    repo, tools, base = setup
    if weakness == "group-writable base":
        base.mkdir()
        base.chmod(0o775)
        expected = f"{base}: group-writable"
    elif weakness == "group-writable ancestor":
        base.parent.chmod(0o775)
        expected = f"{base.parent}: group-writable"
    else:
        real = tmp_path / "real"
        real.mkdir()
        real.chmod(0o755)
        link = tmp_path / "link"
        link.symlink_to(real)
        base = link / "services"
        expected = f"{link}: is a symlink"
    result = install(repo, tools, base)
    assert result.returncode != 0
    assert expected in result.stderr
    assert not (tools / "uv-call.json").exists()


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({"escaping_link": "/usr/lib"}, "links outside the snapshot"),
        ({"pth": "/opt/writable/site\n"}, "adds /opt/writable/site outside the snapshot"),
    ],
)
def test_a_snapshot_reaching_outside_itself_is_not_published(setup, extra, expected):
    repo, tools, base = setup
    result = install(repo, tools, base, extra=extra)
    assert result.returncode != 0
    assert expected in result.stderr
    assert not published(base)


@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs a C compiler to build an ELF")
def test_a_native_library_searching_outside_the_snapshot_is_not_published(setup, tmp_path):
    repo, tools, base = setup
    source = write(tmp_path / "native.c", "int native(void) { return 0; }\n")
    library = tmp_path / "native.so"
    build = ["gcc", "-shared", "-fPIC", "-o", str(library), str(source)]
    subprocess.run([*build, "-Wl,-rpath,/opt/writable/lib"], check=True)
    result = install(repo, tools, base, extra={"elf": str(library)})
    assert result.returncode != 0
    assert "search path /opt/writable/lib outside the snapshot" in result.stderr
    assert not published(base)
    # Without the outside search path the same library is accepted.
    subprocess.run(build, check=True)
    result = install(repo, tools, base, extra={"elf": str(library)})
    assert result.returncode == 0, result.stderr


CHECKER = INSTALLER.with_name("install-root-services-check.py")


def check_snapshot(dest):
    return subprocess.run(
        ["/usr/bin/python3", "-I", "-S", str(CHECKER), "snapshot", str(dest)],
        capture_output=True,
        text=True,
    )


def build_library(tmp_path, *flags):
    source = write(tmp_path / "native.c", "int native(void) { return 0; }\n")
    library = tmp_path / "built.so"
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(library), str(source), *flags], check=True)
    return library


@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs a C compiler to build an ELF")
@pytest.mark.parametrize(
    ("rpath", "expected"),
    [
        ("$ORIGIN/../../../../../../../../var/tmp/native-libs", "outside the snapshot"),
        ("$ORIGIN::$ORIGIN", "empty search path entry"),
        ("$ORIGIN/$LIB", "unsupported loader token"),
        ("$ORIGIN/../lib", None),
    ],
)
def test_origin_search_paths_are_expanded_and_contained(tmp_path, rpath, expected):
    dest = tmp_path / "snapshot"
    (dest / "venv/lib").mkdir(parents=True)
    library = build_library(tmp_path, f"-Wl,-rpath,{rpath}")
    shutil.copy(library, dest / "venv/lib/native.so")
    result = check_snapshot(dest)
    if expected is None:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode == 1
        assert expected in result.stderr


def test_a_link_through_an_outside_link_is_refused_even_if_it_ends_inside(tmp_path):
    dest = tmp_path / "snapshot"
    write(dest / "venv/lib/real.py")
    outside = tmp_path / "changeable"
    outside.mkdir()
    (outside / "hop").symlink_to(dest / "venv/lib/real.py")
    (dest / "venv/lib/module.py").symlink_to(outside / "hop")
    assert os.path.realpath(dest / "venv/lib/module.py") == str(dest / "venv/lib/real.py")
    result = check_snapshot(dest)
    assert result.returncode == 1
    assert "passes through" in result.stderr and "changeable" in result.stderr
    # A link that stays inside on every step is accepted.
    (dest / "venv/lib/module.py").unlink()
    (dest / "venv/lib/module.py").symlink_to("real.py")
    assert check_snapshot(dest).returncode == 0


def test_a_link_through_a_directory_that_points_back_up_is_refused(tmp_path):
    dest = tmp_path / "snapshot"
    (dest / "a").mkdir(parents=True)
    (dest / "a/up").symlink_to(".")  # resolves to dest/a itself
    # dest/a/up/../../x is dest/x lexically from the link, but the kernel resolves
    # up to dest/a first, so .. .. lands outside the snapshot.
    (dest / "a/escape").symlink_to("up/../../../outside")
    result = check_snapshot(dest)
    assert result.returncode == 1
    assert "escape" in result.stderr


@pytest.mark.parametrize(
    ("line", "module", "expected"),
    [
        ("import sys; sys.path.insert(0, '/var/tmp/external')", None, "unreviewed code"),
        ("import _virtualenv", "_virtualenv.py", None),
        ("import _virtualenv", None, "not in the snapshot"),
        ("../../../../../../../var/tmp/site", None, "outside the snapshot"),
    ],
)
def test_pth_lines_are_contained_or_reviewed(tmp_path, line, module, expected):
    site = tmp_path / "snapshot/venv/lib/site-packages"
    write(site / "hook.pth", line + "\n")
    if module:
        write(site / module)
    result = check_snapshot(tmp_path / "snapshot")
    if expected is None:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode == 1
        assert expected in result.stderr


def test_an_elf_file_readelf_cannot_read_is_refused(tmp_path):
    dest = tmp_path / "snapshot"
    broken = write(dest / "venv/lib/broken.so")
    broken.write_bytes(b"\x7fELF" + b"\x00" * 12)
    result = check_snapshot(dest)
    assert result.returncode == 1
    assert "readelf failed" in result.stderr
