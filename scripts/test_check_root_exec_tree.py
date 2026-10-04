"""The root-executed tree check refuses anything another user could change."""

import grp
import importlib.util
import os
import pwd
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parent / "check-root-exec-tree.py"
spec = importlib.util.spec_from_file_location("check_root_exec_tree", SOURCE)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

ME = os.getuid()


def tree(root):
    """A small code tree with explicit modes, independent of the umask."""
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    (root / "pkg").mkdir(mode=0o755)
    (root / "pkg").chmod(0o755)
    for name in ("main.py", "pkg/__init__.py"):
        (root / name).write_text("pass\n")
        (root / name).chmod(0o644)
    return root


def run(*args, trusted=ME):
    return checker.main(["--trusted-uid", str(trusted), *map(str, args)])


def test_a_tree_only_the_trusted_user_can_change_passes(tmp_path):
    assert run("--tree", tree(tmp_path / "code")) == 0


def test_a_world_writable_file_is_refused(tmp_path, capsys):
    code = tree(tmp_path / "code")
    (code / "pkg/__init__.py").chmod(0o646)
    assert run("--tree", code) == 1
    assert "pkg/__init__.py: writable by everyone" in capsys.readouterr().err


def test_a_world_writable_directory_inside_the_tree_is_refused_even_if_sticky(tmp_path):
    code = tree(tmp_path / "code")
    (code / "pkg").chmod(0o1777)
    assert run("--tree", code) == 1


def test_an_ancestor_is_accepted_only_if_sticky(tmp_path, capsys):
    shared = tmp_path / "shared"
    shared.mkdir()
    code = tree(shared / "code")
    shared.chmod(0o777)
    assert run("--tree", code) == 1
    assert f"{shared}: writable by everyone" in capsys.readouterr().err
    shared.chmod(0o1777)
    assert run("--tree", code) == 0


def test_files_owned_by_another_user_are_refused(tmp_path, capsys):
    code = tree(tmp_path / "code")
    assert run("--tree", code, trusted=ME + 12345) == 1
    assert f"owned by uid {ME}" in capsys.readouterr().err


def test_a_symlink_is_judged_by_what_it_points_to(tmp_path, capsys):
    code = tree(tmp_path / "code")
    outside = tmp_path / "outside.py"
    outside.write_text("pass\n")
    outside.chmod(0o666)
    (code / "pkg/linked.py").symlink_to(outside)
    assert run("--tree", code) == 1
    assert f"{outside}: writable by everyone" in capsys.readouterr().err
    outside.chmod(0o644)
    assert run("--tree", code) == 0


def test_a_symlinked_directory_is_walked(tmp_path):
    code = tree(tmp_path / "code")
    other = tree(tmp_path / "other")
    (other / "main.py").chmod(0o666)
    (code / "vendor").symlink_to(other)
    assert run("--tree", code) == 1


def test_ignore_skips_exactly_one_path(tmp_path):
    code = tree(tmp_path / "code")
    (code / ".lock").write_text("")
    (code / ".lock").chmod(0o666)
    assert run("--tree", code) == 1
    assert run("--tree", code, "--ignore", code / ".lock") == 0
    (code / "main.py").chmod(0o666)
    assert run("--tree", code, "--ignore", code / ".lock") == 1


def test_a_path_is_checked_without_walking_its_siblings(tmp_path):
    code = tree(tmp_path / "code")
    (code / "pkg/__init__.py").chmod(0o666)
    assert run("--path", code / "main.py") == 0
    assert run("--path", code / "pkg/__init__.py") == 1


def test_a_missing_path_is_refused(tmp_path, capsys):
    assert run("--path", tmp_path / "absent.so") == 1
    assert "absent.so" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("members", "primary", "private"),
    [
        ([], [], True),
        (["trusted"], ["trusted"], True),
        (["intruder"], [], False),
        ([], ["intruder"], False),
        (["ghost"], [], False),  # a member no account resolves to
    ],
)
def test_group_write_is_allowed_only_for_a_group_nobody_else_is_in(
    monkeypatch, members, primary, private
):
    uids = {"trusted": 1000, "intruder": 2000}
    monkeypatch.setattr(grp, "getgrgid", lambda gid: SimpleNamespace(gr_mem=members))

    def getpwnam(name):
        if name not in uids:
            raise KeyError(name)
        return SimpleNamespace(pw_uid=uids[name])

    monkeypatch.setattr(pwd, "getpwnam", getpwnam)
    monkeypatch.setattr(
        pwd, "getpwall", lambda: [SimpleNamespace(pw_uid=uids[n], pw_gid=77) for n in primary]
    )
    assert checker.Checker(1000).group_is_private(77) is private


def test_a_negative_trusted_uid_is_rejected():
    with pytest.raises(SystemExit):
        checker.main(["--trusted-uid", "-1", "--path", "/"])
