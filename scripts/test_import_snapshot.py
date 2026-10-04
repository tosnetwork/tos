#!/usr/bin/env python3
"""Offline tests for docker/import-snapshot.sh.

Every archive is served from a file:// URL, so no test touches the network.
plzip is replaced by a stub that copies its input, and the archives are plain
tar files: the tests exercise the import policy, not the lzip codec.

Each refusal test checks three things: the script exits non-zero, it prints
the refusal the case is about (so an unrelated error cannot pass the test),
and the database directory is byte-for-byte what it was before, with no
success marker.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "docker" / "import-snapshot.sh"
ZEROSTATE = "F6OpKZKqvqeFp6CQmFomXNMfMj2EnaUSOXN+Mh+wVWk="
OTHER_ZEROSTATE = "XplPz01CXAps5qeSWUtxcyBfdAo5zVb1N979KLSKD24="

PLZIP_STUB = """#!/bin/sh
# Test stand-in for plzip: "-d -c FILE" writes FILE unchanged.
#
# The import decompresses twice: once to list, once to unpack. Two optional
# hooks act on the second call only, to model what the listing cannot see:
#   PLZIP_STUB_SECOND  write this file instead, so the unpacked tree differs
#                      from the listing that was checked;
#   PLZIP_STUB_TOUCH   create this path first, as if something wrote into the
#                      database while the archive was staged.
for last; do :; done
if [ -n "${PLZIP_STUB_STATE:-}" ]; then
  if [ -e "$PLZIP_STUB_STATE" ]; then
    if [ -n "${PLZIP_STUB_TOUCH:-}" ]; then
      printf 'appeared during staging' >"$PLZIP_STUB_TOUCH"
    fi
    if [ -n "${PLZIP_STUB_SECOND:-}" ]; then
      exec cat -- "$PLZIP_STUB_SECOND"
    fi
  else
    : >"$PLZIP_STUB_STATE"
  fi
fi
exec cat -- "$last"
"""


def tar_bytes(members: list[tuple[str, str, bytes | str]]) -> bytes:
    """Build a tar archive. Each member is (name, kind, payload)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            info.mtime = 1_700_000_000
            if kind == "file":
                assert isinstance(payload, bytes)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = str(payload)
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = str(payload)
                archive.addfile(info)
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
                archive.addfile(info)
            else:
                raise ValueError(kind)
    return buffer.getvalue()


GOOD_MEMBERS: list[tuple[str, str, bytes | str]] = [
    ("archive", "dir", b""),
    ("archive/packages", "dir", b""),
    ("archive/packages/arch0000.pack", "file", b"block data"),
    ("celldb", "dir", b""),
    ("celldb/CURRENT", "file", b"MANIFEST-000001\n"),
    ("state", "dir", b""),
]


def tree(root: Path) -> dict[str, tuple[str, bytes]]:
    snapshot: dict[str, tuple[str, bytes]] = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            snapshot[relative] = ("link", os.readlink(path).encode())
        elif stat.S_ISDIR(mode):
            snapshot[relative] = ("dir", b"")
        else:
            snapshot[relative] = ("file", path.read_bytes())
    return snapshot


class ImportSnapshotTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="import-snapshot-")
        root = Path(self._tmp.name)
        self.root = root
        self.extra_env: dict[str, str] = {}
        self.db = root / "volume" / "db"
        self.staging = root / "volume" / "staging"
        self.served = root / "served"
        self.bin = root / "bin"
        for directory in (self.db, self.served, self.bin):
            directory.mkdir(parents=True)
        stub = self.bin / "plzip"
        stub.write_text(PLZIP_STUB)
        stub.chmod(0o755)
        # The state a freshly initialized node has before any import.
        (self.db / "config.json").write_text('{"node":"identity"}')
        (self.db / "keyring").mkdir()
        (self.db / "keyring" / "server").write_bytes(b"private key")
        (self.db / "tos-global.config").write_text(
            json.dumps({"validator": {"zero_state": {"root_hash": ZEROSTATE}}})
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def serve(self, payload: bytes, name: str = "snapshot.tar.lz") -> tuple[str, str]:
        path = self.served / name
        path.write_bytes(payload)
        return path.as_uri(), hashlib.sha256(payload).hexdigest()

    def run_import(self, **env_overrides: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "TOS_DB_DIR": str(self.db),
            "SNAPSHOT_STAGING_DIR": str(self.staging),
            **self.extra_env,
        }
        env.update(env_overrides)
        return subprocess.run(
            ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=120, check=False
        )

    def enabled(self, url: str, digest: str, **extra: str) -> dict[str, str]:
        env = {
            "SNAPSHOT_IMPORT": "1",
            "DUMP_URL": url,
            "DUMP_SHA256": digest,
            "DUMP_ZEROSTATE_ROOT_HASH": ZEROSTATE,
        }
        env.update(extra)
        return env

    def assert_refused(
        self, result: subprocess.CompletedProcess[str], reason: str, before: dict
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(reason, result.stderr)
        self.assertEqual(tree(self.db), before, "a refused import changed the database")
        self.assertFalse((self.db / ".snapshot-imported").exists())
        if self.staging.exists():
            self.assertEqual(list(self.staging.iterdir()), [], "a refused import left staging data")

    def assert_member_refused(
        self, members: list[tuple[str, str, bytes | str]], reason: str
    ) -> None:
        url, digest = self.serve(tar_bytes(members))
        before = tree(self.db)
        self.assert_refused(self.run_import(**self.enabled(url, digest)), reason, before)

    # ---- opt-in and configuration

    def test_no_request_is_a_no_op(self) -> None:
        before = tree(self.db)
        result = self.run_import()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(tree(self.db), before)

    def test_url_without_opt_in_is_refused(self) -> None:
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        before = tree(self.db)
        result = self.run_import(
            DUMP_URL=url, DUMP_SHA256=digest, DUMP_ZEROSTATE_ROOT_HASH=ZEROSTATE
        )
        self.assert_refused(result, "SNAPSHOT_IMPORT is not enabled", before)

    def test_unknown_opt_in_value_is_refused(self) -> None:
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        before = tree(self.db)
        result = self.run_import(**self.enabled(url, digest, SNAPSHOT_IMPORT="yes"))
        self.assert_refused(result, "SNAPSHOT_IMPORT must be", before)

    def test_missing_digest_is_refused(self) -> None:
        url, _ = self.serve(tar_bytes(GOOD_MEMBERS))
        before = tree(self.db)
        result = self.run_import(**self.enabled(url, ""))
        self.assert_refused(result, "DUMP_SHA256 must be", before)

    def test_malformed_digest_is_refused(self) -> None:
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        before = tree(self.db)
        result = self.run_import(**self.enabled(url, digest[:-1] + "g"))
        self.assert_refused(result, "DUMP_SHA256 must be", before)

    def test_missing_network_binding_is_refused(self) -> None:
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        before = tree(self.db)
        result = self.run_import(**self.enabled(url, digest, DUMP_ZEROSTATE_ROOT_HASH=""))
        self.assert_refused(result, "DUMP_ZEROSTATE_ROOT_HASH must name", before)

    def test_snapshot_for_another_network_is_refused(self) -> None:
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        before = tree(self.db)
        result = self.run_import(
            **self.enabled(url, digest, DUMP_ZEROSTATE_ROOT_HASH=OTHER_ZEROSTATE)
        )
        self.assert_refused(result, f"does not match zero state {ZEROSTATE}", before)
        # The message must not present the comparison as authentication.
        self.assertIn("authenticates neither", result.stderr)

    def test_opt_in_without_url_is_refused(self) -> None:
        before = tree(self.db)
        result = self.run_import(**self.enabled("", "0" * 64))
        self.assert_refused(result, "DUMP_URL is empty", before)

    def test_missing_global_config_is_refused(self) -> None:
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        (self.db / "tos-global.config").unlink()
        before = tree(self.db)
        result = self.run_import(**self.enabled(url, digest))
        self.assert_refused(result, "tos-global.config is missing", before)

    def test_global_config_without_zero_state_is_refused(self) -> None:
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        (self.db / "tos-global.config").write_text("{}")
        before = tree(self.db)
        result = self.run_import(**self.enabled(url, digest))
        self.assert_refused(result, "cannot read validator.zero_state.root_hash", before)

    def test_plain_http_is_refused(self) -> None:
        _, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        before = tree(self.db)
        result = self.run_import(**self.enabled("http://127.0.0.1:9/snapshot.tar.lz", digest))
        self.assert_refused(result, "must be an https:// or file:// URL", before)

    def test_staging_inside_database_is_refused(self) -> None:
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        self.staging = self.db / "staging"
        before = tree(self.db)
        result = self.run_import(**self.enabled(url, digest))
        self.assert_refused(result, "is inside the database directory", before)

    # ---- content authentication and download

    def test_digest_mismatch_is_refused(self) -> None:
        url, _ = self.serve(tar_bytes(GOOD_MEMBERS))
        before = tree(self.db)
        result = self.run_import(**self.enabled(url, "0" * 64))
        self.assert_refused(result, "does not match DUMP_SHA256", before)

    def test_failed_download_is_refused(self) -> None:
        before = tree(self.db)
        missing = (self.served / "absent.tar.lz").as_uri()
        result = self.run_import(**self.enabled(missing, "0" * 64))
        self.assert_refused(result, "download failed", before)

    def test_corrupt_stream_with_matching_digest_is_refused(self) -> None:
        # The digest authenticates the bytes; it does not make them a valid
        # archive. Decompression or listing failure must still fail closed.
        self.assert_member_refused_payload(
            b"this is not a tar stream" * 64, "cannot be decompressed and listed"
        )

    def assert_member_refused_payload(self, payload: bytes, reason: str) -> None:
        url, digest = self.serve(payload)
        before = tree(self.db)
        self.assert_refused(self.run_import(**self.enabled(url, digest)), reason, before)

    def test_empty_archive_is_refused(self) -> None:
        self.assert_member_refused_payload(tar_bytes([]), "archive is empty")

    def test_archive_of_only_its_root_is_refused(self) -> None:
        self.assert_member_refused([("./", "dir", b"")], "archive unpacked to nothing")

    # ---- member policy

    def test_absolute_member_is_refused(self) -> None:
        self.assert_member_refused(
            [*GOOD_MEMBERS, ("/etc/cron.d/x", "file", b"x")], "absolute name"
        )

    def test_parent_traversal_member_is_refused(self) -> None:
        self.assert_member_refused(
            [*GOOD_MEMBERS, ("celldb/../../escape", "file", b"x")], "escapes its directory"
        )

    def test_symlink_member_is_refused(self) -> None:
        self.assert_member_refused(
            [*GOOD_MEMBERS, ("celldb/link", "symlink", "/etc")], "neither a regular file"
        )

    def test_hardlink_member_is_refused(self) -> None:
        self.assert_member_refused(
            [*GOOD_MEMBERS, ("celldb/hard", "hardlink", "celldb/CURRENT")], "neither a regular file"
        )

    def test_special_file_member_is_refused(self) -> None:
        self.assert_member_refused(
            [*GOOD_MEMBERS, ("celldb/pipe", "fifo", b"")], "neither a regular file"
        )

    def test_node_config_member_is_refused(self) -> None:
        self.assert_member_refused(
            [*GOOD_MEMBERS, ("config.json", "file", b"{}")],
            "archive member overwrites the node's own config.json",
        )

    def test_keyring_member_is_refused(self) -> None:
        self.assert_member_refused(
            [*GOOD_MEMBERS, ("./keyring/server", "file", b"k")],
            "archive member overwrites the node's own keyring",
        )

    # ---- repeated '.' components and other spellings of a reserved name.
    # The reserved destination is removed first, so only the member policy
    # stands between the archive and the node's identity: no collision with an
    # existing entry can be what refuses these.

    def assert_spelling_refused(self, member: str, kind: str, reserved: str) -> None:
        # The global config moves out of the database so that the database
        # starts out empty.
        outside = self.root / "tos-global.config"
        (self.db / "tos-global.config").rename(outside)
        self.extra_env["TOS_GLOBAL_CONFIG"] = str(outside)
        (self.db / "config.json").unlink()
        for path in sorted((self.db / "keyring").iterdir()):
            path.unlink()
        (self.db / "keyring").rmdir()
        self.assertEqual(sorted(p.name for p in self.db.iterdir()), [])
        payload: bytes | str = b"x" if kind == "file" else b""
        self.assert_member_refused(
            [*GOOD_MEMBERS, (member, kind, payload)],
            f"archive member overwrites the node's own {reserved}: ",
        )

    def test_repeated_dot_keyring_is_refused(self) -> None:
        self.assert_spelling_refused("././keyring/server", "file", "keyring")

    def test_many_dots_keyring_is_refused(self) -> None:
        self.assert_spelling_refused("./././././keyring/server", "file", "keyring")

    def test_doubled_slash_keyring_is_refused(self) -> None:
        self.assert_spelling_refused(".//keyring/server", "file", "keyring")

    def test_dot_slash_dot_keyring_is_refused(self) -> None:
        self.assert_spelling_refused("././/./keyring", "dir", "keyring")

    def test_trailing_slash_keyring_dir_is_refused(self) -> None:
        self.assert_spelling_refused("keyring/", "dir", "keyring")

    def test_repeated_dot_config_is_refused(self) -> None:
        self.assert_spelling_refused("././config.json", "file", "config.json")

    def test_repeated_dot_global_config_is_refused(self) -> None:
        self.assert_spelling_refused(".//./tos-global.config", "file", "tos-global.config")

    def test_repeated_dot_marker_is_refused(self) -> None:
        self.assert_spelling_refused("././.snapshot-imported", "file", ".snapshot-imported")

    def test_parent_then_reserved_is_refused(self) -> None:
        self.assert_member_refused(
            [*GOOD_MEMBERS, ("celldb/../keyring/server", "file", b"k")], "escapes its directory"
        )

    def test_dot_root_entries_are_accepted(self) -> None:
        url, digest = self.serve(
            tar_bytes([("./.", "dir", b""), (".//", "dir", b""), *GOOD_MEMBERS])
        )
        result = self.run_import(**self.enabled(url, digest))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.db / "celldb" / "CURRENT").read_bytes(), b"MANIFEST-000001\n")

    # ---- the unpacked tree is checked independently of the listing

    def assert_unpacked_refused(
        self, unpacked: list[tuple[str, str, bytes | str]], reason: str
    ) -> None:
        (self.db / "keyring" / "server").unlink()
        (self.db / "keyring").rmdir()
        second = self.served / "second.tar"
        second.write_bytes(tar_bytes(unpacked))
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        before = tree(self.db)
        result = self.run_import(
            **self.enabled(url, digest),
            PLZIP_STUB_STATE=str(self.root / "plzip-called"),
            PLZIP_STUB_SECOND=str(second),
        )
        self.assert_refused(result, reason, before)

    def test_unpacked_reserved_name_is_refused(self) -> None:
        self.assert_unpacked_refused(
            [*GOOD_MEMBERS, ("keyring/server", "file", b"k")],
            "unpacked archive carries the node's own keyring",
        )

    def test_unpacked_symlink_is_refused(self) -> None:
        self.assert_unpacked_refused(
            [*GOOD_MEMBERS, ("celldb/link", "symlink", "/etc")],
            "unpacked archive contains something that is neither a regular file nor a directory: "
            "celldb/link",
        )

    def test_unpacked_hardlink_is_refused(self) -> None:
        self.assert_unpacked_refused(
            [*GOOD_MEMBERS, ("celldb/hard", "hardlink", "celldb/CURRENT")],
            "unpacked archive contains a hard-linked file",
        )

    # ---- the destination must be a new database

    def test_existing_chain_data_is_refused_before_download(self) -> None:
        # The URL cannot be fetched: refusing with this message proves the
        # destination was checked before any network access.
        (self.db / "celldb").mkdir()
        (self.db / "celldb" / "CURRENT").write_bytes(b"existing")
        before = tree(self.db)
        missing = (self.served / "absent.tar.lz").as_uri()
        result = self.run_import(**self.enabled(missing, "0" * 64))
        self.assert_refused(result, "the database directory is not new: it contains celldb", before)

    def test_unrelated_existing_content_is_refused(self) -> None:
        # Nothing in the snapshot collides with it; the database is still not new.
        (self.db / "files").mkdir()
        (self.db / "files" / "packages.db").write_bytes(b"older chain data")
        (self.db / "notes.txt").write_bytes(b"operator notes")
        self.assert_member_refused(GOOD_MEMBERS, "the database directory is not new: it contains")

    def test_keyring_that_is_not_a_directory_is_refused(self) -> None:
        (self.db / "keyring" / "server").unlink()
        (self.db / "keyring").rmdir()
        (self.db / "keyring").symlink_to(self.root)
        self.assert_member_refused(GOOD_MEMBERS, "database entry keyring is not a directory")

    def test_config_that_is_not_a_regular_file_is_refused(self) -> None:
        (self.db / "config.json").unlink()
        (self.db / "config.json").symlink_to(self.root / "elsewhere.json")
        self.assert_member_refused(GOOD_MEMBERS, "database entry config.json is not a regular file")

    def test_non_empty_lost_and_found_is_refused(self) -> None:
        (self.db / "lost+found").mkdir()
        (self.db / "lost+found" / "#12").write_bytes(b"recovered")
        self.assert_member_refused(
            GOOD_MEMBERS, "database entry lost+found is not an empty directory"
        )

    def test_content_appearing_during_staging_is_refused(self) -> None:
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        intruder = self.db / "appeared"
        before = tree(self.db)
        result = self.run_import(
            **self.enabled(url, digest),
            PLZIP_STUB_STATE=str(self.root / "plzip-called"),
            PLZIP_STUB_TOUCH=str(intruder),
        )
        before["appeared"] = ("file", b"appeared during staging")
        self.assert_refused(
            result, "the database directory is not new: it contains appeared", before
        )

    # ---- markers

    def test_legacy_unverified_import_is_refused(self) -> None:
        (self.db / "dump_downloaded").write_bytes(b"")
        self.assert_member_refused(GOOD_MEMBERS, "earlier unverified snapshot import")

    def test_marker_for_another_snapshot_is_refused(self) -> None:
        (self.db / ".snapshot-imported").write_text("1" * 64)
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        before = tree(self.db)
        result = self.run_import(**self.enabled(url, digest))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already holds snapshot", result.stderr)
        self.assertEqual(tree(self.db), before)

    # ---- success

    def test_empty_lost_and_found_is_accepted(self) -> None:
        (self.db / "lost+found").mkdir()
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        result = self.run_import(**self.enabled(url, digest))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.db / ".snapshot-imported").read_text(), digest)
        self.assertEqual(list((self.db / "lost+found").iterdir()), [])

    def test_verified_snapshot_is_installed_and_marked(self) -> None:
        url, digest = self.serve(tar_bytes(GOOD_MEMBERS))
        result = self.run_import(**self.enabled(url, digest.upper()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.db / "archive" / "packages" / "arch0000.pack").read_bytes(), b"block data"
        )
        self.assertEqual((self.db / "celldb" / "CURRENT").read_bytes(), b"MANIFEST-000001\n")
        self.assertTrue((self.db / "state").is_dir())
        self.assertEqual((self.db / ".snapshot-imported").read_text(), digest)
        # The node's own identity is untouched.
        self.assertEqual((self.db / "keyring" / "server").read_bytes(), b"private key")
        self.assertEqual(list(self.staging.iterdir()), [])

        installed = tree(self.db)
        rerun = self.run_import(**self.enabled(url, digest))
        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertIn("already imported", rerun.stdout)
        self.assertEqual(tree(self.db), installed)


if __name__ == "__main__":
    unittest.main()
