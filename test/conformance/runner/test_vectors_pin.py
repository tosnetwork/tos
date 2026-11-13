#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the external vectors pin check. Each check is shown to fail on a controlled defect."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vectors_pin as vp  # noqa: E402

FIXTURE = {
    "metadata": {
        "harness": "vm",
        "harness_version": 1,
        "fixture_id": "case-0",
        "family": "sample",
        "source": "authored",
        "reference_commit": "0123456789abcdef0123456789abcdef01234567",
    },
    "context": {
        "code": "te6ccgEBAQEAAwAAAXA=",
        "global_version": 16,
        "gas": {"limit": 1, "max": 1},
        "stack": [],
    },
    "effects": {
        "exit_code": 0,
        "gas_used": 1,
        "steps": 1,
        "committed": False,
        "c4_hash": None,
        "c5_hash": None,
        "stack": [],
    },
}


def git(root: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


class PinTests(unittest.TestCase):
    root: Path = Path()
    pin: Path = Path()

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "vectors"
        family = self.root / "vm" / "fixtures" / "sample.jsonl"
        family.parent.mkdir(parents=True)
        family.write_text(json.dumps(FIXTURE) + "\n")
        (self.root / vp.MANIFEST).write_text(json.dumps(vp.build_manifest(self.root)))
        git(self.root.parent, "init", "-q", str(self.root))
        git(self.root, "add", "-A")
        git(
            self.root,
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-q",
            "-m",
            "v",
        )
        self.pin = Path(tmp.name) / "VECTORS"
        self.write_pin(git(self.root, "rev-parse", "HEAD"))

    def write_pin(self, commit: str) -> None:
        self.pin.write_text(
            json.dumps({"repository": "https://example.invalid/vectors", "commit": commit})
        )

    def commit(self) -> None:
        git(self.root, "add", "-A")
        git(
            self.root,
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-q",
            "-m",
            "c",
        )

    def test_pinned_clean_checkout_passes(self) -> None:
        self.assertEqual(vp.check(self.root, self.pin), [])

    def test_other_commit_fails(self) -> None:
        self.write_pin("f" * 40)
        self.assertTrue(any("pins" in p for p in vp.check(self.root, self.pin)))

    def test_local_change_fails(self) -> None:
        (self.root / "vm" / "fixtures" / "sample.jsonl").write_text(json.dumps(FIXTURE) + "\n\n")
        self.assertTrue(any("local changes" in p for p in vp.check(self.root, self.pin)))

    def test_unlisted_file_fails(self) -> None:
        (self.root / "vm" / "fixtures" / "extra.jsonl").write_text(json.dumps(FIXTURE) + "\n")
        self.commit()
        self.write_pin(git(self.root, "rev-parse", "HEAD"))
        self.assertTrue(any("not listed" in p for p in vp.check(self.root, self.pin)))

    def test_digest_mismatch_fails(self) -> None:
        manifest = json.loads((self.root / vp.MANIFEST).read_text())
        manifest["files"]["vm/fixtures/sample.jsonl"]["sha256"] = "0" * 64
        (self.root / vp.MANIFEST).write_text(json.dumps(manifest))
        self.commit()
        self.write_pin(git(self.root, "rev-parse", "HEAD"))
        self.assertTrue(any("digest" in p for p in vp.check(self.root, self.pin)))


if __name__ == "__main__":
    unittest.main()
