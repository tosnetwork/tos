#!/usr/bin/env python3
"""Tests for scripts/pin-image-digest.py against the committed deployment manifests."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("pin_image_digest", HERE / "pin-image-digest.py")
assert SPEC is not None and SPEC.loader is not None
pin_image_digest = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pin_image_digest
SPEC.loader.exec_module(pin_image_digest)

MANIFESTS = sorted((HERE.parent / "docker").glob("tos-*.yaml"))
DIGEST = "sha256:" + "4f" * 32
RECORD = {
    "image": "ghcr.io/tosnetwork/tos",
    "digest": DIGEST,
    "tag": "v2026.10",
    "source_commit": "c" * 40,
    "run_url": "https://github.com/tosnetwork/tos/actions/runs/123",
}


class PinImageDigestTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="pin-image-")
        self.root = Path(self._tmp.name)
        self.manifests = []
        for manifest in MANIFESTS:
            copy = self.root / manifest.name
            shutil.copyfile(manifest, copy)
            self.manifests.append(copy)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_pin(self, record: dict[str, str]) -> int:
        path = self.root / "image-release.json"
        path.write_text(json.dumps(record))
        return pin_image_digest.main(["--record", str(path), *map(str, self.manifests)])

    def test_committed_manifests_are_found(self) -> None:
        self.assertEqual(len(MANIFESTS), 5)

    def test_pins_every_manifest_with_provenance(self) -> None:
        self.assertEqual(self.run_pin(RECORD), 0)
        for manifest in self.manifests:
            text = manifest.read_text()
            self.assertIn(f"image: ghcr.io/tosnetwork/tos@{DIGEST}\n", text)
            self.assertIn("image-provenance: release v2026.10 built from " + "c" * 40, text)
            self.assertIn("# by https://github.com/tosnetwork/tos/actions/runs/123", text)
            self.assertNotIn("unreleased", text)
            self.assertEqual(text.count("image-provenance:"), 1)

    def test_repinning_replaces_the_previous_provenance(self) -> None:
        self.assertEqual(self.run_pin(RECORD), 0)
        newer = dict(RECORD, digest="sha256:" + "5e" * 32, tag="v2026.11")
        self.assertEqual(self.run_pin(newer), 0)
        for manifest in self.manifests:
            text = manifest.read_text()
            self.assertIn("@sha256:" + "5e" * 32, text)
            self.assertNotIn(DIGEST, text)
            self.assertEqual(text.count("image-provenance:"), 1)

    def assert_refused(self, record: dict[str, str]) -> None:
        before = [manifest.read_text() for manifest in self.manifests]
        self.assertEqual(self.run_pin(record), 1)
        self.assertEqual([manifest.read_text() for manifest in self.manifests], before)

    def test_placeholder_digest_is_refused(self) -> None:
        self.assert_refused(dict(RECORD, digest="sha256:" + "0" * 64))

    def test_malformed_digest_is_refused(self) -> None:
        self.assert_refused(dict(RECORD, digest="sha256:abc"))

    def test_other_image_is_refused(self) -> None:
        self.assert_refused(dict(RECORD, image="ghcr.io/someone/tos"))

    def test_missing_source_commit_is_refused(self) -> None:
        record = dict(RECORD)
        del record["source_commit"]
        self.assert_refused(record)

    def test_untraceable_run_is_refused(self) -> None:
        self.assert_refused(dict(RECORD, run_url="https://example.invalid/run"))


if __name__ == "__main__":
    unittest.main()
