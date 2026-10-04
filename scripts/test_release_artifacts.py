#!/usr/bin/env python3
"""Offline tests for scripts/release-artifacts.py.

The GitHub API is replaced by fixtures, so each test states exactly which runs
and artifacts exist. Refusal tests check the specific reason, not merely that
something failed.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("release_artifacts", HERE / "release-artifacts.py")
assert SPEC is not None and SPEC.loader is not None
release_artifacts = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_artifacts
SPEC.loader.exec_module(release_artifacts)
ReleaseError = release_artifacts.ReleaseError

REPO = "example-org/chain"
TAG_SHA = "a" * 40
OTHER_SHA = "b" * 40
WORKFLOW = "build-linux.yml"


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def run(run_id: int, **overrides: Any) -> dict[str, Any]:
    record = {
        "id": run_id,
        "run_attempt": 1,
        "head_sha": TAG_SHA,
        "status": "completed",
        "conclusion": "success",
        "event": "push",
        "path": f".github/workflows/{WORKFLOW}",
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
        "html_url": f"https://example.invalid/runs/{run_id}",
    }
    record.update(overrides)
    return record


class FakeApi:
    def __init__(
        self,
        runs: list[dict[str, Any]],
        payload: bytes,
        *,
        digest: str | None = None,
        **artifact: Any,
    ):
        self.runs = runs
        self.payload = payload
        self.artifact = {
            "id": 900,
            "name": "tos-linux",
            "expired": False,
            "digest": digest
            if digest is not None
            else "sha256:" + hashlib.sha256(payload).hexdigest(),
            "workflow_run": {"id": None, "head_sha": TAG_SHA},
        }
        self.artifact.update(artifact)
        self.served = payload
        self.requests: list[str] = []

    def get_json(self, path: str) -> Any:
        self.requests.append(path)
        if "/workflows/" in path:
            return {"workflow_runs": self.runs}
        if "/runs/" in path:
            run_id = int(path.split("/runs/")[1].split("/")[0])
            artifact = dict(self.artifact)
            if artifact["workflow_run"]["id"] is None:
                artifact["workflow_run"] = {**artifact["workflow_run"], "id": run_id}
            return {"artifacts": [artifact]}
        raise AssertionError(path)

    def download(self, path: str, destination: Path) -> None:
        self.requests.append(path)
        destination.write_bytes(self.served)


CONFIG = {
    "build_workflows": [{"artifact": "tos-linux", "workflow": WORKFLOW}],
    "release_sets": {
        "full": {
            "assets": [
                {"artifact": "tos-linux", "zip": True, "name": "tos-linux.zip"},
                {"artifact": "tos-linux", "path": "fift", "name": "fift-linux"},
            ],
            "bundles": [
                {"artifact": "tos-linux", "directories": ["smartcont"], "name": "smartcont_lib.zip"}
            ],
        }
    },
}

GOOD_ZIP = zip_bytes({"fift": b"\x7fELF fift", "smartcont/wallet.fc": b";; wallet"})


class SelectRunTest(unittest.TestCase):
    def select(self, runs: list[dict[str, Any]]) -> Any:
        return release_artifacts.select_run(runs, repo=REPO, workflow=WORKFLOW, tag_sha=TAG_SHA)

    def assert_refused(self, runs: list[dict[str, Any]], reason: str) -> None:
        with self.assertRaises(ReleaseError) as caught:
            self.select(runs)
        self.assertIn(reason, str(caught.exception))

    def test_run_of_the_tag_commit_is_selected(self) -> None:
        chosen = self.select([run(7)])
        self.assertEqual((chosen.run_id, chosen.head_sha), (7, TAG_SHA))

    def test_newest_qualifying_run_is_selected(self) -> None:
        self.assertEqual(self.select([run(7), run(9), run(8)]).run_id, 9)

    def test_no_runs_is_refused(self) -> None:
        self.assert_refused([], "no runs at all")

    def test_run_of_another_commit_is_never_used(self) -> None:
        # The newest successful run of the branch is of a different commit;
        # it must not stand in for the tag.
        self.assert_refused([run(99, head_sha=OTHER_SHA)], "is not the tag commit")

    def test_failed_run_is_refused(self) -> None:
        self.assert_refused([run(7, conclusion="failure")], "is not completed/success")

    def test_unfinished_run_is_refused(self) -> None:
        self.assert_refused(
            [run(7, status="in_progress", conclusion=None)], "is not completed/success"
        )

    def test_pull_request_run_is_refused(self) -> None:
        self.assert_refused([run(7, event="pull_request")], "event pull_request")

    def test_pull_request_target_run_is_refused(self) -> None:
        self.assert_refused([run(7, event="pull_request_target")], "event pull_request_target")

    def test_fork_head_is_refused(self) -> None:
        self.assert_refused(
            [run(7, head_repository={"full_name": "someone/fork"})], "another repository's head"
        )

    def test_other_repository_is_refused(self) -> None:
        self.assert_refused(
            [run(7, repository={"full_name": "someone/fork"})], "another repository"
        )

    def test_other_workflow_is_refused(self) -> None:
        self.assert_refused([run(7, path=".github/workflows/other.yml")], "not build-linux.yml")

    def test_abbreviated_tag_commit_is_refused(self) -> None:
        # Even a run that reports the same abbreviation is not accepted: an
        # abbreviated SHA does not name one commit.
        short = TAG_SHA[:12]
        with self.assertRaises(ReleaseError) as caught:
            release_artifacts.select_run(
                [run(7, head_sha=short)], repo=REPO, workflow=WORKFLOW, tag_sha=short
            )
        self.assertIn("full 40-character", str(caught.exception))


class CollectTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="release-artifacts-")
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def collect(self, api: FakeApi) -> dict[str, Any]:
        return release_artifacts.collect(
            api, CONFIG, repo=REPO, tag="v2026.10", tag_sha=TAG_SHA, out=self.root / "artifacts"
        )

    def assert_refused(self, api: FakeApi, reason: str) -> None:
        with self.assertRaises(ReleaseError) as caught:
            self.collect(api)
        self.assertIn(reason, str(caught.exception))
        self.assertFalse((self.root / "artifacts" / "release-provenance.json").exists())
        self.assertFalse((self.root / "artifacts" / "tos-linux").exists())

    def test_collect_binds_run_artifact_and_digest(self) -> None:
        api = FakeApi([run(41), run(42, head_sha=OTHER_SHA)], GOOD_ZIP)
        provenance = self.collect(api)
        self.assertEqual(provenance["tag_commit"], TAG_SHA)
        (record,) = provenance["artifacts"]
        self.assertEqual(record["run_id"], 41)
        self.assertEqual(record["head_sha"], TAG_SHA)
        self.assertEqual(record["artifact_id"], 900)
        self.assertEqual(
            record["artifact_digest"], "sha256:" + hashlib.sha256(GOOD_ZIP).hexdigest()
        )
        self.assertIn(
            f"repos/{REPO}/actions/runs/41/artifacts?name=tos-linux&per_page=100", api.requests
        )
        self.assertIn(f"repos/{REPO}/actions/artifacts/900/zip", api.requests)
        self.assertEqual(
            (self.root / "artifacts" / "tos-linux" / "fift").read_bytes(), b"\x7fELF fift"
        )
        written = json.loads((self.root / "artifacts" / "release-provenance.json").read_text())
        self.assertEqual(written, provenance)

    def test_runs_are_queried_by_tag_commit(self) -> None:
        api = FakeApi([run(41)], GOOD_ZIP)
        self.collect(api)
        self.assertTrue(
            api.requests[0].endswith(f"runs?head_sha={TAG_SHA}&status=success&per_page=100")
        )

    def test_digest_mismatch_is_refused(self) -> None:
        api = FakeApi([run(41)], GOOD_ZIP)
        api.served = zip_bytes({"fift": b"tampered"})
        self.assert_refused(api, "does not match recorded")

    def test_missing_digest_is_refused(self) -> None:
        self.assert_refused(FakeApi([run(41)], GOOD_ZIP, digest=""), "carries no sha256 digest")

    def test_artifact_of_another_run_is_refused(self) -> None:
        api = FakeApi([run(41)], GOOD_ZIP, workflow_run={"id": 40, "head_sha": TAG_SHA})
        self.assert_refused(api, "is not bound to run 41")

    def test_artifact_of_another_commit_is_refused(self) -> None:
        api = FakeApi([run(41)], GOOD_ZIP, workflow_run={"id": None, "head_sha": OTHER_SHA})
        self.assert_refused(api, "is not bound to run 41")

    def test_expired_artifact_is_refused(self) -> None:
        self.assert_refused(FakeApi([run(41)], GOOD_ZIP, expired=True), "has expired")

    def test_misnamed_artifact_is_refused(self) -> None:
        self.assert_refused(
            FakeApi([run(41)], GOOD_ZIP, name="tos-other"), "has 0 artifacts named tos-linux"
        )

    def test_traversing_zip_member_is_refused(self) -> None:
        payload = zip_bytes({"../escape": b"x"})
        self.assert_refused(FakeApi([run(41)], payload), "escapes the artifact directory")

    def test_symlink_zip_member_is_refused(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            info = zipfile.ZipInfo("link")
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "/etc/passwd")
        self.assert_refused(FakeApi([run(41)], buffer.getvalue()), "is a symbolic link")

    def test_no_run_of_tag_commit_is_refused(self) -> None:
        self.assert_refused(FakeApi([run(42, head_sha=OTHER_SHA)], GOOD_ZIP), "no successful push")


class StageTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="release-stage-")
        self.root = Path(self._tmp.name)
        release_artifacts.collect(
            FakeApi([run(41)], GOOD_ZIP),
            CONFIG,
            repo=REPO,
            tag="v1",
            tag_sha=TAG_SHA,
            out=self.root / "artifacts",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_stage_writes_assets_bundle_provenance_and_sums(self) -> None:
        out = self.root / "stage"
        names = release_artifacts.stage(
            CONFIG, release_set="full", artifacts=self.root / "artifacts", out=out
        )
        self.assertEqual(
            names, ["fift-linux", "release-provenance.json", "smartcont_lib.zip", "tos-linux.zip"]
        )
        self.assertEqual((out / "tos-linux.zip").read_bytes(), GOOD_ZIP)
        with zipfile.ZipFile(out / "smartcont_lib.zip") as bundle:
            self.assertEqual(bundle.namelist(), ["smartcont/wallet.fc"])
        lines = (out / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(lines), 4)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((out / name).read_bytes()).hexdigest(), digest)

    def test_missing_asset_is_refused(self) -> None:
        config = json.loads(json.dumps(CONFIG))
        config["release_sets"]["full"]["assets"].append(
            {"artifact": "tos-linux", "path": "absent", "name": "x"}
        )
        with self.assertRaises(ReleaseError) as caught:
            release_artifacts.stage(
                config, release_set="full", artifacts=self.root / "artifacts", out=self.root / "s"
            )
        self.assertIn("tos-linux/absent is missing", str(caught.exception))

    def test_asset_path_outside_artifact_is_refused(self) -> None:
        config = json.loads(json.dumps(CONFIG))
        config["release_sets"]["full"]["assets"].append(
            {"artifact": "tos-linux", "path": "../release-provenance.json", "name": "x"}
        )
        with self.assertRaises(ReleaseError) as caught:
            release_artifacts.stage(
                config, release_set="full", artifacts=self.root / "artifacts", out=self.root / "s"
            )
        self.assertIn("leaves artifact", str(caught.exception))

    def test_stage_without_collected_provenance_is_refused(self) -> None:
        (self.root / "artifacts" / "release-provenance.json").unlink()
        with self.assertRaises(ReleaseError) as caught:
            release_artifacts.stage(
                CONFIG, release_set="full", artifacts=self.root / "artifacts", out=self.root / "s"
            )
        self.assertIn("release-provenance.json is missing", str(caught.exception))


class RepositoryConfigTest(unittest.TestCase):
    """The committed configuration names workflows that exist and build on tags."""

    def test_every_build_workflow_exists_and_builds_release_tags(self) -> None:
        config = json.loads((HERE / "release-artifacts.json").read_text())
        workflows = HERE.parent / ".github" / "workflows"
        for entry in config["build_workflows"]:
            text = (workflows / entry["workflow"]).read_text()
            self.assertIn("tags: ['v*']", text, entry["workflow"])
            self.assertIn(f"name: {entry['artifact']}\n", text, entry["workflow"])

    def test_every_asset_comes_from_a_collected_artifact(self) -> None:
        config = json.loads((HERE / "release-artifacts.json").read_text())
        collected = {entry["artifact"] for entry in config["build_workflows"]}
        for release_set in config["release_sets"].values():
            for item in [*release_set["assets"], *release_set.get("bundles", [])]:
                self.assertIn(item["artifact"], collected)


if __name__ == "__main__":
    unittest.main()
