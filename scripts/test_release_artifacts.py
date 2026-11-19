#!/usr/bin/env python3
"""Offline tests for scripts/release-artifacts.py.

The GitHub API is replaced by fixtures, so each test states exactly which runs
and artifacts exist. Refusal tests check the specific reason, not merely that
something failed.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import re
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
            api,
            CONFIG,
            repo=REPO,
            release_set="full",
            tag="v2026.10",
            tag_sha=TAG_SHA,
            out=self.root / "artifacts",
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


EXTRA_WORKFLOW = "build-extra.yml"
EXTRA_ARTIFACTS = ("tos-extra-linux-x64", "tos-extra-linux-arm64")
EXTRA_CONFIG = {
    "build_workflows": [
        {"artifact": "tos-linux", "workflow": WORKFLOW},
        *({"artifact": name, "workflow": EXTRA_WORKFLOW} for name in EXTRA_ARTIFACTS),
    ],
    "release_sets": {
        "full": {
            "assets": [
                {"artifact": "tos-linux", "path": "fift", "name": "fift-linux"},
                *(
                    {"artifact": name, "path": f"{name}.tar.gz", "name": f"{name}.tar.gz"}
                    for name in EXTRA_ARTIFACTS
                ),
            ]
        },
        "tol": {"assets": [{"artifact": "tos-linux", "path": "fift", "name": "fift-linux"}]},
    },
}


class FakeMultiApi:
    """Runs per workflow, and per run the artifacts it uploaded."""

    def __init__(self, runs: dict[str, list[dict[str, Any]]], payloads: dict[str, bytes]):
        self.runs = runs
        self.payloads = payloads
        self.served = dict(payloads)
        self.artifact_overrides: dict[str, dict[str, Any]] = {}
        self.requests: list[str] = []
        self.ids = {name: 900 + index for index, name in enumerate(sorted(payloads))}

    def get_json(self, path: str) -> Any:
        self.requests.append(path)
        if "/workflows/" in path:
            workflow = path.split("/workflows/")[1].split("/")[0]
            return {"workflow_runs": self.runs.get(workflow, [])}
        if "/runs/" in path:
            run_id = int(path.split("/runs/")[1].split("/")[0])
            name = path.split("name=")[1].split("&")[0]
            artifact = {
                "id": self.ids[name],
                "name": name,
                "expired": False,
                "digest": "sha256:" + hashlib.sha256(self.payloads[name]).hexdigest(),
                "workflow_run": {"id": run_id, "head_sha": TAG_SHA},
            }
            artifact.update(self.artifact_overrides.get(name, {}))
            return {"artifacts": [artifact]}
        raise AssertionError(path)

    def download(self, path: str, destination: Path) -> None:
        self.requests.append(path)
        artifact_id = int(path.split("/artifacts/")[1].split("/")[0])
        (name,) = [name for name, value in self.ids.items() if value == artifact_id]
        destination.write_bytes(self.served[name])


def extra_api(**runs: list[dict[str, Any]]) -> FakeMultiApi:
    payloads = {"tos-linux": GOOD_ZIP}
    for name in EXTRA_ARTIFACTS:
        payloads[name] = zip_bytes({f"{name}.tar.gz": f"archive {name}".encode()})
    return FakeMultiApi(
        {
            WORKFLOW: runs.get("linux", [run(41)]),
            EXTRA_WORKFLOW: runs.get(
                "extra", [run(77, path=f".github/workflows/{EXTRA_WORKFLOW}")]
            ),
        },
        payloads,
    )


class SecondWorkflowCollectTest(unittest.TestCase):
    """Several artifacts from one run of a second build workflow are each
    bound to that run and to their own digest."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="release-second-workflow-")
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def collect(self, api: FakeMultiApi, release_set: str = "full") -> dict[str, Any]:
        return release_artifacts.collect(
            api,
            EXTRA_CONFIG,
            repo=REPO,
            release_set=release_set,
            tag="v2026.10",
            tag_sha=TAG_SHA,
            out=self.root / "artifacts",
        )

    def assert_refused(self, api: FakeMultiApi, reason: str) -> None:
        with self.assertRaises(ReleaseError) as caught:
            self.collect(api)
        self.assertIn(reason, str(caught.exception))
        self.assertFalse((self.root / "artifacts" / "release-provenance.json").exists())

    def test_second_workflow_artifacts_are_collected_and_bound(self) -> None:
        api = extra_api()
        provenance = self.collect(api)
        records = {record["artifact_name"]: record for record in provenance["artifacts"]}
        self.assertEqual(sorted(records), sorted(["tos-linux", *EXTRA_ARTIFACTS]))
        for name in EXTRA_ARTIFACTS:
            record = records[name]
            self.assertEqual(record["workflow"], EXTRA_WORKFLOW)
            self.assertEqual(record["run_id"], 77)
            self.assertEqual(record["head_sha"], TAG_SHA)
            self.assertEqual(
                record["artifact_digest"],
                "sha256:" + hashlib.sha256(api.payloads[name]).hexdigest(),
            )
            self.assertEqual(
                (self.root / "artifacts" / name / f"{name}.tar.gz").read_bytes(),
                f"archive {name}".encode(),
            )
        out = self.root / "stage"
        names = release_artifacts.stage(
            EXTRA_CONFIG, release_set="full", artifacts=self.root / "artifacts", out=out
        )
        self.assertIn("tos-extra-linux-x64.tar.gz", names)
        self.assertIn("tos-extra-linux-x64.tar.gz", (out / "SHA256SUMS").read_text())

    def test_second_workflow_digest_mismatch_is_refused(self) -> None:
        api = extra_api()
        api.served["tos-extra-linux-arm64"] = zip_bytes({"x": b"tampered"})
        self.assert_refused(api, "artifact tos-extra-linux-arm64: downloaded sha256")

    def test_second_workflow_run_of_another_commit_is_refused(self) -> None:
        api = extra_api(
            extra=[run(78, head_sha=OTHER_SHA, path=f".github/workflows/{EXTRA_WORKFLOW}")]
        )
        self.assert_refused(api, f"{EXTRA_WORKFLOW}: no successful push")

    def test_second_workflow_artifact_of_another_run_is_refused(self) -> None:
        api = extra_api()
        api.artifact_overrides["tos-extra-linux-x64"] = {
            "workflow_run": {"id": 76, "head_sha": TAG_SHA}
        }
        self.assert_refused(api, "tos-extra-linux-x64 is not bound to run 77")

    def test_second_workflow_run_claiming_another_workflow_is_refused(self) -> None:
        api = extra_api(extra=[run(79)])  # a run of build-linux.yml, listed under the other
        self.assert_refused(api, f"not {EXTRA_WORKFLOW}")

    def test_set_collects_only_the_inputs_it_publishes(self) -> None:
        api = extra_api(extra=[])
        provenance = self.collect(api, release_set="tol")
        self.assertEqual([r["artifact_name"] for r in provenance["artifacts"]], ["tos-linux"])
        self.assertFalse(any(EXTRA_WORKFLOW in request for request in api.requests))

    def test_set_using_an_unbuilt_artifact_is_refused(self) -> None:
        config = json.loads(json.dumps(EXTRA_CONFIG))
        config["release_sets"]["full"]["assets"].append(
            {"artifact": "tos-unbuilt", "path": "x", "name": "x"}
        )
        with self.assertRaises(ReleaseError) as caught:
            release_artifacts.collect(
                extra_api(),
                config,
                repo=REPO,
                release_set="full",
                tag="v1",
                tag_sha=TAG_SHA,
                out=self.root / "artifacts",
            )
        self.assertIn("no build workflow produces: ['tos-unbuilt']", str(caught.exception))
        self.assertFalse((self.root / "artifacts").exists())

    def test_stage_for_another_set_is_refused(self) -> None:
        self.collect(extra_api(extra=[]), release_set="tol")
        with self.assertRaises(ReleaseError) as caught:
            release_artifacts.stage(
                EXTRA_CONFIG,
                release_set="full",
                artifacts=self.root / "artifacts",
                out=self.root / "s",
            )
        self.assertIn("collected for release set 'tol', not 'full'", str(caught.exception))


class StageTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="release-stage-")
        self.root = Path(self._tmp.name)
        release_artifacts.collect(
            FakeApi([run(41)], GOOD_ZIP),
            CONFIG,
            repo=REPO,
            release_set="full",
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
        # The published provenance record, which is attested, names the digest
        # of every other staged file and keeps what collect recorded.
        record = json.loads((out / "release-provenance.json").read_text())
        listed = dict(reversed(line.split("  ")) for line in lines)
        del listed["release-provenance.json"]
        self.assertEqual(record.pop("assets"), listed)
        collected = json.loads((self.root / "artifacts" / "release-provenance.json").read_text())
        self.assertEqual(record, collected)

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


TAG = "v2026.10"
TAG_OBJECT = "c" * 40
INNER_TAG_OBJECT = "d" * 40
TAG_CONFIG = {
    **CONFIG,
    "release_sets": {
        "full": {**CONFIG["release_sets"]["full"], "tag_prefix": "v"},
        "tol": {"assets": [], "tag_prefix": "tol-v"},
    },
}


class FakeTagApi:
    """GitHub's git database as the publishing job sees it.

    `refs` maps a tag name to the object its ref points at, and `tags` maps an
    annotated tag object's SHA to the object it points at. Tests move a tag by
    changing `refs` between calls, exactly as a push to the remote would.
    """

    def __init__(
        self, refs: dict[str, dict[str, str]], tags: dict[str, dict[str, str]] | None = None
    ):
        self.refs = refs
        self.tags = tags or {}
        self.releases: list[dict[str, Any]] = []
        # Bytes GitHub would serve for each uploaded release asset, by id.
        self.asset_bytes: dict[int, bytes] = {}
        self.requests: list[str] = []

    def get_json(self, path: str) -> Any:
        self.requests.append(path)
        ref_prefix = f"repos/{REPO}/git/ref/tags/"
        tag_prefix = f"repos/{REPO}/git/tags/"
        if path.startswith(ref_prefix):
            name = path.removeprefix(ref_prefix)
            if name not in self.refs:
                raise ReleaseError(f"GitHub API request {path} failed: HTTP 404: Not Found")
            return {"ref": f"refs/tags/{name}", "object": self.refs[name]}
        if path.startswith(tag_prefix):
            return {"object": self.tags[path.removeprefix(tag_prefix)]}
        raise AssertionError(path)

    def get_all(self, path: str) -> list[Any]:
        self.requests.append(path)
        if path != f"repos/{REPO}/releases?per_page=100":
            raise AssertionError(path)
        return self.releases

    def download(self, path: str, destination: Path, *, accept: str | None = None) -> None:
        self.requests.append(path)
        prefix = f"repos/{REPO}/releases/assets/"
        if not path.startswith(prefix) or accept != "application/octet-stream":
            raise AssertionError((path, accept))
        destination.write_bytes(self.asset_bytes[int(path.removeprefix(prefix))])


def commit(sha: str) -> dict[str, str]:
    return {"type": "commit", "sha": sha}


def tag_object(sha: str) -> dict[str, str]:
    return {"type": "tag", "sha": sha}


class CheckTagTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="release-check-tag-")
        self.provenance = Path(self._tmp.name) / "release-provenance.json"
        self.write_provenance()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write_provenance(self, **overrides: str) -> None:
        record = {
            "repository": REPO,
            "release_set": "full",
            "tag": TAG,
            "tag_commit": TAG_SHA,
            "artifacts": [],
        }
        record.update(overrides)
        self.provenance.write_text(json.dumps(record))

    def check(
        self,
        api: FakeTagApi,
        *,
        tag: str = TAG,
        release_set: str = "full",
        release_state: str = "none",
        assets_dir: Path | None = None,
    ) -> str:
        return release_artifacts.check_tag(
            api,
            TAG_CONFIG,
            repo=REPO,
            release_set=release_set,
            tag=tag,
            tag_sha=TAG_SHA,
            provenance=self.provenance,
            release_state=release_state,
            assets_dir=assets_dir,
        )

    def assert_refused(self, api: FakeTagApi, reason: str, **kwargs: Any) -> None:
        with self.assertRaises(ReleaseError) as caught:
            self.check(api, **kwargs)
        self.assertIn(reason, str(caught.exception))

    def test_lightweight_tag_on_the_built_commit_passes(self) -> None:
        api = FakeTagApi({TAG: commit(TAG_SHA)})
        self.assertEqual(self.check(api), TAG_SHA)
        self.assertEqual(
            api.requests,
            [f"repos/{REPO}/git/ref/tags/{TAG}", f"repos/{REPO}/releases?per_page=100"],
        )

    def test_annotated_tag_is_peeled_to_its_commit(self) -> None:
        api = FakeTagApi({TAG: tag_object(TAG_OBJECT)}, {TAG_OBJECT: commit(TAG_SHA)})
        self.assertEqual(self.check(api), TAG_SHA)

    def test_tag_of_a_tag_is_peeled_to_its_commit(self) -> None:
        api = FakeTagApi(
            {TAG: tag_object(TAG_OBJECT)},
            {TAG_OBJECT: tag_object(INNER_TAG_OBJECT), INNER_TAG_OBJECT: commit(TAG_SHA)},
        )
        self.assertEqual(self.check(api), TAG_SHA)

    def test_tag_moved_after_collection_is_refused(self) -> None:
        # The negative control: the tag named the built commit when the
        # assets were collected and checked, then moved before publication.
        api = FakeTagApi({TAG: commit(TAG_SHA)})
        self.assertEqual(self.check(api), TAG_SHA)
        api.refs[TAG] = commit(OTHER_SHA)
        self.assert_refused(api, f"tag {TAG} now names commit {OTHER_SHA}, not {TAG_SHA}")

    def test_annotated_tag_moved_to_another_commit_is_refused(self) -> None:
        api = FakeTagApi({TAG: tag_object(TAG_OBJECT)}, {TAG_OBJECT: commit(OTHER_SHA)})
        self.assert_refused(api, f"now names commit {OTHER_SHA}")

    def test_deleted_tag_is_refused(self) -> None:
        self.assert_refused(FakeTagApi({}), "HTTP 404")

    def test_ref_for_another_name_is_refused(self) -> None:
        api = FakeTagApi({TAG: commit(TAG_SHA)})
        api.get_json = lambda path: {"ref": f"refs/tags/{TAG}-rc1", "object": commit(TAG_SHA)}  # type: ignore[method-assign]
        self.assert_refused(api, f"no tag ref refs/tags/{TAG}")

    def test_tag_naming_a_tree_is_refused(self) -> None:
        api = FakeTagApi({TAG: {"type": "tree", "sha": TAG_SHA}})
        self.assert_refused(api, "names a tree, not a commit")

    def test_abbreviated_object_is_refused(self) -> None:
        api = FakeTagApi({TAG: commit(TAG_SHA[:12])})
        self.assert_refused(api, "full 40-character")

    def test_looping_annotated_tags_are_refused(self) -> None:
        api = FakeTagApi({TAG: tag_object(TAG_OBJECT)}, {TAG_OBJECT: tag_object(TAG_OBJECT)})
        self.assert_refused(api, "nested more than")

    def test_tag_outside_the_release_namespace_is_refused(self) -> None:
        api = FakeTagApi({"release-1": commit(TAG_SHA)})
        self.assert_refused(api, "is not a full release tag", tag="release-1")
        self.assertEqual(api.requests, [])

    def test_tol_set_requires_its_own_prefix(self) -> None:
        api = FakeTagApi({TAG: commit(TAG_SHA)})
        self.write_provenance()
        self.assert_refused(api, "must be tol-v<version>", release_set="tol")

    def test_bare_prefix_is_refused(self) -> None:
        self.assert_refused(
            FakeTagApi({"v": commit(TAG_SHA)}), "is not a full release tag", tag="v"
        )

    def test_provenance_for_another_commit_is_refused(self) -> None:
        self.write_provenance(tag_commit=OTHER_SHA)
        self.assert_refused(FakeTagApi({TAG: commit(TAG_SHA)}), "records tag_commit")

    def test_provenance_for_another_tag_is_refused(self) -> None:
        self.write_provenance(tag="v2026.09")
        self.assert_refused(FakeTagApi({TAG: commit(TAG_SHA)}), "records tag 'v2026.09'")

    def test_provenance_for_another_release_set_is_refused(self) -> None:
        self.write_provenance(release_set="tol")
        self.assert_refused(FakeTagApi({TAG: commit(TAG_SHA)}), "records release_set 'tol'")

    def test_provenance_for_another_repository_is_refused(self) -> None:
        self.write_provenance(repository="someone/fork")
        self.assert_refused(FakeTagApi({TAG: commit(TAG_SHA)}), "records repository")

    def test_command_line_refuses_a_moved_tag(self) -> None:
        # The workflow calls the command line, so the refusal is checked there:
        # exit status 1 and the reason on stderr.
        api = FakeTagApi({TAG: commit(OTHER_SHA)})
        config = Path(self._tmp.name) / "config.json"
        config.write_text(json.dumps(TAG_CONFIG))
        original = release_artifacts.GhApi
        release_artifacts.GhApi = lambda: api
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr):
                status = release_artifacts.main(
                    [
                        "--config",
                        str(config),
                        "check-tag",
                        "--repo",
                        REPO,
                        "--set",
                        "full",
                        "--tag",
                        TAG,
                        "--tag-sha",
                        TAG_SHA,
                        "--provenance",
                        str(self.provenance),
                        "--release-state",
                        "none",
                    ]
                )
        finally:
            release_artifacts.GhApi = original
        # A moved tag has its own exit status: it is the only refusal after
        # which the publisher deletes a published release.
        self.assertEqual(status, release_artifacts.TAG_MOVED_STATUS)
        self.assertEqual(status, 3)
        self.assertIn("RELEASE_ARTIFACTS_REFUSED: tag v2026.10 now names commit", stderr.getvalue())


def release(release_id: int, *, draft: bool, tag: str = TAG, assets: Any = ()) -> dict[str, Any]:
    return {"id": release_id, "tag_name": tag, "draft": draft, "assets": list(assets)}


class ReleaseStateTest(CheckTagTest):
    """Each publication step states which releases must already exist."""

    def setUp(self) -> None:
        super().setUp()
        self.stage = Path(self._tmp.name) / "stage"
        self.stage.mkdir()
        (self.stage / "fift-linux").write_bytes(b"fift")
        (self.stage / "SHA256SUMS").write_bytes(b"sums")
        self.api = FakeTagApi({TAG: commit(TAG_SHA)})
        # Waits between reads of the release listing are recorded, not slept.
        self.waits: list[float] = []
        original = release_artifacts._sleep
        release_artifacts._sleep = self.waits.append
        self.addCleanup(setattr, release_artifacts, "_sleep", original)

    def uploaded(self, name: str, content: bytes | None = None, **overrides: Any) -> dict[str, Any]:
        """An uploaded asset whose served bytes are the staged file, or `content`."""
        payload = (self.stage / name).read_bytes()
        asset_id = 100 + len(self.api.asset_bytes)
        self.api.asset_bytes[asset_id] = payload if content is None else content
        asset = {
            "id": asset_id,
            "name": name,
            "state": "uploaded",
            "size": len(payload),
            "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        }
        asset.update(overrides)
        return asset

    def complete(self) -> list[dict[str, Any]]:
        return [self.uploaded("fift-linux"), self.uploaded("SHA256SUMS")]

    def test_no_release_passes_before_creation(self) -> None:
        self.api.releases = [release(1, draft=False, tag="v2026.09")]
        self.assertEqual(self.check(self.api, release_state="none"), TAG_SHA)

    def test_existing_published_release_is_refused(self) -> None:
        self.api.releases = [release(5, draft=False)]
        self.assert_refused(self.api, "a release for v2026.10 already exists (published release 5)")

    def test_existing_draft_is_refused(self) -> None:
        self.api.releases = [release(6, draft=True)]
        self.assert_refused(self.api, "already exists (draft release 6)")

    def test_a_listing_that_lags_the_write_is_read_again(self) -> None:
        # The draft was created one step earlier and the listing does not
        # show it yet; then it shows it without its assets; then complete.
        complete = release(7, draft=True, assets=self.complete())
        views = [[], [release(7, draft=True)], [complete]]

        def get_all(path: str) -> list[Any]:
            self.api.requests.append(path)
            return views.pop(0) if len(views) > 1 else views[0]

        self.api.get_all = get_all  # type: ignore[method-assign]
        self.check(self.api, release_state="draft", assets_dir=self.stage)
        self.assertEqual(self.waits, [release_artifacts.LISTING_WAIT_SECONDS] * 2)

    def test_a_release_that_never_appears_is_refused_after_bounded_reads(self) -> None:
        self.assert_refused(
            self.api,
            "expected exactly one draft release for v2026.10, found 0",
            release_state="draft",
        )
        self.assertEqual(len(self.waits), release_artifacts.LISTING_ATTEMPTS - 1)
        listing = f"repos/{REPO}/releases?per_page=100"
        self.assertEqual(self.api.requests.count(listing), release_artifacts.LISTING_ATTEMPTS)

    def test_two_releases_for_the_tag_are_refused_without_waiting(self) -> None:
        self.api.releases = [release(7, draft=True), release(8, draft=True)]
        self.assert_refused(self.api, "found 2", release_state="draft")
        self.assertEqual(self.waits, [])

    def test_the_none_state_reads_the_listing_once(self) -> None:
        self.check(self.api, release_state="none")
        self.assertEqual(self.api.requests.count(f"repos/{REPO}/releases?per_page=100"), 1)

    def test_draft_without_assets_passes_before_upload(self) -> None:
        self.api.releases = [release(7, draft=True)]
        self.assertEqual(self.check(self.api, release_state="draft"), TAG_SHA)

    def test_complete_draft_passes_before_publication(self) -> None:
        self.api.releases = [release(7, draft=True, assets=self.complete())]
        self.check(self.api, release_state="draft", assets_dir=self.stage)
        # Every asset's bytes were fetched, not just its metadata.
        self.assertIn(f"repos/{REPO}/releases/assets/100", self.api.requests)
        self.assertIn(f"repos/{REPO}/releases/assets/101", self.api.requests)

    def test_absent_digest_with_same_size_wrong_bytes_is_refused(self) -> None:
        # The negative control: GitHub reports no digest, the name and size
        # match, and only the content differs.
        wrong = b"FIFT"  # same length as the staged b"fift"
        assets = [
            self.uploaded("fift-linux", content=wrong, digest=None),
            self.uploaded("SHA256SUMS"),
        ]
        self.api.releases = [release(7, draft=True, assets=assets)]
        self.assert_refused(
            self.api,
            "asset fift-linux: downloaded bytes hash to sha256:"
            + hashlib.sha256(wrong).hexdigest(),
            release_state="draft",
            assets_dir=self.stage,
        )

    def test_absent_digest_with_right_bytes_passes(self) -> None:
        assets = [
            self.uploaded("fift-linux", digest=None),
            self.uploaded("SHA256SUMS", digest=None),
        ]
        self.api.releases = [release(7, draft=False, assets=assets)]
        self.check(self.api, release_state="published", assets_dir=self.stage)

    def test_matching_digest_with_wrong_bytes_is_refused(self) -> None:
        # A digest field is a claim; the bytes are what is published.
        assets = [self.uploaded("fift-linux", content=b"FIFT"), self.uploaded("SHA256SUMS")]
        self.api.releases = [release(7, draft=True, assets=assets)]
        self.assert_refused(
            self.api,
            "asset fift-linux: downloaded bytes",
            release_state="draft",
            assets_dir=self.stage,
        )

    def test_malformed_digest_is_refused(self) -> None:
        assets = [self.uploaded("fift-linux", digest="md5:abc"), self.uploaded("SHA256SUMS")]
        self.api.releases = [release(7, draft=True, assets=assets)]
        self.assert_refused(
            self.api,
            "reports a malformed digest 'md5:abc'",
            release_state="draft",
            assets_dir=self.stage,
        )

    def test_asset_without_id_is_refused(self) -> None:
        assets = [self.uploaded("fift-linux", digest=None, id=None), self.uploaded("SHA256SUMS")]
        self.api.releases = [release(7, draft=True, assets=assets)]
        self.assert_refused(
            self.api,
            "asset fift-linux has no usable id",
            release_state="draft",
            assets_dir=self.stage,
        )

    def test_asset_without_state_is_refused(self) -> None:
        # An asset whose upload state GitHub does not report is not assumed finished.
        unstated = self.uploaded("fift-linux")
        del unstated["state"]
        assets = [unstated, self.uploaded("SHA256SUMS")]
        self.api.releases = [release(7, draft=True, assets=assets)]
        self.assert_refused(
            self.api, "asset fift-linux is None", release_state="draft", assets_dir=self.stage
        )

    def test_draft_missing_an_asset_is_refused(self) -> None:
        self.api.releases = [release(7, draft=True, assets=[self.uploaded("fift-linux")])]
        self.assert_refused(
            self.api,
            "expected exactly the staged ['SHA256SUMS', 'fift-linux']",
            release_state="draft",
            assets_dir=self.stage,
        )

    def test_draft_with_an_extra_asset_is_refused(self) -> None:
        extra = {"id": 99, "name": "extra", "state": "uploaded", "size": 1}
        self.api.releases = [release(7, draft=True, assets=[*self.complete(), extra])]
        self.assert_refused(
            self.api, "carries assets", release_state="draft", assets_dir=self.stage
        )

    def test_asset_with_another_digest_is_refused(self) -> None:
        assets = [
            self.uploaded("fift-linux", digest="sha256:" + "0" * 64),
            self.uploaded("SHA256SUMS"),
        ]
        self.api.releases = [release(7, draft=True, assets=assets)]
        self.assert_refused(
            self.api,
            "asset fift-linux has digest sha256:000",
            release_state="draft",
            assets_dir=self.stage,
        )

    def test_asset_with_another_size_is_refused(self) -> None:
        assets = [self.uploaded("fift-linux", size=1, digest=None), self.uploaded("SHA256SUMS")]
        self.api.releases = [release(7, draft=True, assets=assets)]
        self.assert_refused(
            self.api, "expected uploaded with 4", release_state="draft", assets_dir=self.stage
        )

    def test_unfinished_upload_is_refused(self) -> None:
        assets = [self.uploaded("fift-linux", state="starter"), self.uploaded("SHA256SUMS")]
        self.api.releases = [release(7, draft=True, assets=assets)]
        self.assert_refused(
            self.api, "asset fift-linux is starter", release_state="draft", assets_dir=self.stage
        )

    def test_already_published_is_refused_before_publication(self) -> None:
        self.api.releases = [release(7, draft=False, assets=self.complete())]
        self.assert_refused(
            self.api, "is published, expected draft", release_state="draft", assets_dir=self.stage
        )

    def test_two_drafts_are_refused(self) -> None:
        self.api.releases = [release(7, draft=True), release(8, draft=True)]
        self.assert_refused(self.api, "expected exactly one draft release", release_state="draft")

    def test_published_release_passes_after_publication(self) -> None:
        self.api.releases = [release(7, draft=False, assets=self.complete())]
        self.check(self.api, release_state="published", assets_dir=self.stage)

    def test_release_still_a_draft_after_publication_is_refused(self) -> None:
        self.api.releases = [release(7, draft=True, assets=self.complete())]
        self.assert_refused(self.api, "is a draft, expected published", release_state="published")

    def test_unknown_state_is_refused(self) -> None:
        self.assert_refused(self.api, "release state 'gone'", release_state="gone")


def workflow_job(text: str, job: str) -> str | None:
    """The body of one job of a workflow, or None if it has no such job."""
    jobs = text.split("\njobs:\n", 1)[-1]
    match = re.search(rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", jobs)
    return match.group(1) if match else None


def publisher_attest_problems(text: str, sums: str) -> list[str]:
    attest = workflow_job(text, "attest")
    publish = workflow_job(text, "publish")
    if attest is None or publish is None:
        return ["the publisher has no attest job or no publish job"]
    problems: list[str] = []
    # Comments describe the next job; only the job's own lines are judged.
    lines = [
        line for line in attest.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    body = "\n".join(lines) + "\n"
    if "    needs: collect\n" not in body:
        problems.append("attest does not follow collect")
    grants = re.search(r"(?m)^    permissions:\n((?:      .*\n)+)", body)
    if grants is None or sorted(grants.group(1).split("\n")[:-1]) != [
        "      attestations: write",
        "      contents: read",
        "      id-token: write",
    ]:
        problems.append("attest holds other permissions than the signing token and read access")
    if re.search(r"(?m)^\s*(?:- )?(?:run|if|continue-on-error):", body):
        problems.append("attest runs a script, is conditional or tolerates failure")
    uses = re.findall(r"(?m)^\s*uses: (\S+)", body)
    if [use.split("@")[0] for use in uses] != [
        "actions/download-artifact",
        "actions/attest-build-provenance",
    ] or not all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", use) for use in uses):
        problems.append(
            "attest must only receive the staged files and attest them, by pinned actions"
        )
    if f"          subject-checksums: {sums}\n" not in body:
        problems.append(f"attest does not attest the files {sums} lists")
    if "    runs-on: ubuntu-24.04\n" not in body:
        problems.append("attest does not run on the hosted runner")
    # The action signs an empty statement when the checksum file is missing,
    # so the files must arrive where the attest step reads them, and the
    # step takes that one input and nothing else (no other token).
    directory = sums.rsplit("/", 2)[0] if sums.count("/") > 1 else sums.split("/")[0]
    if f"          name: release-stage\n          path: {directory}\n" not in body:
        problems.append(f"attest does not receive release-stage into {directory}")
    withs = re.findall(r"(?m)^        with:\n((?:          .*\n)+)", body)
    if len(withs) != 2 or withs[1] != f"          subject-checksums: {sums}\n":
        problems.append("the attest step takes other inputs than the staged SHA256SUMS")
    header = [line for line in publish.splitlines() if re.match(r"    \S", line)]
    if "    needs: [collect, attest]" not in header:
        problems.append("publish does not wait for attest")
    # A condition such as always() would let publish run after a failed or
    # skipped attest.
    if any(line.startswith("    if:") for line in header):
        problems.append("publish is conditional; it must run only after attest succeeded")
    # Signed from another ref, a modified copy of this workflow could attest
    # anything; verifiers pin the ref, and an honest run refuses the mistake.
    collect = workflow_job(text, "collect") or ""
    if '[ "$GITHUB_REF" = refs/heads/main ]' not in collect:
        problems.append("collect does not refuse a run dispatched from another ref than main")
    return problems


def publisher_attest_mutants(text: str) -> dict[str, str]:
    def swap(old: str, new: str) -> str:
        if text.count(old) != 1:
            raise AssertionError(f"{old!r} occurs {text.count(old)} times")
        return text.replace(old, new)

    before_attest, in_attest = text.split("\n  attest:\n", 1)
    before_attest += "\n  attest:\n"
    attest_grants = (
        "    permissions:\n      contents: read\n      id-token: write\n      attestations: write\n"
    )
    return {
        "unchanged": text,
        "publish does not wait": swap("    needs: [collect, attest]\n", "    needs: collect\n"),
        "release access": swap(
            attest_grants, attest_grants.replace("contents: read", "contents: write")
        ),
        "no signing token": swap(
            attest_grants, attest_grants.replace("      id-token: write\n", "")
        ),
        "conditional": swap(attest_grants, "    if: github.ref_type == 'tag'\n" + attest_grants),
        "another file list": swap("/SHA256SUMS\n\n", "/OTHERSUMS\n\n"),
        "runs a script": swap(
            "      - name: Attest every file SHA256SUMS lists\n",
            "      - run: ./stage/hook.sh\n      - name: Attest every file SHA256SUMS lists\n",
        ),
        "publish runs regardless": swap(
            "    needs: [collect, attest]\n", "    needs: [collect, attest]\n    if: always()\n"
        ),
        "self-hosted signer": swap(
            "    needs: collect\n    runs-on: ubuntu-24.04\n",
            "    needs: collect\n    runs-on: self-hosted\n",
        ),
        "another download path": before_attest
        + in_attest.replace(
            "          name: release-stage\n          path: ",
            "          name: release-stage\n          path: x-",
            1,
        ),
        "another token": swap(
            "/SHA256SUMS\n\n", "/SHA256SUMS\n          github-token: ${{ secrets.OTHER }}\n\n"
        ),
        "any ref": swap('[ "$GITHUB_REF" = refs/heads/main ]', "true"),
        "unpinned action": swap(
            "actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a",
            "actions/attest-build-provenance@v3",
        ),
    }


class RepositoryConfigTest(unittest.TestCase):
    """The committed configuration names workflows that exist and build on tags."""

    def test_every_build_workflow_exists_and_builds_release_tags(self) -> None:
        config = json.loads((HERE / "release-artifacts.json").read_text())
        workflows = HERE.parent / ".github" / "workflows"
        for entry in config["build_workflows"]:
            text = (workflows / entry["workflow"]).read_text()
            self.assertIn("tags: ['v*']", text, entry["workflow"])
            # A matrix workflow names each leg's artifact in its matrix.
            self.assertTrue(
                f"name: {entry['artifact']}\n" in text
                or f"artifact: {entry['artifact']}\n" in text,
                entry["workflow"],
            )

    def test_every_asset_comes_from_a_collected_artifact(self) -> None:
        config = json.loads((HERE / "release-artifacts.json").read_text())
        collected = {entry["artifact"] for entry in config["build_workflows"]}
        for release_set in config["release_sets"].values():
            for item in [*release_set["assets"], *release_set.get("bundles", [])]:
                self.assertIn(item["artifact"], collected)

    def test_releases_ship_linux_x86_64_and_arm64_only(self) -> None:
        # The node is built, tested and released for Linux x86-64 and arm64
        # only (BUILD.md). Every set publishes both architectures and nothing
        # else, and tol ships its compiler for each. The full set adds the
        # node binaries, built separately with the node recipe.
        tools = {"tos-x86_64-linux", "tos-arm64-linux"}
        node = {"tos-node-x86_64-linux", "tos-node-arm64-linux"}
        config = json.loads((HERE / "release-artifacts.json").read_text())
        self.assertEqual({entry["artifact"] for entry in config["build_workflows"]}, tools | node)
        self.assertEqual(len(config["build_workflows"]), len(tools | node))
        expected_sets = {"full": tools | node, "tol": tools}
        self.assertEqual(set(config["release_sets"]), set(expected_sets))
        for name, release_set in config["release_sets"].items():
            items = [*release_set["assets"], *release_set.get("bundles", [])]
            self.assertEqual({item["artifact"] for item in items}, expected_sets[name], name)
            for item in items:
                self.assertRegex(
                    item["name"], r"(^|-)linux-(x86_64|arm64)(\.|$)|^smartcont_lib\.zip$"
                )
        tol = {
            (asset["artifact"], asset.get("path"), asset["name"])
            for asset in config["release_sets"]["tol"]["assets"]
        }
        self.assertEqual(
            tol,
            {
                ("tos-x86_64-linux", "tol", "tol-linux-x86_64"),
                ("tos-arm64-linux", "tol", "tol-linux-arm64"),
            },
        )

    def test_release_workflows_check_tags_in_their_own_namespace(self) -> None:
        # Each release workflow passes --set for the namespace its tags live
        # in; the tag ruleset documented in doc/tos-release-policy.md covers
        # exactly these prefixes.
        config = json.loads((HERE / "release-artifacts.json").read_text())
        workflows = HERE.parent / ".github" / "workflows"
        expected = {"create-release.yml": "full", "create-tol-release.yml": "tol"}
        prefixes = {name: spec["tag_prefix"] for name, spec in config["release_sets"].items()}
        self.assertEqual(prefixes, {"full": "v", "tol": "tol-v"})
        for workflow, release_set in expected.items():
            text = (workflows / workflow).read_text()
            self.assertIn("release-artifacts.py check-tag", text, workflow)
            self.assertIn(
                f'collect \\\n            --repo "$GITHUB_REPOSITORY" --set {release_set}', text
            )
            self.assertNotIn("--set ", text.replace(f"--set {release_set} ", ""), workflow)

    def test_release_workflows_attest_what_they_publish(self) -> None:
        # The attestation job signs with the publisher's identity. It may
        # hold the signing token only: no release access, no checkout, no
        # repository code. Publication waits for it.
        workflows = HERE.parent / ".github" / "workflows"
        for workflow, sums in (
            ("create-release.yml", "release/stage/SHA256SUMS"),
            ("create-tol-release.yml", "stage/SHA256SUMS"),
        ):
            for name, text in publisher_attest_mutants((workflows / workflow).read_text()).items():
                with self.subTest(workflow=workflow, mutant=name):
                    problems = publisher_attest_problems(text, sums)
                    if name == "unchanged":
                        self.assertEqual(problems, [], workflow)
                    else:
                        self.assertNotEqual(problems, [], workflow)

    def test_release_workflows_delete_a_release_only_when_the_tag_moved(self) -> None:
        # Deleting an immutable release makes its tag unusable for good, so a
        # transient failure of the final check must not reach the delete.
        workflows = HERE.parent / ".github" / "workflows"
        for workflow in ("create-release.yml", "create-tol-release.yml"):
            text = (workflows / workflow).read_text()
            self.assertEqual(text.count("gh release delete"), 1, workflow)
            before, after = text.split("gh release delete")
            # The delete sits in the branch taken for status 3 alone, and
            # that status comes from the final check-tag.
            checked = before.rsplit("|| status=$?", 1)
            self.assertEqual(len(checked), 2, workflow)
            self.assertIn("--release-state published --assets", checked[0][-200:], workflow)
            conditions = re.findall(r"^ +(if .*)$", checked[1], flags=re.M)
            self.assertEqual(conditions, ['if [ "$status" -eq 3 ]; then'], workflow)
            self.assertNotIn("fi\n", checked[1], workflow)
            self.assertIn('if [ "$status" -ne 0 ]; then', after, workflow)

    def test_release_workflows_write_into_directories_the_checkout_lacks(self) -> None:
        # collect and stage refuse an existing --out, and both run at the
        # root of a checkout of the tag: a name the repository already has
        # (as artifacts/ is) fails every release before anything is collected.
        root = HERE.parent
        for workflow in ("create-release.yml", "create-tol-release.yml"):
            text = (root / ".github" / "workflows" / workflow).read_text()
            outs = re.findall(r"--out (\S+)", text)
            self.assertEqual(len(outs), 2, workflow)
            for out in outs:
                self.assertRegex(out, r"^[a-z][a-z-]*$", workflow)
                self.assertFalse(
                    (root / out).exists(), f"{workflow}: --out {out} exists in the tree"
                )
            collected, staged = outs
            self.assertIn("stage --set", text, workflow)
            self.assertIn(f"--artifacts {collected} --out {staged}", text, workflow)


class PqToolPackagingTest(unittest.TestCase):
    """A Linux release and the node image carry the post-quantum key tools.

    Without them an operator installing from a release cannot create the
    consensus key a validator loads, nor sign its stake and votes.
    """

    TOOLS = {
        # tool -> where the packaging scripts find it, relative to the build dir
        "tos-pq-consensus-key": "crypto/pq/tos-pq-consensus-key",
        "tos-pq-vote": "crypto/tos-pq-vote",
        # A separate CMake project, so its signer links into no node target.
        "tos-pq-key": "pq-key/tos-pq-key",
    }
    IN_TREE_TARGETS = ("tos-pq-consensus-key", "tos-pq-vote")
    LINUX_ARTIFACTS = {"tos-x86_64-linux": "linux-x86_64", "tos-arm64-linux": "linux-arm64"}
    LINUX_SCRIPTS = (
        "build-ubuntu-appimages.sh",
        "build-ubuntu-portable.sh",
        "build-ubuntu-shared.sh",
    )

    @staticmethod
    def copied_into_artifacts(script: str) -> str:
        """The single `cp ... artifacts` command that fills the artifact directory."""
        start = script.index("  cp build/storage/storage-daemon/storage-daemon ")
        end = script.index("\n     artifacts\n", start)
        return script[start:end]

    @staticmethod
    def ninja_target_lists(script: str) -> list[str]:
        lists = []
        # The main build's target lists, one for a build with tests, one without.
        for chunk in script.split("\nninja storage-daemon ")[1:]:
            lines = []
            for line in chunk.splitlines():
                lines.append(line)
                if not line.rstrip().endswith("\\"):
                    break
            lists.append(" ".join(lines))
        return lists

    def test_full_release_publishes_every_tool_for_each_linux_architecture(self) -> None:
        config = json.loads((HERE / "release-artifacts.json").read_text())
        published = {
            (asset["artifact"], asset.get("path")): asset["name"]
            for asset in config["release_sets"]["full"]["assets"]
        }
        for artifact, suffix in self.LINUX_ARTIFACTS.items():
            for tool in self.TOOLS:
                # The consensus key tool is a node binary: a validator host
                # runs it, so the release publishes the node-recipe build.
                source = (
                    artifact.replace("tos-", "tos-node-", 1)
                    if tool in NodeBinaryReleaseTest.BINARIES
                    else artifact
                )
                self.assertEqual(published.get((source, tool)), f"{tool}-{suffix}")

    def test_linux_release_workflows_package_with_the_appimage_script(self) -> None:
        config = json.loads((HERE / "release-artifacts.json").read_text())
        workflows = HERE.parent / ".github" / "workflows"
        for entry in config["build_workflows"]:
            if entry["artifact"] in self.LINUX_ARTIFACTS:
                text = (workflows / entry["workflow"]).read_text()
                self.assertIn("./build-ubuntu-appimages.sh -a", text, entry["workflow"])

    def test_linux_packaging_scripts_build_and_copy_every_tool(self) -> None:
        for name in self.LINUX_SCRIPTS:
            script = (HERE.parent / "assembly" / "native" / name).read_text()
            target_lists = self.ninja_target_lists(script)
            self.assertEqual(len(target_lists), 2, name)
            for targets in target_lists:
                for target in self.IN_TREE_TARGETS:
                    self.assertIn(f" {target} ", f" {targets} ", f"{name}: ninja misses {target}")
            self.assertIn("-S ../crypto/pq/tools -B pq-key", script, name)
            self.assertIn("ninja -C pq-key tos-pq-key", script, name)
            copied = self.copied_into_artifacts(script).split()
            for tool, path in self.TOOLS.items():
                self.assertIn(f"build/{path}", copied, f"{name}: {tool} is not copied")

    def test_node_image_installs_every_tool(self) -> None:
        dockerfile = (HERE.parent / "Dockerfile").read_text()
        for tool in self.IN_TREE_TARGETS:
            self.assertRegex(dockerfile, rf"\bninja [^\n]*(?:\\\n[^\n]*)*\b{tool}\b")
        self.assertIn("-S /tos/crypto/pq/tools -B /tos/build-pq-key", dockerfile)
        for tool, path in self.TOOLS.items():
            source = f"/tos/build-pq-key/{tool}" if tool == "tos-pq-key" else f"/tos/build/{path}"
            self.assertIn(f"COPY --from=builder {source} /usr/local/bin/\n", dockerfile)


def node_workflow_legs(workflow: str) -> list[dict[str, str]] | None:
    """The matrix `include:` entries of the node workflow, or None if the
    matrix is not exactly one `include:` list of flat `key: value` entries."""
    lines = workflow.splitlines()
    try:
        start = lines.index("      matrix:")
    except ValueError:
        return None
    if start + 1 >= len(lines) or lines[start + 1] != "        include:":
        return None
    legs: list[dict[str, str]] = []
    for line in lines[start + 2 :]:
        if not line.startswith("          "):
            break
        entry = re.fullmatch(r" {10}- ([a-z_-]+): (\S+)", line)
        field = re.fullmatch(r" {12}([a-z_-]+): (\S+)", line)
        if entry:
            legs.append({entry.group(1): entry.group(2)})
        elif field and legs and field.group(1) not in legs[-1]:
            legs[-1][field.group(1)] = field.group(2)
        else:
            return None
    return legs


def node_workflow_leg_problems(workflow: str) -> list[str]:
    """Each architecture is one unconditional leg on its runner, uploading its artifact."""
    workflow_name = NodeBinaryReleaseTest.WORKFLOW
    expected = [
        {"arch": arch, "runner": runner, "artifact": artifact}
        for arch, (artifact, runner, _cpu, _rust_cpu) in NodeBinaryReleaseTest.ARCHES.items()
    ]
    problems: list[str] = []
    legs = node_workflow_legs(workflow)
    if legs is None:
        problems.append(f"{workflow_name} has no plain matrix include list")
    elif sorted(legs, key=str) != sorted(expected, key=str):
        problems.append(f"{workflow_name} legs are {legs}, expected {expected}")
    jobs = workflow.split("\njobs:\n", 1)[-1]
    if re.findall(r"(?m)^  [A-Za-z0-9_-]+:$", jobs) != ["  build:"]:
        problems.append(f"{workflow_name} must have exactly the one build job")
    # A condition, an exclusion or a tolerated failure would let a leg be
    # skipped, or fail, while the run still succeeds.
    for pattern, why in (
        (r"(?m)^\s*(?:- )?if:", "a condition"),
        (r"(?m)^\s*exclude:", "a matrix exclusion"),
        (r"(?m)^\s*continue-on-error:", "a tolerated failure"),
    ):
        if re.search(pattern, jobs):
            problems.append(f"{workflow_name} has {why}; both legs must always run")
    for line in ("    runs-on: ${{ matrix.runner }}\n", "        name: ${{ matrix.artifact }}\n"):
        if line not in jobs:
            problems.append(f"{workflow_name} lost {line.strip()!r}")
    return problems


def node_release_problems(config: dict[str, Any], workflow: str, script: str) -> list[str]:
    """Why the published node binaries would not be the node-recipe build.

    Operators install validators from a release by these exact asset names, so
    each name must come from the node build and the node build must configure
    the recipe the testnet hosts run.
    """
    problems: list[str] = []
    arches = NodeBinaryReleaseTest.ARCHES
    binaries = NodeBinaryReleaseTest.BINARIES
    rust_binaries = NodeBinaryReleaseTest.RUST_BINARIES
    workflow_name = NodeBinaryReleaseTest.WORKFLOW
    inputs = {entry["artifact"]: entry["workflow"] for entry in config["build_workflows"]}
    by_name = {asset["name"]: asset for asset in config["release_sets"]["full"]["assets"]}
    machines = {"x86_64": "x86_64", "arm64": "aarch64|arm64"}
    for arch, (artifact, _runner, cpu, rust_cpu) in arches.items():
        if f"\n  {machines[arch]}) CPU={cpu} RUST_CPU={rust_cpu} ;;\n" not in script:
            problems.append(
                f"the node build script does not build {arch} for {cpu} and Rust {rust_cpu}"
            )
        if inputs.get(artifact) != workflow_name:
            problems.append(f"{artifact} is not built by {workflow_name}")
        # The artifact zip whose digest release-provenance.json records: the
        # anchor an installer checks each standalone binary against.
        anchor = by_name.get(f"tos-node-linux-{arch}.zip")
        if anchor is None or anchor.get("artifact") != artifact or anchor.get("zip") is not True:
            problems.append(
                f"the full set does not publish {artifact} as tos-node-linux-{arch}.zip"
            )
        for binary in [*binaries, *rust_binaries, "BUILD-INFO"]:
            name = (
                f"node-build-info-linux-{arch}.txt"
                if binary == "BUILD-INFO"
                else f"{binary}-linux-{arch}"
            )
            asset = by_name.get(name)
            if asset is None:
                problems.append(f"the full set does not publish {name}")
            elif (asset["artifact"], asset.get("path")) != (artifact, binary):
                problems.append(f"{name} is not {artifact}/{binary}")
    for asset in config["release_sets"]["full"]["assets"]:
        if asset["artifact"].startswith("tos-node-") or asset.get("zip"):
            continue
        if asset.get("path") in (*binaries, *rust_binaries):
            problems.append(f"{asset['name']} publishes {asset['path']} from {asset['artifact']}")
    problems += node_workflow_leg_problems(workflow)
    if "run: assembly/native/build-node-binaries.sh node-binaries\n" not in workflow:
        problems.append(f"{workflow_name} does not run the node build script")
    if "path: node-binaries\n" not in workflow:
        problems.append(f"{workflow_name} does not upload the node build output")
    if "ccache" in workflow or "actions/cache" in workflow:
        problems.append(f"{workflow_name} reuses cached objects")
    # tosctl needs the toolchain rust-toolchain.toml pins, installed before the
    # build, and a change to the toolchain or the lock file must run the build.
    install_rust = "      run: scripts/install-rust-toolchain.sh\n"
    build_step = "      run: assembly/native/build-node-binaries.sh node-binaries\n"
    if not 0 <= workflow.find(install_rust) < workflow.find(build_step):
        problems.append(f"{workflow_name} does not install the pinned Rust toolchain first")
    for path in NodeBinaryReleaseTest.RUST_INPUTS:
        if f"      - '{path}'\n" not in workflow.split("\njobs:\n", 1)[0]:
            problems.append(f"{workflow_name} does not run when {path} changes")
    recipe = [
        "-DCMAKE_BUILD_TYPE=Release \\\n",
        "-DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 \\\n",
        '-DTOS_ARCH="$CPU" -DPORTABLE="$CPU" \\\n',
        "-DTOS_USE_JEMALLOC=ON\n",
        "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)\nexport SOURCE_DATE_EPOCH\n",
        "export CCACHE_DISABLE=1\n",
        '[ "$(cached TOS_USE_JEMALLOC)" = ON ]',
        # ... and with the hardware SHA-256 backend of its architecture, which
        # the build record names.
        "\nunset TOS_SLHDSA_SHA_NI TOS_SLHDSA_ARMV8_SHA2\n",
        "\n  x86_64) SLHDSA_BACKEND=TOS_SLHDSA_SHA_NI ;;\n  *) SLHDSA_BACKEND=TOS_SLHDSA_ARMV8_SHA2 ;;\n",
        '\n[ "$(cached "$SLHDSA_BACKEND")" = ON ] || die "$SLHDSA_BACKEND is not ON"\n',
        '\n  echo "slhdsa_sha256 TOS_SLHDSA_SHA_NI=$(cached TOS_SLHDSA_SHA_NI) '
        'TOS_SLHDSA_ARMV8_SHA2=$(cached TOS_SLHDSA_ARMV8_SHA2)"\n',
        # jemalloc is a dependency of the binaries that link it ...
        '\nfor t in "${JEMALLOC_TARGETS[@]}"; do\n'
        '  bin="$BUILD/${PATHS[$t]}"\n'
        "  readelf -d \"$bin\" | grep -q 'NEEDED.*\\[libjemalloc\\.so' "
        '|| die "$t does not link jemalloc"\n'
        "done\n",
        # ... and the allocator validator-engine actually runs with ...
        '\nMALLOC_CONF=stats_print:true "$BUILD/${PATHS[validator-engine]}" -V '
        '>"$BUILD/jemalloc-stats.txt" 2>&1 \\\n'
        '  || die "validator-engine -V failed"\n'
        "grep -q 'jemalloc statistics' \"$BUILD/jemalloc-stats.txt\" \\\n"
        '  || die "validator-engine does not allocate through jemalloc"\n',
        # ... and every binary with -V reports the commit it was built from.
        '\nfor t in "${VERSIONED_TARGETS[@]}"; do\n'
        '  "$BUILD/${PATHS[$t]}" -V | grep -q "Commit: $REV" '
        '|| die "$t -V does not report commit $REV"\n'
        "done\n",
        # Every target goes into the artifact zip, with its dynamic
        # dependencies and digest in the build record.
        '\nfor t in "${TARGETS[@]}"; do\n  install -m 0755 "$BUILD/${PATHS[$t]}" "$OUT/$t"\ndone\n',
        '\n  for t in "${TARGETS[@]}" tosctl; do\n    echo "needed $t $(readelf -d "$OUT/$t" | ',
        '\n  (cd "$OUT" && sha256sum "${TARGETS[@]}" tosctl) | sed \'s/^/sha256 /\'\n',
        # tosctl: the pinned toolchain ...
        '\n[[ "$RUSTC_VERSION" == "rustc $RUST_CHANNEL "* ]] || die ',
        '\n[[ "$CARGO_VERSION" == "cargo $RUST_CHANNEL "* ]] || die ',
        # ... a fixed target CPU, the node compiler for C sources, no wrapper ...
        '\nTOSCTL_RUSTFLAGS="-C target-cpu=$RUST_CPU"\n',
        '\n  export RUSTFLAGS="$TOSCTL_RUSTFLAGS" CARGO_TARGET_DIR="$TOSCTL_TARGET"\n',
        "\n  export CC=clang-21 CXX=clang++-21\n",
        '\n  export RUSTC_WRAPPER="" CARGO_BUILD_RUSTC_WRAPPER="" CARGO_INCREMENTAL=0\n',
        "\n  unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET GIT_COMMIT GIT_COMMIT_DATE\n",
        "\n  unset CFLAGS CXXFLAGS TARGET_CFLAGS TARGET_CXXFLAGS\n",
        # ... the same embedded branch name for a tag build and a dispatch build ...
        "\n  export GIT_BRANCH=HEAD\n",
        # ... no other compiler standing in for the checked one ...
        "\nunset RUSTC CARGO_BUILD_RUSTC RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER\n",
        # ... the committed lock file, which the build must leave as it was ...
        '\n  cargo build --release --locked -p tosctl -j "$JOBS"\n',
        "\nTOSCTL=$TOSCTL_TARGET/release/tosctl\n"
        '[ -z "$(git status --porcelain --untracked-files=no)" ] '
        '|| die "the tosctl build changed the checkout"\n',
        # ... the commit it reports, and its place in the zip and the record.
        '\n"$TOSCTL" --version | grep -qx "COMMIT_ID: $REV" '
        '|| die "tosctl --version does not report commit $REV"\n',
        '\ninstall -m 0755 "$TOSCTL" "$OUT/tosctl"\n',
        '\n  echo "$RUSTC_VERSION"\n  echo "$CARGO_VERSION"\n'
        '  echo "rust_flags RUSTFLAGS=$TOSCTL_RUSTFLAGS CC=clang-21 '
        'cargo build --release --locked -p tosctl"\n',
    ]
    # Every cargo build in the script is the locked release build of tosctl.
    cargo_builds = re.findall(r"(?m)^\s*cargo build\b.*$", script)
    if [line.split() for line in cargo_builds] != [
        ["cargo", "build", "--release", "--locked", "-p", "tosctl", "-j", '"$JOBS"']
    ]:
        problems.append("the node build script does not build tosctl with --release --locked")
    # A host without the pinned toolchain is refused before the long C++ build.
    if (
        not 0
        <= script.find('\n[[ "$RUSTC_VERSION" == "rustc $RUST_CHANNEL "* ]]')
        < script.find("\ncmake -S . -B")
    ):
        problems.append("the node build script checks the Rust toolchain after the C++ build")
    if "target-cpu=native" in script or "sccache" in script:
        problems.append("the node build script uses the build host's CPU or a compiler cache")
    for line in recipe:
        if line not in script:
            problems.append(f"the node build script lost {line.strip()!r}")
    for name, expected, what in (
        ("TARGETS", binaries, "build exactly the node binaries"),
        (
            "JEMALLOC_TARGETS",
            NodeBinaryReleaseTest.JEMALLOC_BINARIES,
            "check jemalloc in exactly the binaries that link it",
        ),
        (
            "VERSIONED_TARGETS",
            NodeBinaryReleaseTest.VERSIONED_BINARIES,
            "check the commit of exactly the binaries with -V",
        ),
    ):
        found = re.search(rf"\n{name}=\(([^)]*)\)\n", script)
        if found is None or found.group(1).split() != list(expected):
            problems.append(f"the node build script does not {what}")
    paths = re.search(r"\ndeclare -A PATHS=\(\n((?:  \[[a-z-]+\]=\S+\n)*)\)\n", script)
    found_paths = dict(re.findall(r"  \[([a-z-]+)\]=(\S+)\n", paths.group(1))) if paths else None
    if found_paths != NodeBinaryReleaseTest.PATHS:
        problems.append("the node build script does not take each binary from its build path")
    return problems


class NodeBinaryReleaseTest(unittest.TestCase):
    """The full set publishes the node binaries built with the node recipe."""

    WORKFLOW = "build-tos-linux-node-binaries.yml"
    # arch -> (artifact, runner, CPU level for TOS_ARCH and PORTABLE, rustc target CPU)
    ARCHES = {
        "x86_64": ("tos-node-x86_64-linux", "ubuntu-24.04", "x86-64-v2", "x86-64-v2"),
        "arm64": ("tos-node-arm64-linux", "ubuntu-24.04-arm", "armv8-a", "generic"),
    }
    BINARIES = (
        "validator-engine",
        "validator-engine-console",
        "lite-client",
        "generate-random-id",
        "tos-pq-consensus-key",
        "dht-server",
        "tos-rpc",
        "tos-wallet-index",
    )
    # Built by cargo in the same script run, published from the same artifact.
    RUST_BINARIES = ("tosctl",)
    # What the Rust half of the recipe reads besides the script itself.
    RUST_INPUTS = (
        "rust-toolchain.toml",
        "scripts/install-rust-toolchain.sh",
        "tosctl/src/Cargo.lock",
        # The two files behind the COMMIT_ID line the script requires.
        "tosctl/src/common/build/build.rs",
        "tosctl/src/node-control/nodectl/src/app_cli_args.rs",
    )
    # binary -> its path in the build directory
    PATHS = {
        "validator-engine": "validator-engine/validator-engine",
        "validator-engine-console": "validator-engine-console/validator-engine-console",
        "lite-client": "lite-client/lite-client",
        "generate-random-id": "utils/generate-random-id",
        "tos-pq-consensus-key": "crypto/pq/tos-pq-consensus-key",
        "dht-server": "dht-server/dht-server",
        "tos-rpc": "services/tos-rpc",
        "tos-wallet-index": "services/tos-wallet-index",
    }
    # The binaries whose link line carries jemalloc: validator-engine and
    # dht-server list it, tos-rpc and tos-wallet-index get it through tos_db.
    JEMALLOC_BINARIES = ("validator-engine", "dht-server", "tos-rpc", "tos-wallet-index")
    # The binaries with a -V option that prints the commit; the others have none.
    VERSIONED_BINARIES = (
        "validator-engine",
        "validator-engine-console",
        "lite-client",
        "generate-random-id",
        "dht-server",
    )

    def inputs(self) -> tuple[dict[str, Any], str, str]:
        return (
            json.loads((HERE / "release-artifacts.json").read_text()),
            (HERE.parent / ".github" / "workflows" / self.WORKFLOW).read_text(),
            (HERE.parent / "assembly" / "native" / "build-node-binaries.sh").read_text(),
        )

    def test_repository_publishes_the_node_recipe_build(self) -> None:
        self.assertEqual(node_release_problems(*self.inputs()), [])

    def test_a_node_binary_from_the_appimage_build_is_refused(self) -> None:
        config, workflow, script = self.inputs()
        for asset in config["release_sets"]["full"]["assets"]:
            if asset["name"] == "lite-client-linux-x86_64":
                asset["artifact"] = "tos-x86_64-linux"
        found = node_release_problems(config, workflow, script)
        self.assertIn("lite-client-linux-x86_64 is not tos-node-x86_64-linux/lite-client", found)
        self.assertIn("lite-client-linux-x86_64 publishes lite-client from tos-x86_64-linux", found)

    def test_a_missing_node_binary_is_refused(self) -> None:
        config, workflow, script = self.inputs()
        assets = config["release_sets"]["full"]["assets"]
        assets[:] = [a for a in assets if a["name"] != "dht-server-linux-arm64"]
        self.assertEqual(
            node_release_problems(config, workflow, script),
            ["the full set does not publish dht-server-linux-arm64"],
        )

    def test_swapped_leg_artifacts_are_refused(self) -> None:
        # Each binary would then be published under the other architecture.
        config, workflow, script = self.inputs()
        swapped = (
            workflow.replace("artifact: tos-node-x86_64-linux\n", "artifact: SWAP\n")
            .replace("artifact: tos-node-arm64-linux\n", "artifact: tos-node-x86_64-linux\n")
            .replace("artifact: SWAP\n", "artifact: tos-node-arm64-linux\n")
        )
        self.assertNotEqual(swapped, workflow)
        found = node_release_problems(config, swapped, script)
        self.assertEqual(len(found), 1, found)
        self.assertIn("legs are", found[0])

    def test_a_skipped_leg_is_refused(self) -> None:
        config, workflow, script = self.inputs()
        anchor = "    runs-on: ${{ matrix.runner }}\n"
        for condition in (
            "    if: matrix.arch != 'arm64'\n",
            "    continue-on-error: ${{ matrix.arch == 'arm64' }}\n",
        ):
            with self.subTest(condition=condition):
                mutant = workflow.replace(anchor, anchor + condition, 1)
                self.assertNotEqual(mutant, workflow)
                self.assertNotEqual(node_release_problems(config, mutant, script), [])
        step = "    - name: Upload artifacts\n"
        mutant = workflow.replace(step, step + "      if: matrix.arch == 'x86_64'\n", 1)
        self.assertNotEqual(node_release_problems(config, mutant, script), [])
        exclusion = workflow.replace(
            "        include:\n", "        exclude:\n          - arch: arm64\n        include:\n", 1
        )
        self.assertNotEqual(node_release_problems(config, exclusion, script), [])
        dropped = workflow.replace(
            "          - arch: arm64\n"
            "            runner: ubuntu-24.04-arm\n"
            "            artifact: tos-node-arm64-linux\n",
            "",
        )
        self.assertNotEqual(dropped, workflow)
        self.assertNotEqual(node_release_problems(config, dropped, script), [])

    def test_a_dropped_jemalloc_check_is_refused(self) -> None:
        config, workflow, script = self.inputs()
        needed = (
            "  readelf -d \"$bin\" | grep -q 'NEEDED.*\\[libjemalloc\\.so' "
            '|| die "$t does not link jemalloc"\n'
        )
        stats = (
            "grep -q 'jemalloc statistics' \"$BUILD/jemalloc-stats.txt\" \\\n"
            '  || die "validator-engine does not allocate through jemalloc"\n'
        )
        mutants = {
            "NEEDED check deleted": script.replace(needed, ""),
            "NEEDED check tolerated": script.replace(
                '|| die "$t does not link jemalloc"', '|| echo "$t does not link jemalloc"'
            ),
            "NEEDED check on no target": script.replace(
                "JEMALLOC_TARGETS=(validator-engine dht-server tos-rpc tos-wallet-index)",
                "JEMALLOC_TARGETS=()",
            ),
            "stats check deleted": script.replace(stats, ""),
            "commit check deleted": script.replace(
                '  "$BUILD/${PATHS[$t]}" -V | grep -q "Commit: $REV" ', "  true "
            ),
        }
        for label, mutant in mutants.items():
            with self.subTest(mutant=label):
                self.assertNotEqual(mutant, script)
                self.assertNotEqual(node_release_problems(config, workflow, mutant), [])

    def test_the_wallet_services_are_built_published_and_checked(self) -> None:
        # tos-rpc and tos-wallet-index are node binaries like the others:
        # dropping either from the build targets, its build path, the zip,
        # the build record, the jemalloc check or the asset list is refused.
        config, workflow, script = self.inputs()
        self.assertEqual(node_release_problems(config, workflow, script), [])
        targets = (
            "TARGETS=(validator-engine validator-engine-console lite-client generate-random-id\n"
            "         tos-pq-consensus-key dht-server tos-rpc tos-wallet-index)"
        )
        jemalloc = "JEMALLOC_TARGETS=(validator-engine dht-server tos-rpc tos-wallet-index)"
        install = 'for t in "${TARGETS[@]}"; do\n  install -m 0755'
        needed = 'for t in "${TARGETS[@]}" tosctl; do\n    echo "needed $t'
        digests = '(cd "$OUT" && sha256sum "${TARGETS[@]}" tosctl)'
        for binary, path in (
            ("tos-rpc", "services/tos-rpc"),
            ("tos-wallet-index", "services/tos-wallet-index"),
        ):
            other = "tos-wallet-index" if binary == "tos-rpc" else "tos-rpc"
            dropped = f" {binary}"
            script_mutants = {
                "build target dropped": script.replace(targets, targets.replace(dropped, "", 1)),
                "build path dropped": script.replace(f"  [{binary}]={path}\n", ""),
                "build path moved": script.replace(
                    f"  [{binary}]={path}\n", f"  [{binary}]=services/{other}\n"
                ),
                "jemalloc check dropped": script.replace(
                    jemalloc, jemalloc.replace(dropped, "", 1)
                ),
                "not copied into the zip": script.replace(
                    install,
                    f'for t in "${{TARGETS[@]}}"; do\n  [ "$t" = {binary} ] && continue\n'
                    "  install -m 0755",
                ),
                "no needed line": script.replace(
                    needed,
                    f'for t in "${{TARGETS[@]}}" tosctl; do\n    [ "$t" = {binary} ] && continue\n'
                    '    echo "needed $t',
                ),
                "no digest": script.replace(
                    digests, f'(cd "$OUT" && sha256sum "${{TARGETS[@]/{binary}}}" tosctl)'
                ),
            }
            for label, mutant in script_mutants.items():
                with self.subTest(binary=binary, mutant=label):
                    self.assertNotEqual(mutant, script)
                    self.assertNotEqual(node_release_problems(config, workflow, mutant), [])
            for arch in self.ARCHES:
                with self.subTest(binary=binary, arch=arch, mutant="asset dropped"):
                    mutant = json.loads(json.dumps(config))
                    assets = mutant["release_sets"]["full"]["assets"]
                    before = len(assets)
                    assets[:] = [a for a in assets if a["name"] != f"{binary}-linux-{arch}"]
                    self.assertEqual(len(assets), before - 1)
                    self.assertEqual(
                        node_release_problems(mutant, workflow, script),
                        [f"the full set does not publish {binary}-linux-{arch}"],
                    )

    def test_tosctl_is_built_locked_published_and_recorded(self) -> None:
        # tosctl ships in the node artifact: dropping it from the script's
        # output, the build record or the asset list, taking it from another
        # artifact, or loosening its build is refused.
        config, workflow, script = self.inputs()
        self.assertEqual(node_release_problems(config, workflow, script), [])
        script_mutants = {
            "not copied into the zip": ('install -m 0755 "$TOSCTL" "$OUT/tosctl"\n', ""),
            "no needed line": (
                'for t in "${TARGETS[@]}" tosctl; do',
                'for t in "${TARGETS[@]}"; do',
            ),
            "no digest": ('sha256sum "${TARGETS[@]}" tosctl)', 'sha256sum "${TARGETS[@]}")'),
            "no toolchain record": ('  echo "$RUSTC_VERSION"\n  echo "$CARGO_VERSION"\n', ""),
            "no flags record": ('  echo "rust_flags RUSTFLAGS=$TOSCTL_RUSTFLAGS ', '  : "'),
            "not locked": (
                "cargo build --release --locked -p tosctl -j",
                "cargo build --release -p tosctl -j",
            ),
            "second unlocked build": (
                '  cargo build --release --locked -p tosctl -j "$JOBS"\n',
                '  cargo build --release -p tosctl\n  cargo build --release --locked -p tosctl -j "$JOBS"\n',
            ),
            "debug build": (
                "cargo build --release --locked -p tosctl -j",
                "cargo build --locked -p tosctl -j",
            ),
            "another package": ("--locked -p tosctl -j", "--locked -p commands -j"),
            "host CPU": (
                'TOSCTL_RUSTFLAGS="-C target-cpu=$RUST_CPU"',
                'TOSCTL_RUSTFLAGS="-C target-cpu=native"',
            ),
            "x86-64 target CPU dropped": (
                "CPU=x86-64-v2 RUST_CPU=x86-64-v2 ;;",
                "CPU=x86-64-v2 RUST_CPU=generic ;;",
            ),
            "ambient flags": (
                '  export RUSTFLAGS="$TOSCTL_RUSTFLAGS" CARGO_TARGET_DIR',
                "  export CARGO_TARGET_DIR",
            ),
            "compiler wrapper allowed": (
                '  export RUSTC_WRAPPER="" CARGO_BUILD_RUSTC_WRAPPER="" CARGO_INCREMENTAL=0\n',
                "",
            ),
            "compiler cache": ('export RUSTC_WRAPPER=""', "export RUSTC_WRAPPER=sccache"),
            "host C compiler": ("  export CC=clang-21 CXX=clang++-21\n", ""),
            "toolchain check dropped": (
                '[[ "$RUSTC_VERSION" == "rustc $RUST_CHANNEL "* ]] || die',
                "true || die",
            ),
            "commit check dropped": (
                '"$TOSCTL" --version | grep -qx "COMMIT_ID: $REV" ||',
                "true ||",
            ),
            "commit check tolerated": (
                '|| die "tosctl --version does not report commit $REV"',
                '|| echo "tosctl --version does not report commit $REV"',
            ),
            "lock file change tolerated": (
                '|| die "the tosctl build changed the checkout"',
                "|| true",
            ),
        }
        for label, (old, new) in script_mutants.items():
            with self.subTest(mutant=label):
                self.assertEqual(script.count(old), 1, old)
                self.assertNotEqual(
                    node_release_problems(config, workflow, script.replace(old, new)), []
                )
        workflow_mutants = {
            "toolchain not installed": (
                "    - name: Install repository-pinned Rust toolchain\n"
                "      run: scripts/install-rust-toolchain.sh\n",
                "",
            ),
            "toolchain installed after the build": (
                "      run: scripts/install-rust-toolchain.sh\n",
                "      run: true\n",
            ),
            "compiler cache": (
                "    - name: Upload artifacts\n",
                "    - run: sccache --start-server\n    - name: Upload artifacts\n",
            ),
            **{
                f"{path} is not a trigger": (f"      - '{path}'\n", "") for path in self.RUST_INPUTS
            },
        }
        for label, (old, new) in workflow_mutants.items():
            with self.subTest(mutant=label):
                self.assertEqual(workflow.count(old), 1, old)
                self.assertNotEqual(
                    node_release_problems(config, workflow.replace(old, new), script), []
                )
        for arch, (artifact, _runner, _cpu, _rust_cpu) in self.ARCHES.items():
            name = f"tosctl-linux-{arch}"
            with self.subTest(arch=arch, mutant="asset dropped"):
                mutant = json.loads(json.dumps(config))
                assets = mutant["release_sets"]["full"]["assets"]
                before = len(assets)
                assets[:] = [a for a in assets if a["name"] != name]
                self.assertEqual(len(assets), before - 1)
                self.assertEqual(
                    node_release_problems(mutant, workflow, script),
                    [f"the full set does not publish {name}"],
                )
            for other in (
                f"tos-{arch}-linux",
                "tos-node-" + ("arm64" if arch == "x86_64" else "x86_64") + "-linux",
            ):
                with self.subTest(arch=arch, mutant=f"taken from {other}"):
                    mutant = json.loads(json.dumps(config))
                    for asset in mutant["release_sets"]["full"]["assets"]:
                        if asset["name"] == name:
                            asset["artifact"] = other
                    self.assertIn(
                        f"{name} is not {artifact}/tosctl",
                        node_release_problems(mutant, workflow, script),
                    )
            with self.subTest(arch=arch, mutant="another member"):
                mutant = json.loads(json.dumps(config))
                for asset in mutant["release_sets"]["full"]["assets"]:
                    if asset["name"] == name:
                        asset["path"] = "lite-client"
                self.assertEqual(
                    node_release_problems(mutant, workflow, script),
                    [f"{name} is not {artifact}/tosctl"],
                )

    def test_a_missing_artifact_zip_is_refused(self) -> None:
        config, workflow, script = self.inputs()
        assets = config["release_sets"]["full"]["assets"]
        assets[:] = [a for a in assets if a["name"] != "tos-node-linux-x86_64.zip"]
        self.assertEqual(
            node_release_problems(config, workflow, script),
            ["the full set does not publish tos-node-x86_64-linux as tos-node-linux-x86_64.zip"],
        )

    def test_a_weakened_recipe_is_refused(self) -> None:
        config, workflow, script = self.inputs()
        mutants = {
            "-DTOS_USE_JEMALLOC=ON": "-DTOS_USE_JEMALLOC=OFF",
            "CPU=x86-64-v2": "CPU=native",
            "CPU=armv8-a": "CPU=native",
            "-DCMAKE_BUILD_TYPE=Release": "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
            "export SOURCE_DATE_EPOCH": "",
            "clang++-21 \\": "g++ \\",
            "tos-pq-consensus-key dht-server tos-rpc tos-wallet-index)": "tos-pq-consensus-key)",
            "grep -q 'jemalloc statistics'": "true",
        }
        for old, new in mutants.items():
            with self.subTest(mutant=old):
                self.assertIn(old, script)
                self.assertNotEqual(
                    node_release_problems(config, workflow, script.replace(old, new, 1)), []
                )

    def test_a_cached_or_unscripted_build_is_refused(self) -> None:
        config, workflow, script = self.inputs()
        for old, new in {
            "run: assembly/native/build-node-binaries.sh node-binaries": "run: make",
            "    - name: Upload artifacts\n": "    - uses: actions/cache@x\n    - name: Upload artifacts\n",
            "runner: ubuntu-24.04-arm\n": "runner: ubuntu-24.04\n",
        }.items():
            with self.subTest(mutant=old):
                self.assertIn(old, workflow)
                self.assertNotEqual(
                    node_release_problems(config, workflow.replace(old, new, 1), script), []
                )


def macos_release_problems(workflow: str, script: str) -> list[str]:
    """Why the macOS release build would not be the macOS recipe.

    The macOS binaries are the build the shared macOS workflow tests, fixed to
    a CPU level and a minimum macOS, and checked to need nothing a stock macOS
    does not provide.
    """
    problems: list[str] = []
    name = MacosReleaseTest.WORKFLOW
    head, _, jobs = workflow.partition("\njobs:\n")
    if re.findall(r"(?m)^  [A-Za-z0-9_-]+:$", jobs) != ["  build:"]:
        problems.append(f"{name} must have exactly the one build job")
    for pattern, why in (
        (r"(?m)^\s*(?:- )?if:", "a condition"),
        (r"(?m)^\s*continue-on-error:", "a tolerated failure"),
        (r"(?m)^\s*strategy:", "a matrix"),
    ):
        if re.search(pattern, jobs):
            problems.append(f"{name} has {why}; the build must always run whole")
    for line in (
        "    runs-on: macos-15\n",
        "      run: assembly/native/build-macos-release.sh macos-binaries\n",
        "        name: tos-arm64-macos\n",
        "        path: macos-binaries\n",
    ):
        if line not in jobs:
            problems.append(f"{name} lost {line.strip()!r}")
    if "ccache" in workflow or "actions/cache" in workflow:
        problems.append(f"{name} reuses cached objects")
    install_rust = "      run: scripts/install-rust-toolchain.sh\n"
    build_step = "      run: assembly/native/build-macos-release.sh macos-binaries\n"
    if not 0 <= workflow.find(install_rust) < workflow.find(build_step):
        problems.append(f"{name} does not install the pinned Rust toolchain first")
    for path in (*NodeBinaryReleaseTest.RUST_INPUTS, "assembly/native/build-macos-release.sh"):
        if f"      - '{path}'\n" not in head:
            problems.append(f"{name} does not run when {path} changes")
    recipe = [
        '[ "$(uname -m)" = arm64 ] || die ',
        "\nCPU=apple-m1\nROCKSDB_CPU=armv8-a\nRUST_CPU=apple-m1\nMACOS_MIN=15.0\n",
        "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)\nexport SOURCE_DATE_EPOCH\n",
        "\nexport MACOSX_DEPLOYMENT_TARGET=$MACOS_MIN\n",
        "export CCACHE_DISABLE=1\n",
        "\nunset TOS_SLHDSA_SHA_NI TOS_SLHDSA_ARMV8_SHA2\n",
        "  -DCMAKE_BUILD_TYPE=Release \\\n",
        '  -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOS_MIN" \\\n',
        '  -DTOS_ARCH="$CPU" -DPORTABLE="$ROCKSDB_CPU" \\\n',
        # The recipe read back from the configured cache ...
        '\n[ "$(cached CMAKE_BUILD_TYPE)" = Release ] || die ',
        '\n[ "$(cached TOS_ARCH)" = "$CPU" ] || die ',
        '\n[ "$(cached PORTABLE)" = "$ROCKSDB_CPU" ] || die ',
        '\n[ "$(cached CMAKE_OSX_DEPLOYMENT_TARGET)" = "$MACOS_MIN" ] || die ',
        '\n[ "$(cached TOS_SLHDSA_ARMV8_SHA2)" = ON ] || die ',
        # ... every shipped Mach-O file checked ...
        '\n  [ "$archs" = arm64 ] || die ',
        '\n  [ "$minos" = "$MACOS_MIN" ] || die ',
        '\n  codesign --verify "$file" || die ',
        "\n      /usr/lib/*|/System/Library/*) ;;\n"
        '      *) die "$file links $dep, which macOS does not provide" ;;\n',
        '\nfor name in "${SHIPPED[@]}"; do\n  check_macho "$OUT/$name"\ndone\n',
        # ... the commit every binary with -V reports ...
        '\n  "$BUILD/$path" -V | grep -q "Commit: $REV" || die ',
        # ... and tosctl as the Linux node recipe builds it.
        '\n[[ "$RUSTC_VERSION" == "rustc $RUST_CHANNEL "* ]] || die ',
        '\n[[ "$CARGO_VERSION" == "cargo $RUST_CHANNEL "* ]] || die ',
        '\nTOSCTL_RUSTFLAGS="-C target-cpu=$RUST_CPU"\n',
        '\n  export RUSTC_WRAPPER="" CARGO_BUILD_RUSTC_WRAPPER="" CARGO_INCREMENTAL=0\n',
        "\n  unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET GIT_COMMIT GIT_COMMIT_DATE\n",
        "\n  export GIT_BRANCH=HEAD\n",
        "\nunset RUSTC CARGO_BUILD_RUSTC RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER\n",
        '[ -z "$(git status --porcelain --untracked-files=no)" ] || die "the tosctl build changed the checkout"\n',
        '\n"$TOSCTL" --version | grep -qx "COMMIT_ID: $REV" || die ',
    ]
    for line in recipe:
        if line not in script:
            problems.append(f"the macOS build script lost {line.strip()!r}")
    cargo_builds = re.findall(r"(?m)^\s*cargo build\b.*$", script)
    if [line.split() for line in cargo_builds] != [
        ["cargo", "build", "--release", "--locked", "-p", "tosctl", "-j", '"$JOBS"']
    ]:
        problems.append("the macOS build script does not build tosctl with --release --locked")
    if "native" in re.sub(r"(?m)#.*$", "", script) or "sccache" in script:
        problems.append("the macOS build script uses the build host's CPU or a compiler cache")
    node_files = re.search(r"\nNODE_FILES=\(\n((?:  [a-z-]+=\S+\n)*)\)\n", script)
    found = dict(re.findall(r"  ([a-z-]+)=(\S+)\n", node_files.group(1))) if node_files else None
    if found != NodeBinaryReleaseTest.PATHS:
        problems.append(
            "the macOS build script does not ship the node binaries from their build paths"
        )
    versioned = re.search(r"\nVERSIONED_TARGETS=\(([^)]*)\)\n", script)
    if versioned is None or not set(NodeBinaryReleaseTest.VERSIONED_BINARIES) <= set(
        versioned.group(1).split()
    ):
        problems.append(
            "the macOS build script does not check the commit of every node binary with -V"
        )
    return problems


class MacosReleaseTest(unittest.TestCase):
    """The macOS release build is the tested macOS recipe, checked for portability."""

    WORKFLOW = "build-tos-macos-15-arm64-release.yml"

    def inputs(self) -> tuple[str, str]:
        return (
            (HERE.parent / ".github" / "workflows" / self.WORKFLOW).read_text(),
            (HERE.parent / "assembly" / "native" / "build-macos-release.sh").read_text(),
        )

    def test_repository_builds_the_macos_recipe(self) -> None:
        self.assertEqual(macos_release_problems(*self.inputs()), [])

    def test_a_weakened_script_is_refused(self) -> None:
        workflow, script = self.inputs()
        mutants = {
            "MACOS_MIN=15.0\n": "MACOS_MIN=27.0\n",
            "\nCPU=apple-m1\n": "\nCPU=native\n",
            '  [ "$archs" = arm64 ] || die ': '  [ "$archs" = arm64 ] || echo ',
            '  [ "$minos" = "$MACOS_MIN" ] || die ': "  true || die ",
            "      /usr/lib/*|/System/Library/*) ;;": "      /usr/lib/*|/System/Library/*|/opt/*) ;;",
            '  codesign --verify "$file" || die ': '  codesign --verify "$file" || echo ',
            '  check_macho "$OUT/$name"\n': "  true\n",
            '"$BUILD/$path" -V | grep -q "Commit: $REV" || die ': "true || die ",
            "export CCACHE_DISABLE=1\n": "",
            "  dht-server=dht-server/dht-server\n": "",
            'cargo build --release --locked -p tosctl -j "$JOBS"': 'cargo build --release -p tosctl -j "$JOBS"',
            '[ "$(cached TOS_SLHDSA_ARMV8_SHA2)" = ON ] || die ': "true || die ",
        }
        for old, new in mutants.items():
            with self.subTest(mutant=old):
                self.assertIn(old, script)
                self.assertNotEqual(
                    macos_release_problems(workflow, script.replace(old, new, 1)), []
                )

    def test_a_weakened_workflow_is_refused(self) -> None:
        workflow, script = self.inputs()
        mutants = {
            "run: assembly/native/build-macos-release.sh macos-binaries": "run: make",
            "    runs-on: macos-15\n": "    runs-on: macos-15\n    continue-on-error: true\n",
            "    - name: Upload artifacts\n": "    - uses: actions/cache@x\n    - name: Upload artifacts\n",
            "      - 'tosctl/src/Cargo.lock'\n": "",
            "        name: tos-arm64-macos\n": "        name: tos-macos\n",
        }
        for old, new in mutants.items():
            with self.subTest(mutant=old):
                self.assertIn(old, workflow)
                self.assertNotEqual(
                    macos_release_problems(workflow.replace(old, new, 1), script), []
                )


if __name__ == "__main__":
    unittest.main()
