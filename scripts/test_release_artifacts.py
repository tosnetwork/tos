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
EXTRA_ARTIFACTS = ("tos-extra-linux-x64", "tos-extra-macos-arm64")
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
        api.served["tos-extra-macos-arm64"] = zip_bytes({"x": b"tampered"})
        self.assert_refused(api, "artifact tos-extra-macos-arm64: downloaded sha256")

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
        self.assertEqual(status, 1)
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


if __name__ == "__main__":
    unittest.main()
