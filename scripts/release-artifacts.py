#!/usr/bin/env python3
"""Collect and stage release assets built from exactly the release tag's commit.

A release publishes binaries under a tag, so the binaries must be the ones
built from the commit the tag names. For every build workflow this script
selects a successful run whose immutable head_sha equals the tag commit, and
refuses the release when there is none: there is no "latest successful run"
fallback. Each artifact is then bound to that run by its id, its run id and
head_sha, and the SHA-256 digest GitHub recorded at upload time, which the
downloaded zip must match before anything is unpacked.

  collect  select runs, download and verify artifacts, write provenance
  stage    copy the configured assets under their release names, build the
           bundles, and write SHA256SUMS over everything staged

The GitHub API is reached through the gh CLI, using GH_TOKEN from the
environment. Nothing here publishes: a separate job with write permission
uploads the staged directory after checking SHA256SUMS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
# A pull_request run builds the merge commit, not head_sha, and runs code the
# release never reviewed; only runs of the commit itself qualify.
TRUSTED_EVENTS = frozenset({"push", "workflow_dispatch"})
ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class ReleaseError(Exception):
    pass


class Api(Protocol):
    def get_json(self, path: str) -> Any: ...

    def download(self, path: str, destination: Path) -> None: ...


class GhApi:
    def get_json(self, path: str) -> Any:
        result = subprocess.run(["gh", "api", path], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise ReleaseError(f"GitHub API request {path} failed: {result.stderr.strip()}")
        return json.loads(result.stdout)

    def download(self, path: str, destination: Path) -> None:
        with destination.open("wb") as handle:
            result = subprocess.run(
                ["gh", "api", path], stdout=handle, stderr=subprocess.PIPE, check=False
            )
        if result.returncode != 0:
            raise ReleaseError(
                f"GitHub API download {path} failed: {result.stderr.decode(errors='replace').strip()}"
            )


@dataclass(frozen=True)
class SelectedRun:
    workflow: str
    run_id: int
    run_attempt: int
    head_sha: str
    event: str
    html_url: str


def require_sha(value: str, what: str) -> str:
    if not SHA1_RE.fullmatch(value):
        raise ReleaseError(
            f"{what} must be a full 40-character lowercase commit SHA, got {value!r}"
        )
    return value


def run_rejection(run: dict[str, Any], *, repo: str, workflow: str, tag_sha: str) -> str | None:
    """Why a run cannot supply release artifacts, or None when it can."""
    if run.get("head_sha") != tag_sha:
        return f"head_sha {run.get('head_sha')} is not the tag commit"
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return f"status {run.get('status')}/{run.get('conclusion')} is not completed/success"
    if run.get("event") not in TRUSTED_EVENTS:
        return f"event {run.get('event')} is not one of {sorted(TRUSTED_EVENTS)}"
    if (run.get("repository") or {}).get("full_name") != repo:
        return "run belongs to another repository"
    if (run.get("head_repository") or {}).get("full_name") != repo:
        return "run was built from another repository's head"
    if run.get("path") != f".github/workflows/{workflow}":
        return f"run is of {run.get('path')}, not {workflow}"
    return None


def select_run(
    runs: list[dict[str, Any]], *, repo: str, workflow: str, tag_sha: str
) -> SelectedRun:
    require_sha(tag_sha, "tag commit")
    accepted: list[dict[str, Any]] = []
    reasons: list[str] = []
    for run in runs:
        reason = run_rejection(run, repo=repo, workflow=workflow, tag_sha=tag_sha)
        if reason is None:
            accepted.append(run)
        else:
            reasons.append(f"run {run.get('id')}: {reason}")
    if not accepted:
        detail = "; ".join(reasons) if reasons else "no runs at all"
        raise ReleaseError(
            f"{workflow}: no successful push or workflow_dispatch run of commit {tag_sha} ({detail}). "
            f"Run the workflow on the release tag first."
        )
    # Every accepted run built the same commit; the newest attempt is used and
    # recorded, so the choice is reproducible from the provenance file.
    chosen = max(accepted, key=lambda run: (int(run["id"]), int(run.get("run_attempt", 1))))
    return SelectedRun(
        workflow=workflow,
        run_id=int(chosen["id"]),
        run_attempt=int(chosen.get("run_attempt", 1)),
        head_sha=str(chosen["head_sha"]),
        event=str(chosen["event"]),
        html_url=str(chosen.get("html_url", "")),
    )


def select_artifact(
    artifacts: list[dict[str, Any]], *, name: str, run: SelectedRun
) -> dict[str, Any]:
    matching = [artifact for artifact in artifacts if artifact.get("name") == name]
    if len(matching) != 1:
        raise ReleaseError(
            f"run {run.run_id} has {len(matching)} artifacts named {name}, expected exactly one"
        )
    artifact = matching[0]
    if artifact.get("expired"):
        raise ReleaseError(f"artifact {name} of run {run.run_id} has expired")
    workflow_run = artifact.get("workflow_run") or {}
    if workflow_run.get("id") != run.run_id or workflow_run.get("head_sha") != run.head_sha:
        raise ReleaseError(f"artifact {name} is not bound to run {run.run_id} at {run.head_sha}")
    if not DIGEST_RE.fullmatch(str(artifact.get("digest") or "")):
        raise ReleaseError(f"artifact {name} of run {run.run_id} carries no sha256 digest")
    return artifact


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_extract(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            name = PurePosixPath(member.filename)
            if name.is_absolute() or ".." in name.parts or "\\" in member.filename:
                raise ReleaseError(
                    f"{archive.name}: member {member.filename!r} escapes the artifact directory"
                )
            # The high bits of external_attr carry the Unix mode; a symlink
            # entry would let a later member write outside the directory.
            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise ReleaseError(f"{archive.name}: member {member.filename!r} is a symbolic link")
        destination.mkdir(parents=True, exist_ok=False)
        bundle.extractall(destination)


def collect(
    api: Api, config: dict[str, Any], *, repo: str, tag: str, tag_sha: str, out: Path
) -> dict[str, Any]:
    require_sha(tag_sha, "tag commit")
    out.mkdir(parents=True, exist_ok=False)
    records = []
    for entry in config["build_workflows"]:
        workflow, name = entry["workflow"], entry["artifact"]
        runs = api.get_json(
            f"repos/{repo}/actions/workflows/{workflow}/runs?head_sha={tag_sha}&status=success&per_page=100"
        )["workflow_runs"]
        run = select_run(runs, repo=repo, workflow=workflow, tag_sha=tag_sha)
        artifacts = api.get_json(
            f"repos/{repo}/actions/runs/{run.run_id}/artifacts?name={name}&per_page=100"
        )["artifacts"]
        artifact = select_artifact(artifacts, name=name, run=run)
        expected = DIGEST_RE.fullmatch(artifact["digest"]).group(1)  # type: ignore[union-attr]
        archive = out / f"{name}.zip"
        api.download(f"repos/{repo}/actions/artifacts/{artifact['id']}/zip", archive)
        actual = sha256_file(archive)
        if actual != expected:
            archive.unlink()
            raise ReleaseError(
                f"artifact {name}: downloaded sha256 {actual} does not match recorded {expected}"
            )
        safe_extract(archive, out / name)
        records.append(
            {
                "workflow": workflow,
                "run_id": run.run_id,
                "run_attempt": run.run_attempt,
                "run_url": run.html_url,
                "event": run.event,
                "head_sha": run.head_sha,
                "artifact_id": int(artifact["id"]),
                "artifact_name": name,
                "artifact_digest": artifact["digest"],
            }
        )
    provenance = {"repository": repo, "tag": tag, "tag_commit": tag_sha, "artifacts": records}
    (out / "release-provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n"
    )
    return provenance


def checked_asset_name(name: str) -> str:
    if not ASSET_NAME_RE.fullmatch(name):
        raise ReleaseError(f"asset name {name!r} is not a plain file name")
    return name


def stage(config: dict[str, Any], *, release_set: str, artifacts: Path, out: Path) -> list[str]:
    provenance = artifacts / "release-provenance.json"
    if not provenance.is_file():
        raise ReleaseError("artifacts were not collected: release-provenance.json is missing")
    spec = config["release_sets"].get(release_set)
    if spec is None:
        raise ReleaseError(f"unknown release set {release_set!r}")
    out.mkdir(parents=True, exist_ok=False)
    staged: list[str] = []

    def claim(name: str) -> Path:
        target = out / checked_asset_name(name)
        if name in staged:
            raise ReleaseError(f"asset {name} is staged twice")
        staged.append(name)
        return target

    for asset in spec["assets"]:
        artifact_dir = artifacts / asset["artifact"]
        if asset.get("zip"):
            source = artifacts / f"{asset['artifact']}.zip"
        else:
            source = artifact_dir / asset["path"]
            if not source.resolve().is_relative_to(artifact_dir.resolve()):
                raise ReleaseError(
                    f"asset path {asset['path']!r} leaves artifact {asset['artifact']}"
                )
        if not source.is_file():
            raise ReleaseError(f"asset {asset['name']}: {source.relative_to(artifacts)} is missing")
        shutil.copyfile(source, claim(asset["name"]))

    for bundle in spec.get("bundles", []):
        target = claim(bundle["name"])
        root = artifacts / bundle["artifact"]
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for directory in bundle["directories"]:
                base = root / directory
                if not base.is_dir():
                    raise ReleaseError(
                        f"bundle {bundle['name']}: {bundle['artifact']}/{directory} is missing"
                    )
                for path in sorted(base.rglob("*")):
                    if path.is_file():
                        archive.write(path, str(path.relative_to(root)))

    shutil.copyfile(provenance, claim("release-provenance.json"))
    sums = "".join(f"{sha256_file(out / name)}  {name}\n" for name in sorted(staged))
    (out / "SHA256SUMS").write_text(sums)
    return sorted(staged)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--config", type=Path, default=Path(__file__).with_name("release-artifacts.json")
    )
    commands = parser.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect")
    collect_parser.add_argument("--repo", required=True)
    collect_parser.add_argument("--tag", required=True)
    collect_parser.add_argument("--tag-sha", required=True)
    collect_parser.add_argument("--out", type=Path, required=True)
    stage_parser = commands.add_parser("stage")
    stage_parser.add_argument("--set", dest="release_set", required=True)
    stage_parser.add_argument("--artifacts", type=Path, required=True)
    stage_parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    config = json.loads(args.config.read_text())
    try:
        if args.command == "collect":
            provenance = collect(
                GhApi(), config, repo=args.repo, tag=args.tag, tag_sha=args.tag_sha, out=args.out
            )
            for record in provenance["artifacts"]:
                print(
                    f"{record['artifact_name']}: run {record['run_id']} {record['artifact_digest']}"
                )
        else:
            for name in stage(
                config, release_set=args.release_set, artifacts=args.artifacts, out=args.out
            ):
                print(name)
    except ReleaseError as error:
        print(f"RELEASE_ARTIFACTS_REFUSED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
