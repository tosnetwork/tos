#!/usr/bin/env python3
"""Reuse only a successful, attested identical snapshot on ready_for_review."""

import argparse
import io
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

MAX_ARCHIVE = 65536
MAX_RECEIPT = 16384
SCHEMA = 1


class StripRedirectCredentials(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).scheme != "https":
            raise ValueError("Artifact redirect must use HTTPS")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        redirected.remove_header("Authorization")
        return redirected


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def context(job, env=os.environ):
    payload = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text())
    pr = payload.get("pull_request")
    if env.get("GITHUB_EVENT_NAME") != "pull_request" or not pr:
        return None, payload
    repository = env["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid repository")
    workflow_ref = env["GITHUB_WORKFLOW_REF"]
    prefix = repository + "/"
    if not workflow_ref.startswith(prefix):
        raise ValueError("Unexpected workflow repository")
    workflow = workflow_ref[len(prefix) :].split("@", 1)[0]
    if not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", workflow):
        raise ValueError("Invalid workflow path")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", job):
        raise ValueError("Invalid job identity")
    return {
        "schema": SCHEMA,
        "repository": repository,
        "pr": int(pr["number"]),
        "head": pr["head"]["sha"],
        "base": pr["base"]["sha"],
        "tree": git("rev-parse", "HEAD^{tree}"),
        "workflow": workflow,
        "workflow_blob": git("rev-parse", "HEAD:" + workflow),
        "job": job,
    }, payload


def receipt_path(job, env=os.environ):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", job):
        raise ValueError("Invalid job identity")
    return Path(env["RUNNER_TEMP"]) / ("ci-snapshot-" + job + ".json")


def artifact_name(job):
    return "ci-snapshot-" + job


def archive_receipt(raw):
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("Artifact archive too large")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        files = archive.infolist()
        if len(files) != 1 or not re.fullmatch(
            r"ci-snapshot-[A-Za-z0-9_.-]+\.json", files[0].filename
        ):
            raise ValueError("Unexpected snapshot artifact contents")
        if files[0].file_size > MAX_RECEIPT:
            raise ValueError("Snapshot receipt too large")
        return json.loads(archive.read(files[0]))


class Api:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(StripRedirectCredentials())

    def read(self, path, limit=2_000_000):
        request = urllib.request.Request(
            "https://api.github.com/" + path,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with self.opener.open(request, timeout=15) as response:
            raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("API response too large")
        return raw

    def json(self, path):
        return json.loads(self.read(path))


def reusable_run(identity, api, current_run):
    repo = identity["repository"]
    name = identity["workflow"].rsplit("/", 1)[1]
    query = urllib.parse.urlencode(
        {"event": "pull_request", "status": "success", "head_sha": identity["head"], "per_page": 10}
    )
    runs = api.json(f"repos/{repo}/actions/workflows/{name}/runs?{query}")["workflow_runs"]
    for run in runs:
        if (
            run["id"] == current_run
            or run["status"] != "completed"
            or run["conclusion"] != "success"
            or run["head_sha"] != identity["head"]
            or run["event"] != "pull_request"
            or run["path"] != identity["workflow"]
        ):
            continue
        rid = int(run["id"])
        artifacts = api.json(f"repos/{repo}/actions/runs/{rid}/artifacts?per_page=100")["artifacts"]
        matches = []
        for artifact in artifacts:
            match = re.fullmatch(
                re.escape(artifact_name(identity["job"])) + r"-attempt-([1-9][0-9]*)",
                artifact["name"],
            )
            if match and not artifact["expired"] and 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE:
                attempt = int(match[1])
                if attempt <= int(run["run_attempt"]):
                    matches.append((attempt, artifact))
        if not matches or len({attempt for attempt, _ in matches}) != len(matches):
            continue
        attempt, artifact = max(matches, key=lambda item: item[0])
        aid = int(artifact["id"])
        prior = archive_receipt(api.read(f"repos/{repo}/actions/artifacts/{aid}/zip", MAX_ARCHIVE))
        if (
            prior.get("identity") == identity
            and prior.get("run_id") == rid
            and prior.get("run_attempt") == attempt
            and prior.get("executed") is True
        ):
            return rid
    return None


def decide(identity, payload, env=os.environ, api=None):
    if identity is None or payload.get("action") != "ready_for_review":
        return None
    token = env.get("GH_TOKEN")
    if not token:
        return None
    try:
        return reusable_run(identity, api or Api(token), int(env["GITHUB_RUN_ID"]))
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, EOFError, zipfile.BadZipFile):
        # Unavailable, incomplete or malformed evidence always means real tests.
        print("Snapshot evidence unavailable; executing the complete job")
        return None


def record(identity, job, env=os.environ):
    if identity is None:
        raise ValueError("Only PR validation can publish reusable evidence")
    subprocess.run(["git", "diff", "--quiet", "HEAD"], check=True)
    receipt_path(job, env).write_text(
        json.dumps(
            {
                "identity": identity,
                "run_id": int(env["GITHUB_RUN_ID"]),
                "run_attempt": int(env["GITHUB_RUN_ATTEMPT"]),
                "executed": True,
            },
            sort_keys=True,
        )
        + "\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    if args.record:
        identity, _ = context(args.job)
        record(identity, args.job)
        return
    try:
        identity, payload = context(args.job)
        previous = decide(identity, payload)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError):
        previous = None
        print("Snapshot context unavailable; executing the complete job")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write("run-tests=" + ("false" if previous else "true") + "\n")
    if previous:
        url = f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{previous}"
        message = "Reusing successful identical head/base/tree/workflow/job validation: " + url
        print(message)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
                summary.write(message + "\n")


if __name__ == "__main__":
    main()
