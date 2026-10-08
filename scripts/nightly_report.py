#!/usr/bin/env python3
"""Keep one tracking issue in step with the nightly platform matrix.

Run by the nightly-report job of .github/workflows/platform-nightly.yml at the
end of a scheduled run. It reads the run's job conclusions through the API. A
failing night opens the issue or adds a comment to it; a green night comments
and closes it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

TITLE = "Nightly platform matrix is failing"
GOOD = {"success", "skipped"}
# The job running this script, still in progress while it reads the run.
SELF = "nightly-report"
# The job that calls the platform matrix.
CALLER = "matrix"


def failing_members(jobs: list[dict]) -> list[str]:
    """Members with a job that did not succeed.

    Jobs of the called matrix are named "matrix / <member> / <job>"; the member is
    the segment after "matrix".
    """
    failing = set()
    for job in jobs:
        if job.get("name") == SELF:
            continue
        if job.get("conclusion") not in GOOD:
            parts = job.get("name", "?").split(" / ")
            if parts[0] == CALLER and len(parts) > 1:
                parts = parts[1:]
            failing.add(parts[0])
    return sorted(failing)


def plan(
    conclusion: str, jobs: list[dict], issue: int | None, run_url: str
) -> list[tuple[str, str]]:
    """The issue actions for one finished run: (action, text) pairs."""
    failing = failing_members(jobs)
    if conclusion == "success" and not failing:
        if issue is None:
            return []
        return [("comment", f"Green again: {run_url}"), ("close", "")]
    lines = [f"Nightly run {run_url} concluded `{conclusion}`.", ""]
    lines += [f"- {name}" for name in failing] or ["- (no member job failed; see the run)"]
    body = "\n".join(lines)
    if issue is None:
        return [("create", body)]
    return [("comment", body)]


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def main() -> int:
    repo, run_id = os.environ["REPO"], os.environ["RUN_ID"]
    conclusion, run_url = os.environ["CONCLUSION"], os.environ["RUN_URL"]
    # One compact object per line across every page; pages themselves are not
    # newline-separated JSON documents.
    listed = gh(
        "api",
        "--paginate",
        f"/repos/{repo}/actions/runs/{run_id}/jobs?per_page=100",
        "--jq",
        ".jobs[] | {name, conclusion}",
    )
    jobs = [json.loads(line) for line in listed.splitlines() if line.strip()]
    found = json.loads(
        gh(
            "issue",
            "list",
            "--repo",
            repo,
            "--state",
            "open",
            "--search",
            f'in:title "{TITLE}"',
            "--json",
            "number,title",
        )
    )
    issue = next((item["number"] for item in found if item["title"] == TITLE), None)
    for action, text in plan(conclusion, jobs, issue, run_url):
        if action == "create":
            gh("issue", "create", "--repo", repo, "--title", TITLE, "--body", text)
        elif action == "comment":
            gh("issue", "comment", str(issue), "--repo", repo, "--body", text)
        elif action == "close":
            gh("issue", "close", str(issue), "--repo", repo)
        print(action, text.splitlines()[0] if text else "")
    return 0


if __name__ == "__main__":
    sys.exit(main())
