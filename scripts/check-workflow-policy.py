#!/usr/bin/env python3
"""Workflow policy: every rule a workflow here must satisfy, checked from the files.

R1  every job that runs steps declares timeout-minutes (a job that calls a reusable
    workflow cannot, so the callee's own jobs carry it)
R2  every workflow declares top-level permissions
R3  every workflow triggered by a push, a pull request or a schedule declares
    concurrency; a callable workflow does not group on github.workflow (inside a
    call that is the caller's name, so every callee would share one group); a
    release workflow never cancels a run in progress
R4  no job runs on a moving *-latest runner label
R5  no trigger names a branch this repository does not have
R6  every platform workflow in the inventory below is a matrix member; the
    platform matrix runs exactly the members scripts/platform-matrix.json
    lists, each under its tier's condition, and its gate needs all of them; the
    nightly workflow calls the matrix and reports on the schedule alone, and its
    report is the only job holding a write grant
R7  an inherited platform workflow runs only through the matrix, by hand, or on a
    release tag: no pull_request trigger and no push trigger without tags
R8  every release build workflow keeps its v* tag trigger
R9  a matrix member uses no secret except GITHUB_TOKEN, and the matrix passes none
R10 every status badge in README.md names a workflow that runs for the event and
    branch it filters on; a badge that can never update shows a stale or empty status
R11 a workflow triggered by pull requests is push-triggered only for main, an
    integration branch listed below, or tags: a push to a pull request's own branch
    falls in a different concurrency group and runs the same change a second time.
    An unfiltered push, branches-ignore, a pattern or a negation is refused, since
    each admits branches nobody listed.
R12 a job reaches the self-hosted runner only through ROUTED_RUNS_ON: a trusted
    push to main or a same-repository pull request opened and triggered by a
    trusted login, while the repository variable switches routing on; any other
    event runs hosted. No job names a self-hosted label any other way. A
    workflow with a routed job grants no write permission and uses no secret
    except GITHUB_TOKEN, has exactly one weekly schedule (a scheduled run is
    hosted, so the fallback stays exercised), and each routed job's timeout,
    plus a margin for setup, fits the host's per-job cap.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs

import yaml

DEAD_BRANCHES = {"master", "testnet"}
AUTOMATIC = ("push", "pull_request", "pull_request_target", "schedule")
RELEASE_WORKFLOWS = {"create-release.yml", "create-tol-release.yml"}
TIER_CONDITIONS = {
    "platform": "needs.changes.outputs.relevant == 'true'",
    "nightly": "needs.changes.outputs.relevant == 'true' && "
    "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')",
}
GATE_JOB = "platform-gate"
REPORT_JOB = "nightly-report"
REPORT_CONDITION = "always() && github.event_name == 'schedule'"
REPORT_PERMISSIONS = {"actions": "read", "issues": "write"}
# The platform workflows the matrix must cover. Kept here, apart from the
# manifest, so that removing a platform from the manifest and the matrix
# together is still refused: losing one is a change to this list, made on purpose.
INHERITED_PLATFORM_WORKFLOWS = {
    "build-tos-linux-android-toslib.yml",
    "build-tos-linux-arm64-appimage.yml",
    "build-tos-linux-arm64-shared.yml",
    "build-tos-linux-x86-64-appimage.yml",
    "build-tos-linux-x86-64-shared.yml",
    "build-tos-macos-14-arm64-portable.yml",
    "build-tos-macos-15-arm64-shared.yml",
    "build-tos-macos-15-x86-64-portable.yml",
    "build-tos-macos-15-x86-64-shared.yml",
    "build-tos-macos-arm64-shared.yml",
    "build-tos-wasm-emscripten.yml",
    "build-tos-windows-mingw64.yml",
    "build-tos-windows-ucrt64.yml",
    "tos-ccpcheck.yml",
    "tos-x86-64-windows.yml",
}


# Branches besides main whose pushes may run a workflow that pull requests also
# run, each with the reason the push run is not a duplicate.
INTEGRATION_BRANCHES = {
    "node-health-monitor": "integration branch for node-health-monitor work; a push "
    "there is the post-merge check of a reviewed isolation pull request",
}
PUSH_BRANCHES = {"main", *INTEGRATION_BRANCHES}

# The only runs-on that may name the self-hosted runner, compared with all
# whitespace collapsed. Its trusted-login list and switch are repository
# variables, so routing can be turned off without a commit.
ROUTED_RUNS_ON = " ".join(
    """${{ (vars.SELF_HOSTED_LINUX == 'true' && (
    (github.event_name == 'push' && github.ref == 'refs/heads/main') ||
    (github.event_name == 'pull_request' &&
     github.event.pull_request.head.repo.full_name == github.repository &&
     contains(fromJSON(vars.CI_TRUSTED_LOGINS), github.event.pull_request.user.login) &&
     contains(fromJSON(vars.CI_TRUSTED_LOGINS), github.triggering_actor))))
    && fromJSON('["self-hosted","linux","x64","tos-vm"]') || 'ubuntu-24.04' }}""".split()
)
SELF_HOSTED_MARKERS = ("self-hosted", "tos-vm")
# The host stops a job at this many minutes; a routed job's own timeout plus the
# setup margin must fit inside it, so the job's timeout is what ends a hang.
HOST_JOB_CAP_MINUTES = 165
HOST_SETUP_MARGIN_MINUTES = 15
WEEKLY_CRON = re.compile(r"(?:[0-9]|[1-5][0-9]) (?:[0-9]|1[0-9]|2[0-3]) \* \* [0-6]")
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
# Expression context and property names are case-insensitive.
SECRET_ACCESS = re.compile(r"\bsecrets\b(?!\s*\.\s*GITHUB_TOKEN\b)", re.I)


def conditions(node: object) -> list[str]:
    """Every if: value in a workflow document; an if: is an expression without ${{ }}."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "if" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(conditions(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(conditions(item))
    return found


def grants_write(permissions: object) -> bool:
    if permissions is None:
        return False
    if isinstance(permissions, str):
        return permissions != "read-all"
    if isinstance(permissions, dict):
        return any(value not in ("read", "none") for value in permissions.values())
    return True


def check_routing(name: str, doc: dict, text: str, on: dict) -> list[str]:
    problems: list[str] = []
    jobs = doc.get("jobs") or {}
    routed = []
    for job_id, job in jobs.items():
        labels = job.get("runs-on")
        if isinstance(labels, str) and " ".join(labels.split()) == ROUTED_RUNS_ON:
            routed.append((job_id, job))
            continue
        flat = json.dumps(labels)
        if any(marker in flat for marker in SELF_HOSTED_MARKERS):
            problems.append(
                f"R12 {name}: job {job_id} names a self-hosted label outside the routing expression"
            )
    if not routed:
        return problems
    # A workflow without top-level permissions gets the repository default,
    # which may grant writes; R2 also refuses it.
    if grants_write(doc.get("permissions", "write-all")):
        problems.append(f"R12 {name}: workflow with a routed job grants write permission")
    for job_id, job in jobs.items():
        if grants_write(job.get("permissions")):
            problems.append(f"R12 {name}: job {job_id} grants write permission")
    # The secrets context is read only inside expressions: ${{ }} anywhere, and
    # the bare expressions of if: keys. Any reference to it there other than
    # secrets.GITHUB_TOKEN is refused, whole-context access (toJSON(secrets))
    # and indexing included.
    for expression in [*EXPRESSION.findall(text), *conditions(doc)]:
        for access in SECRET_ACCESS.finditer(expression):
            problems.append(
                f"R12 {name}: workflow with a routed job reads secrets beyond GITHUB_TOKEN: "
                f"{' '.join(expression[access.start() :].split())[:60]}"
            )
    for job_id, job in jobs.items():
        if "secrets" in job:
            problems.append(f"R12 {name}: job {job_id} passes secrets to a called workflow")
    schedule = on.get("schedule")
    if not (
        isinstance(schedule, list)
        and len(schedule) == 1
        and isinstance(schedule[0], dict)
        and set(schedule[0]) == {"cron"}
        and isinstance(schedule[0]["cron"], str)
        and WEEKLY_CRON.fullmatch(schedule[0]["cron"])
    ):
        problems.append(f"R12 {name}: workflow with a routed job lacks exactly one weekly schedule")
    for job_id, job in routed:
        timeout = job.get("timeout-minutes")
        if not (
            isinstance(timeout, int)
            and not isinstance(timeout, bool)
            and timeout > 0
            and timeout + HOST_SETUP_MARGIN_MINUTES <= HOST_JOB_CAP_MINUTES
        ):
            problems.append(
                f"R12 {name}: routed job {job_id} timeout {timeout!r} plus "
                f"{HOST_SETUP_MARGIN_MINUTES} does not fit the host cap {HOST_JOB_CAP_MINUTES}"
            )
    return problems


def duplicate_push(on: dict) -> str | None:
    """Why this workflow's push trigger duplicates its pull request runs, or None."""
    if not any(event in on for event in ("pull_request", "pull_request_target")):
        return None
    if "push" not in on:
        return None
    push = on["push"]
    if not isinstance(push, dict):
        return "push has no branch filter"
    if "branches-ignore" in push:
        return "push uses branches-ignore"
    branches = push.get("branches")
    if branches is None:
        if push.get("tags") or push.get("tags-ignore"):
            return None
        return "push has no branch filter"
    if not isinstance(branches, list) or not branches:
        return "push branches is not a non-empty list"
    others = [b for b in branches if b not in PUSH_BRANCHES]
    if others:
        return f"push names branches beyond main and the integration branches: {others}"
    return None


def triggers(doc: dict) -> dict:
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {name: None for name in on}
    return on or {}


def check(root: Path) -> list[str]:
    workflows_dir = root / ".github" / "workflows"
    paths = sorted([*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")])
    docs = {p.name: yaml.safe_load(p.read_text()) or {} for p in paths}
    texts = {p.name: p.read_text() for p in paths}
    matrix = json.loads((root / "scripts" / "platform-matrix.json").read_text())
    release = json.loads((root / "scripts" / "release-artifacts.json").read_text())
    manifest_files = {m["workflow"] for m in matrix["members"].values()}
    member_files = manifest_files | INHERITED_PLATFORM_WORKFLOWS
    problems: list[str] = []
    for name in sorted(INHERITED_PLATFORM_WORKFLOWS - manifest_files):
        problems.append(f"R6 {name}: platform workflow is not a matrix member")
    for name in sorted(INHERITED_PLATFORM_WORKFLOWS - set(docs)):
        problems.append(f"R6 {name}: platform workflow is missing")

    for name, doc in docs.items():
        on = triggers(doc)
        jobs = doc.get("jobs") or {}
        for job_id, job in jobs.items():
            if "uses" not in job and "timeout-minutes" not in job:
                problems.append(f"R1 {name}: job {job_id} has no timeout-minutes")
            labels = job.get("runs-on")
            for label in labels if isinstance(labels, list) else [labels]:
                if isinstance(label, str) and re.search(r"-latest\b", label):
                    problems.append(f"R4 {name}: job {job_id} runs on moving label {label}")
        if "permissions" not in doc:
            problems.append(f"R2 {name}: no top-level permissions")
        concurrency = doc.get("concurrency")
        if any(event in on for event in AUTOMATIC) and concurrency is None:
            problems.append(f"R3 {name}: automatically triggered without concurrency")
        group = (
            concurrency.get("group", "")
            if isinstance(concurrency, dict)
            else str(concurrency or "")
        )
        if "workflow_call" in on and "github.workflow" in group:
            problems.append(f"R3 {name}: callable workflow groups on github.workflow")
        if name in RELEASE_WORKFLOWS and not (
            isinstance(concurrency, dict) and concurrency.get("cancel-in-progress") is False
        ):
            problems.append(f"R3 {name}: release workflow must not cancel a run in progress")
        problems.extend(check_routing(name, doc, texts[name], on))
        reason = duplicate_push(on)
        if reason:
            problems.append(f"R11 {name}: {reason}")
        for event, spec in on.items():
            if not isinstance(spec, dict):
                continue
            for key in ("branches", "branches-ignore"):
                dead = DEAD_BRANCHES & set(spec.get(key) or [])
                if dead:
                    problems.append(f"R5 {name}: {event}.{key} names {sorted(dead)}")
        if name in member_files:
            if "pull_request" in on or "pull_request_target" in on:
                problems.append(
                    f"R7 {name}: inherited platform workflow has a pull_request trigger"
                )
            push = on.get("push")
            if "push" in on and not (
                isinstance(push, dict) and push.get("tags") and not push.get("branches")
            ):
                problems.append(
                    f"R7 {name}: inherited platform workflow has a push trigger that is not tag-only"
                )
            if "workflow_call" not in on:
                problems.append(f"R6 {name}: matrix member does not declare workflow_call")
            for secret in re.findall(r"secrets\.([A-Za-z0-9_]+)", texts[name]):
                if secret != "GITHUB_TOKEN":
                    problems.append(f"R9 {name}: matrix member uses secret {secret}")

    for entry in release["build_workflows"]:
        on = triggers(docs.get(entry["workflow"], {}))
        push = on.get("push")
        tags = push.get("tags") if isinstance(push, dict) else None
        if not tags or "v*" not in tags:
            problems.append(f"R8 {entry['workflow']}: release build lost its v* tag trigger")

    problems.extend(check_badges(root, docs))
    problems.extend(check_matrix(docs.get(matrix["orchestrator"]), matrix))
    problems.extend(check_nightly(docs.get(matrix["nightly"]), matrix))
    return problems


BADGE = re.compile(r"actions/workflows/([^/\s)]+)/badge\.svg(?:\?([^)\s]*))?")


def runs_for(on: dict, event: str, branch: str | None) -> bool:
    """Whether a workflow with these triggers runs for this event on this branch."""
    if event not in on:
        return False
    spec = on[event]
    if branch is None or not isinstance(spec, dict):
        return True
    if spec.get("tags") and not spec.get("branches"):
        return False  # tag-only push
    branches = spec.get("branches")
    if branches is not None and branch not in branches:
        return False
    return branch not in (spec.get("branches-ignore") or [])


def check_badges(root: Path, docs: dict) -> list[str]:
    readme = root / "README.md"
    if not readme.is_file():
        return []
    problems = []
    for name, query in BADGE.findall(readme.read_text()):
        params = {k: v[0] for k, v in parse_qs(query).items()}
        doc = docs.get(name)
        if doc is None:
            problems.append(f"R10 {name}: README badge names a workflow that does not exist")
            continue
        event = params.get("event", "push")
        branch = params.get("branch")
        on = triggers(doc)
        if event == "push" and "event" not in params:
            ok = runs_for(on, "push", branch) or (
                branch is None and any(e in on for e in ("schedule", "workflow_dispatch"))
            )
        else:
            ok = runs_for(on, event, branch if event in ("push", "pull_request") else None)
        if not ok:
            problems.append(
                f"R10 {name}: README badge filters on event={event}"
                + (f", branch={branch}" if branch else "")
                + " but the workflow never runs there"
            )
    return problems


def check_matrix(doc: dict | None, matrix: dict) -> list[str]:
    name = matrix["orchestrator"]
    if doc is None:
        return [f"R6 {name}: the platform matrix workflow is missing"]
    problems: list[str] = []
    if "workflow_call" not in triggers(doc):
        problems.append(f"R6 {name}: the matrix must be callable by {matrix['nightly']}")
    jobs = doc.get("jobs") or {}
    members = matrix["members"]
    expected_jobs = set(members) | {"changes", GATE_JOB}
    for job_id in sorted(set(jobs) - expected_jobs):
        problems.append(f"R6 {name}: job {job_id} is not a matrix member")
    for member, spec in members.items():
        job = jobs.get(member)
        if job is None:
            problems.append(f"R6 {name}: member {member} has no job")
            continue
        if job.get("uses") != f"./.github/workflows/{spec['workflow']}":
            problems.append(f"R6 {name}: member {member} does not call {spec['workflow']}")
        if (job.get("with") or {}) != (spec.get("with") or {}):
            problems.append(
                f"R6 {name}: member {member} passes inputs other than {spec.get('with') or {}}"
            )
        if "secrets" in job:
            problems.append(f"R9 {name}: member {member} is passed secrets")
        needs = job.get("needs")
        if (needs if isinstance(needs, list) else [needs]) != ["changes"]:
            problems.append(f"R6 {name}: member {member} must need exactly changes")
        if job.get("if") != TIER_CONDITIONS[spec["tier"]]:
            problems.append(
                f"R6 {name}: member {member} does not run under its {spec['tier']} condition"
            )
    gate = jobs.get(GATE_JOB) or {}
    gate_needs = gate.get("needs") or []
    if set(gate_needs if isinstance(gate_needs, list) else [gate_needs]) != set(members) | {
        "changes"
    }:
        problems.append(f"R6 {name}: {GATE_JOB} does not need every member and changes")
    if gate.get("if") != "always()":
        problems.append(f"R6 {name}: {GATE_JOB} must run always()")
    return problems


def check_nightly(doc: dict | None, matrix: dict) -> list[str]:
    name = matrix["nightly"]
    if doc is None:
        return [f"R6 {name}: the nightly workflow is missing"]
    problems: list[str] = []
    on = triggers(doc)
    if set(on) != {"schedule", "workflow_dispatch"}:
        problems.append(f"R6 {name}: must run on the schedule and by hand only")
    jobs = doc.get("jobs") or {}
    if set(jobs) != {"matrix", REPORT_JOB}:
        problems.append(f"R6 {name}: must have exactly the matrix and {REPORT_JOB} jobs")
    call = jobs.get("matrix") or {}
    if call.get("uses") != f"./.github/workflows/{matrix['orchestrator']}" or "secrets" in call:
        problems.append(f"R6 {name}: matrix must call {matrix['orchestrator']} without secrets")
    report = jobs.get(REPORT_JOB) or {}
    if (
        report.get("needs") != "matrix"
        or report.get("if") != REPORT_CONDITION
        or report.get("permissions") != REPORT_PERMISSIONS
    ):
        problems.append(
            f"R6 {name}: {REPORT_JOB} must need matrix, run only on the schedule, "
            f"and hold exactly {REPORT_PERMISSIONS}"
        )
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "root", nargs="?", default=Path(__file__).resolve().parent.parent, type=Path
    )
    args = parser.parse_args(argv)
    problems = check(args.root)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f"workflow policy: {len(problems)} violation(s)", file=sys.stderr)
        return 1
    print("workflow policy: all rules hold")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
