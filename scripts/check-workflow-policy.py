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
R6  the platform matrix runs exactly the members scripts/platform-matrix.json
    lists, each under its tier's condition, and its gate needs all of them; the
    nightly workflow calls the matrix and reports on the schedule alone, and its
    report is the only job holding a write grant
R7  an inherited platform workflow runs only through the matrix, by hand, or on a
    release tag: no pull_request trigger and no push trigger without tags
R8  every release build workflow keeps its v* tag trigger
R9  a matrix member uses no secret except GITHUB_TOKEN, and the matrix passes none
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

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


def triggers(doc: dict) -> dict:
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {name: None for name in on}
    return on or {}


def check(root: Path) -> list[str]:
    workflows_dir = root / ".github" / "workflows"
    docs = {
        p.name: yaml.safe_load(p.read_text()) or {} for p in sorted(workflows_dir.glob("*.yml"))
    }
    texts = {p.name: p.read_text() for p in sorted(workflows_dir.glob("*.yml"))}
    matrix = json.loads((root / "scripts" / "platform-matrix.json").read_text())
    release = json.loads((root / "scripts" / "release-artifacts.json").read_text())
    member_files = {m["workflow"] for m in matrix["members"].values()}
    problems: list[str] = []

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

    problems.extend(check_matrix(docs.get(matrix["orchestrator"]), matrix))
    problems.extend(check_nightly(docs.get(matrix["nightly"]), matrix))
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
