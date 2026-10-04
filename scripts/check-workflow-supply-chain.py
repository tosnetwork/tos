#!/usr/bin/env python3
"""Fail closed on CI and deployment supply-chain regressions.

Workflows (.github/workflows/*.yml):
  UNPINNED_ACTION         a third-party action or reusable workflow is referenced
                          by a tag or branch instead of a full commit SHA
  BANNED_ACTION           an action that fetches another run's "latest
                          successful" artifacts
  MISSING_PERMISSIONS     neither the workflow nor every job declares permissions
  WRITE_ALL               permissions: write-all
  TOP_LEVEL_WRITE         a write permission granted to every job at once instead
                          of to the job that needs it
  UNTRUSTED_TRIGGER       pull_request_target or workflow_run, which run with
                          repository credentials on behalf of untrusted code
  PR_WRITE                a pull_request workflow holding a write permission
  UNAUTHENTICATED_INPUT   a privileged or release-input workflow runs a
                          downloaded installer or trusts a key fetched at build time
  RELEASE_TAG_UNCHECKED   a job creates, uploads to or publishes a release
                          (gh release create/upload/edit) without running
                          `release-artifacts.py check-tag` immediately before
                          that command, or without running it again after the
                          job's last such command
  RELEASE_EXISTING_NOT_REFUSED
                          gh release create is not preceded by a check-tag with
                          --release-state none, so an existing release could be
                          added to
  RELEASE_INCOMPLETE_PUBLISH
                          gh release edit (publication) is not preceded by a
                          check-tag with --release-state draft --assets, or the
                          final check-tag lacks --release-state published
  RELEASE_NOT_DRAFT       the publisher creates a release that is not a draft,
                          or publishes more than once
  RELEASE_NOT_SERIALIZED  a publisher without a workflow concurrency group keyed
                          on inputs.tag and cancel-in-progress: false
  RELEASE_WRITER_NOT_DESIGNATED
                          a workflow other than the designated publishers
                          (create-release.yml, create-tol-release.yml) writes a
                          release: gh release create/upload/edit/delete/
                          delete-asset, a release-writing action, or a write
                          method on a releases API path
  RELEASE_CLOBBER         --clobber anywhere: an uploaded release asset is never
                          replaced

Deployment manifests (docker/*.yaml) and their README:
  IMAGE_NOT_DIGEST        an image not referenced by @sha256 digest
  MUTABLE_IMAGE_TAG       an image reference that follows :latest
  UNVERIFIED_SNAPSHOT     DUMP_URL set without the opt-in, digest and network
                          binding that make import-snapshot.sh accept it

Usage: check-workflow-supply-chain.py [ROOT]   (default: the repository)
       check-workflow-supply-chain.py --self-test
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

PINNED_USES_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[^@\s]+)?@[0-9a-f]{40}$")
DOCKER_USES_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
USES_RE = re.compile(r"""^\s*(?:-\s+)?uses:\s*['"]?([^'"\s#]+)""")
TOP_KEY_RE = re.compile(r"""^['"]?([A-Za-z_][\w-]*)['"]?:\s*(.*?)\s*(?:#.*)?$""")
KEY_RE = re.compile(r"""^(\s*)['"]?([A-Za-z_][\w-]*)['"]?:\s*(.*?)\s*(?:#.*)?$""")
BANNED_ACTIONS = ("dawidd6/action-download-artifact",)
UNTRUSTED_TRIGGERS = ("pull_request_target", "workflow_run")
UNAUTHENTICATED_INPUT_RES = (
    (re.compile(r"\bllvm\.sh\b"), "runs apt.llvm.org's downloaded installer script"),
    (re.compile(r"\bapt-key\s+add\b"), "trusts a signing key fetched at build time (apt-key add)"),
    (
        re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"),
        "pipes a download into a shell",
    ),
)
# Commands that create, fill or publish a release. Deleting a release or an
# asset is the remedy after a failed check, not a publication.
RELEASE_MUTATION_RE = re.compile(r"\bgh\s+release\s+(create|upload|edit)\b")
TAG_CHECK_RE = re.compile(r"\brelease-artifacts\.py\s+check-tag\b")
# The only workflows that may write a release, and the only tag namespaces
# they publish (v* and tol-v*); create-release.yml exclusively owns v*.
DESIGNATED_PUBLISHERS = ("create-release.yml", "create-tol-release.yml")
RELEASE_WRITE_RE = re.compile(r"\bgh\s+release\s+(?:create|upload|edit|delete|delete-asset)\b")
RELEASE_ACTIONS = (
    "softprops/action-gh-release",
    "actions/create-release",
    "actions/upload-release-asset",
    "ncipollo/release-action",
    "svenstaro/upload-release-action",
)
GH_API_RE = re.compile(r"\bgh\s+api\b")
API_WRITE_METHOD_RE = re.compile(r"(?:-X|--method)[\s=]*['\"]?(?:POST|PATCH|PUT|DELETE)\b", re.I)
CLOBBER_RE = re.compile(r"--clobber\b")
IMAGE_RE = re.compile(r"^\s*(?:-\s+)?image:\s*['\"]?([^'\"\s#]+)")
DIGEST_IMAGE_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
SNAPSHOT_KEYS = ("SNAPSHOT_IMPORT", "DUMP_SHA256", "DUMP_ZEROSTATE_ROOT_HASH")


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.code} {self.path}:{self.line} {self.message}"


def meaningful(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#")


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def block_end(lines: list[str], start: int, indent: int) -> int:
    """Index one past the block of lines indented deeper than `indent` after `start`."""
    end = start + 1
    while end < len(lines) and (not meaningful(lines[end]) or indent_of(lines[end]) > indent):
        end += 1
    return end


def child_keys(lines: list[str], start: int, end: int) -> list[tuple[int, str, str]]:
    """Keys at the first indentation level inside lines[start:end]."""
    child_indent = None
    keys = []
    for index in range(start, end):
        line = lines[index]
        if not meaningful(line):
            continue
        if child_indent is None:
            child_indent = indent_of(line)
        if indent_of(line) != child_indent:
            continue
        match = KEY_RE.match(line)
        if match:
            keys.append((index, match.group(2), match.group(3)))
    return keys


def permission_grants(lines: list[str], index: int, inline: str) -> list[str]:
    """Return 'scope: value' strings (or the inline shorthand) for a permissions key."""
    if inline:
        return [inline.strip("'\"")]
    end = block_end(lines, index, indent_of(lines[index]))
    return [f"{key}: {value}" for _, key, value in child_keys(lines, index + 1, end)]


def has_write(grants: list[str]) -> bool:
    return any(grant == "write-all" or grant.endswith(": write") for grant in grants)


def logical_lines(lines: list[str], start: int, end: int) -> list[tuple[int, str]]:
    """Non-comment lines in [start, end), with shell continuation lines joined
    onto the line that starts the command."""
    joined: list[tuple[int, str]] = []
    index = start
    while index < end:
        line = lines[index]
        if line.lstrip().startswith("#"):
            index += 1
            continue
        first, text = index, line
        while text.rstrip().endswith("\\") and index + 1 < end:
            index += 1
            text = text.rstrip()[:-1] + " " + lines[index].strip()
        joined.append((first, text))
        index += 1
    return joined


def release_tag_findings(
    lines: list[str], job: str, start: int, end: int
) -> list[tuple[str, int, str]]:
    """Each release mutation needs a tag check since the previous one, and the
    last mutation needs a check after it, so the tag cannot move unnoticed
    between collection and any publication step. The check before creation
    must refuse an existing release; the check before publication must find
    the complete draft; the final check must find it published."""
    problems: list[tuple[str, int, str]] = []
    last_check: str | None = None
    last_mutation: int | None = None
    for index, line in logical_lines(lines, start, end):
        mutation = RELEASE_MUTATION_RE.search(line)
        if mutation:
            command = mutation.group(1)
            if last_check is None:
                problems.append(
                    (
                        "RELEASE_TAG_UNCHECKED",
                        index,
                        f"job {job} runs {line.strip()!r} without a check-tag immediately before it",
                    )
                )
            elif command == "create" and "--release-state none" not in last_check:
                problems.append(
                    (
                        "RELEASE_EXISTING_NOT_REFUSED",
                        index,
                        f"job {job} creates a release without first refusing an existing one "
                        "(check-tag --release-state none)",
                    )
                )
            elif command == "edit" and not (
                "--release-state draft" in last_check and "--assets" in last_check
            ):
                problems.append(
                    (
                        "RELEASE_INCOMPLETE_PUBLISH",
                        index,
                        f"job {job} publishes without checking the complete draft "
                        "(check-tag --release-state draft --assets)",
                    )
                )
            last_check = None
            last_mutation = index
        if TAG_CHECK_RE.search(line):
            last_check = line
    if last_mutation is not None:
        if last_check is None:
            problems.append(
                (
                    "RELEASE_TAG_UNCHECKED",
                    last_mutation,
                    f"job {job} does not run check-tag after its last release command",
                )
            )
        elif "--release-state published" not in last_check:
            problems.append(
                (
                    "RELEASE_INCOMPLETE_PUBLISH",
                    last_mutation,
                    f"job {job}'s final check-tag does not confirm the published release "
                    "(--release-state published)",
                )
            )
    return problems


def release_writer_findings(
    path: Path, lines: list[str], top: dict[str, tuple[int, str]]
) -> list[tuple[str, int, str]]:
    problems: list[tuple[str, int, str]] = []
    designated = path.name in DESIGNATED_PUBLISHERS
    logical = logical_lines(lines, 0, len(lines))
    for index, line in logical:
        if CLOBBER_RE.search(line):
            problems.append(("RELEASE_CLOBBER", index, "--clobber replaces an uploaded asset"))
        if designated:
            continue
        uses = USES_RE.match(line)
        writes = (
            RELEASE_WRITE_RE.search(line)
            or (uses and any(uses.group(1).startswith(action + "@") for action in RELEASE_ACTIONS))
            or (GH_API_RE.search(line) and "releases" in line and API_WRITE_METHOD_RE.search(line))
        )
        if writes:
            problems.append(
                (
                    "RELEASE_WRITER_NOT_DESIGNATED",
                    index,
                    f"only {' and '.join(DESIGNATED_PUBLISHERS)} may write a release: {line.strip()!r}",
                )
            )
    if not designated:
        return problems

    creates = [(i, line) for i, line in logical if re.search(r"\bgh\s+release\s+create\b", line)]
    publishes = [i for i, line in logical if re.search(r"\bgh\s+release\s+edit\b", line)]
    for index, line in creates:
        if "--draft" not in line:
            problems.append(("RELEASE_NOT_DRAFT", index, "the release is not created as a draft"))
    if len(creates) > 1 or len(publishes) > 1:
        problems.append(
            (
                "RELEASE_NOT_DRAFT",
                (publishes or [index for index, _ in creates])[-1],
                f"{len(creates)} create and {len(publishes)} publish commands; a release is "
                "created once and published once",
            )
        )

    serialized = False
    if "concurrency" in top:
        index, inline = top["concurrency"]
        settings = {
            key: value.strip("'\"")
            for _, key, value in child_keys(lines, index + 1, block_end(lines, index, 0))
        }
        serialized = "inputs.tag" in settings.get("group", "") and (
            settings.get("cancel-in-progress") == "false"
        )
    if not serialized:
        problems.append(
            (
                "RELEASE_NOT_SERIALIZED",
                top.get("concurrency", (0, ""))[0],
                "a publisher needs concurrency: group keyed on inputs.tag, cancel-in-progress: false",
            )
        )
    return problems


def check_workflow(path: Path, relative: str, release_inputs: set[str]) -> list[Finding]:
    lines = path.read_text().splitlines()
    findings: list[Finding] = []

    def add(code: str, index: int, message: str) -> None:
        findings.append(Finding(code, relative, index + 1, message))

    for index, line in enumerate(lines):
        match = USES_RE.match(line)
        if not match:
            continue
        ref = match.group(1)
        if ref.startswith("./"):
            continue
        if any(ref.startswith(banned + "@") for banned in BANNED_ACTIONS):
            add(
                "BANNED_ACTION",
                index,
                f"{ref} selects another run's artifacts without binding them to a commit",
            )
        if ref.startswith("docker://"):
            if not DOCKER_USES_RE.match(ref):
                add("UNPINNED_ACTION", index, f"{ref} is not pinned to an image digest")
        elif not PINNED_USES_RE.match(ref):
            add("UNPINNED_ACTION", index, f"{ref} is not pinned to a full commit SHA")

    top: dict[str, tuple[int, str]] = {}
    for index, line in enumerate(lines):
        if line and not line[0].isspace() and meaningful(line):
            match = TOP_KEY_RE.match(line)
            if match:
                top[match.group(1)] = (index, match.group(2))

    triggers: set[str] = set()
    if "on" in top:
        index, inline = top["on"]
        if inline:
            triggers = set(re.findall(r"[a-z_]+", inline))
        else:
            end = block_end(lines, index, 0)
            triggers = {key for _, key, _ in child_keys(lines, index + 1, end)}
    for trigger in UNTRUSTED_TRIGGERS:
        if trigger in triggers:
            add(
                "UNTRUSTED_TRIGGER",
                top["on"][0],
                f"{trigger} runs with repository credentials for untrusted code",
            )

    all_grants: list[tuple[int, list[str]]] = []
    top_permissions = top.get("permissions")
    if top_permissions is not None:
        grants = permission_grants(lines, *top_permissions)
        all_grants.append((top_permissions[0], grants))
        if has_write(grants):
            add(
                "TOP_LEVEL_WRITE",
                top_permissions[0],
                f"workflow-wide permissions {grants} include a write grant",
            )

    job_without_permissions: list[str] = []
    if "jobs" in top:
        jobs_index = top["jobs"][0]
        jobs_end = block_end(lines, jobs_index, 0)
        for job_index, job, _ in child_keys(lines, jobs_index + 1, jobs_end):
            job_end = block_end(lines, job_index, indent_of(lines[job_index]))
            for code, index, message in release_tag_findings(lines, job, job_index + 1, job_end):
                add(code, index, message)
            permissions = [
                entry
                for entry in child_keys(lines, job_index + 1, job_end)
                if entry[1] == "permissions"
            ]
            if permissions:
                index, _, inline = permissions[0]
                all_grants.append((index, permission_grants(lines, index, inline)))
            else:
                job_without_permissions.append(job)
    if top_permissions is None and job_without_permissions:
        add(
            "MISSING_PERMISSIONS",
            0,
            f"no workflow permissions and jobs {job_without_permissions} declare none; the token would get "
            "the repository default",
        )

    for code, index, message in release_writer_findings(path, lines, top):
        add(code, index, message)

    privileged = False
    for index, grants in all_grants:
        if "write-all" in grants:
            add("WRITE_ALL", index, "permissions: write-all")
        if has_write(grants):
            privileged = True
            if "pull_request" in triggers:
                add("PR_WRITE", index, f"pull_request workflow holds {grants}")

    if privileged or path.name in release_inputs:
        role = "privileged" if privileged else "release-input"
        for index, line in enumerate(lines):
            if line.lstrip().startswith("#"):
                continue
            for pattern, why in UNAUTHENTICATED_INPUT_RES:
                if pattern.search(line):
                    add("UNAUTHENTICATED_INPUT", index, f"{role} workflow {why}")
    return findings


def check_manifest(path: Path, relative: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = path.read_text().splitlines()
    active_env: dict[str, int] = {}
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        match = IMAGE_RE.match(line)
        if match:
            image = match.group(1)
            if image.endswith(":latest") or ":latest@" in image:
                findings.append(
                    Finding("MUTABLE_IMAGE_TAG", relative, index + 1, f"{image} follows :latest")
                )
            if not DIGEST_IMAGE_RE.search(image):
                findings.append(
                    Finding(
                        "IMAGE_NOT_DIGEST", relative, index + 1, f"{image} has no @sha256 digest"
                    )
                )
        env = re.match(r"^\s*-\s+name:\s*['\"]?([A-Z_][A-Z0-9_]*)['\"]?\s*$", line)
        if env:
            active_env[env.group(1)] = index
    if "DUMP_URL" in active_env:
        missing = [key for key in SNAPSHOT_KEYS if key not in active_env]
        if missing:
            findings.append(
                Finding(
                    "UNVERIFIED_SNAPSHOT",
                    relative,
                    active_env["DUMP_URL"] + 1,
                    f"DUMP_URL without {missing}; the container will refuse to start",
                )
            )
    return findings


README_IMAGE_RE = re.compile(r"ghcr\.io/[\w.-]+/[\w.-]+(?P<suffix>[@:][^\s`'\"]*)?")


def check_readme(path: Path, relative: str) -> list[Finding]:
    """Documented images are pulled by digest; a tag, or no tag at all, follows whatever was pushed last."""
    findings = []
    for index, line in enumerate(path.read_text().splitlines()):
        for match in README_IMAGE_RE.finditer(line):
            suffix = match.group("suffix") or ""
            if not suffix.startswith("@sha256:"):
                findings.append(
                    Finding(
                        "MUTABLE_IMAGE_TAG",
                        relative,
                        index + 1,
                        f"documents {match.group(0)} without a digest",
                    )
                )
    return findings


def release_input_workflows(root: Path) -> set[str]:
    config = root / "scripts" / "release-artifacts.json"
    if not config.is_file():
        return set()
    return {entry["workflow"] for entry in json.loads(config.read_text())["build_workflows"]}


def check_tree(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflows = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    if not workflows:
        return [Finding("NO_WORKFLOWS", ".github/workflows", 0, "no workflow files found")]
    release_inputs = release_input_workflows(root)
    for name in sorted(release_inputs):
        if not (root / ".github" / "workflows" / name).is_file():
            findings.append(
                Finding(
                    "MISSING_RELEASE_INPUT",
                    "scripts/release-artifacts.json",
                    0,
                    f"{name} is missing",
                )
            )
    for workflow in workflows:
        findings += check_workflow(workflow, str(workflow.relative_to(root)), release_inputs)
    for manifest in sorted((root / "docker").glob("*.yaml")):
        findings += check_manifest(manifest, str(manifest.relative_to(root)))
    readme = root / "docker" / "README.md"
    if readme.is_file():
        findings += check_readme(readme, str(readme.relative_to(root)))
    return findings


SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
GOOD_WORKFLOW = f"""name: good
on:
  push:
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@{SHA} # v7
      - uses: ./.github/actions/local
      - run: sudo scripts/install-llvm-toolchain.sh 21
  publish:
    if: github.event_name == 'push'
    permissions:
      contents: write
    runs-on: ubuntu-24.04
    steps:
      - uses: docker://alpine@sha256:{"a" * 64}
"""
GOOD_RELEASE_WORKFLOW = """name: release
on:
  workflow_dispatch:
    inputs:
      tag:
        required: true
permissions: {}
concurrency:
  group: publish-release-${{ inputs.tag }}
  cancel-in-progress: false
jobs:
  publish:
    runs-on: ubuntu-24.04
    permissions:
      contents: write
    steps:
      - run: |
          python3 guard/scripts/release-artifacts.py check-tag --set full --tag "$T" \\
            --release-state none # before create
          gh release create "$T" --verify-tag --draft
          python3 guard/scripts/release-artifacts.py check-tag --set full --tag "$T" \\
            --release-state draft # before upload
          gh release upload "$T" stage/*
          python3 guard/scripts/release-artifacts.py check-tag --set full --tag "$T" \\
            --release-state draft --assets stage # before publish
          gh release edit "$T" --draft=false
          if ! python3 guard/scripts/release-artifacts.py check-tag --set full --tag "$T" \\
            --release-state published --assets stage; then
            gh release delete "$T" --yes
          fi
"""
GOOD_MANIFEST = f"""spec:
  containers:
    - name: node
      # image-provenance: release v1
      image: ghcr.io/example/node@sha256:{"b" * 64}
      env:
        - name: PUBLIC_IP
          value: "1.2.3.4"
        # - name: DUMP_URL
        #   value: "https://example.invalid/x.tar.lz"
"""

# Each bad sample flips one property of the good ones; the checker must report
# exactly the expected code for it.
BAD_WORKFLOWS = {
    "UNPINNED_ACTION": GOOD_WORKFLOW.replace(f"actions/checkout@{SHA}", "actions/checkout@v4"),
    "UNPINNED_ACTION ": GOOD_WORKFLOW.replace(
        f"actions/checkout@{SHA}", f"actions/checkout@{SHA[:12]}"
    ),
    "UNPINNED_ACTION  ": GOOD_WORKFLOW.replace(
        f"docker://alpine@sha256:{'a' * 64}", "docker://alpine:latest"
    ),
    "BANNED_ACTION": GOOD_WORKFLOW.replace(
        "      - uses: ./.github/actions/local",
        f"      - uses: dawidd6/action-download-artifact@{SHA}",
    ),
    "MISSING_PERMISSIONS": GOOD_WORKFLOW.replace("permissions:\n  contents: read\njobs:", "jobs:"),
    "WRITE_ALL": GOOD_WORKFLOW.replace(
        "    permissions:\n      contents: write", "    permissions: write-all"
    ),
    "TOP_LEVEL_WRITE": GOOD_WORKFLOW.replace(
        "permissions:\n  contents: read\njobs:", "permissions:\n  contents: write\njobs:"
    ),
    "UNTRUSTED_TRIGGER": GOOD_WORKFLOW.replace("  pull_request:\n", "  pull_request_target:\n"),
    "UNTRUSTED_TRIGGER ": GOOD_WORKFLOW.replace(
        "on:\n  push:\n  pull_request:\n", "on: [push, workflow_run]\n"
    ),
    "PR_WRITE": GOOD_WORKFLOW,  # paired with the PR trigger below: the publish job writes
    "UNAUTHENTICATED_INPUT": GOOD_WORKFLOW.replace(
        "sudo scripts/install-llvm-toolchain.sh 21",
        "wget -q https://apt.llvm.org/llvm.sh && sudo bash llvm.sh 21",
    ),
    "UNAUTHENTICATED_INPUT ": GOOD_WORKFLOW.replace(
        "sudo scripts/install-llvm-toolchain.sh 21",
        "curl -fsSL https://example.invalid/i.sh | sudo bash",
    ),
    "UNAUTHENTICATED_INPUT  ": GOOD_WORKFLOW.replace(
        "sudo scripts/install-llvm-toolchain.sh 21",
        "wget -qO- https://example.invalid/key | sudo apt-key add -",
    ),
    "RELEASE_WRITER_NOT_DESIGNATED": GOOD_WORKFLOW.replace(
        f"      - uses: docker://alpine@sha256:{'a' * 64}\n",
        f"      - uses: docker://alpine@sha256:{'a' * 64}\n"
        # Even with every tag check in place, this workflow may not write.
        "      - run: |\n"
        "          python3 g/release-artifacts.py check-tag --release-state draft\n"
        '          gh release upload "$T" tool.tar.gz\n'
        "          python3 g/release-artifacts.py check-tag --release-state published\n",
    ),
    "RELEASE_WRITER_NOT_DESIGNATED ": GOOD_WORKFLOW.replace(
        "      - uses: ./.github/actions/local", f"      - uses: softprops/action-gh-release@{SHA}"
    ),
    "RELEASE_WRITER_NOT_DESIGNATED  ": GOOD_WORKFLOW.replace(
        f"      - uses: docker://alpine@sha256:{'a' * 64}\n",
        f"      - uses: docker://alpine@sha256:{'a' * 64}\n"
        '      - run: gh api -X POST "repos/$R/releases/1/assets?name=x"\n',
    ),
    "RELEASE_WRITER_NOT_DESIGNATED   ": GOOD_WORKFLOW.replace(
        f"      - uses: docker://alpine@sha256:{'a' * 64}\n",
        f"      - uses: docker://alpine@sha256:{'a' * 64}\n"
        '      - run: gh release delete-asset "$T" tool.tar.gz --yes\n',
    ),
}
# Each flips one property of GOOD_RELEASE_WORKFLOW, written as the designated
# publisher create-release.yml.
BAD_RELEASE_WORKFLOWS = {
    "RELEASE_TAG_UNCHECKED": GOOD_RELEASE_WORKFLOW.replace(
        'check-tag --set full --tag "$T" \\\n            --release-state draft # before upload',
        "--version # before upload",
    ),
    "RELEASE_TAG_UNCHECKED ": GOOD_RELEASE_WORKFLOW.replace(
        '          if ! python3 guard/scripts/release-artifacts.py check-tag --set full --tag "$T" \\\n'
        "            --release-state published --assets stage; then\n"
        '            gh release delete "$T" --yes\n'
        "          fi\n",
        "",
    ),
    "RELEASE_EXISTING_NOT_REFUSED": GOOD_RELEASE_WORKFLOW.replace(
        "--release-state none # before create", "--release-state draft # before create"
    ),
    "RELEASE_INCOMPLETE_PUBLISH": GOOD_RELEASE_WORKFLOW.replace(
        "--release-state draft --assets stage # before publish",
        "--release-state draft # before publish",
    ),
    "RELEASE_INCOMPLETE_PUBLISH ": GOOD_RELEASE_WORKFLOW.replace(
        "--release-state published --assets stage; then", "--release-state draft; then"
    ),
    "RELEASE_NOT_DRAFT": GOOD_RELEASE_WORKFLOW.replace(
        'gh release create "$T" --verify-tag --draft', 'gh release create "$T" --verify-tag'
    ),
    "RELEASE_CLOBBER": GOOD_RELEASE_WORKFLOW.replace(
        'gh release upload "$T" stage/*', 'gh release upload "$T" --clobber stage/*'
    ),
    "RELEASE_NOT_SERIALIZED": GOOD_RELEASE_WORKFLOW.replace(
        "  cancel-in-progress: false\n", "  cancel-in-progress: true\n"
    ),
    "RELEASE_NOT_SERIALIZED ": GOOD_RELEASE_WORKFLOW.replace(
        "  group: publish-release-${{ inputs.tag }}\n", "  group: publish-release\n"
    ),
    "RELEASE_NOT_SERIALIZED  ": GOOD_RELEASE_WORKFLOW.replace(
        "concurrency:\n  group: publish-release-${{ inputs.tag }}\n  cancel-in-progress: false\n",
        "",
    ),
}
BAD_MANIFESTS = {
    "MUTABLE_IMAGE_TAG": GOOD_MANIFEST.replace(f"@sha256:{'b' * 64}", ":latest"),
    "IMAGE_NOT_DIGEST": GOOD_MANIFEST.replace(f"@sha256:{'b' * 64}", ":v2026.10"),
    "UNVERIFIED_SNAPSHOT": GOOD_MANIFEST.replace(
        "        # - name: DUMP_URL\n        #   value", "        - name: DUMP_URL\n          value"
    ),
}
GOOD_README = f"docker pull ghcr.io/example/node@sha256:{'c' * 64}\n"
BAD_READMES = {
    "latest tag": "docker pull ghcr.io/example/node:latest\n",
    "release tag": "docker pull ghcr.io/example/node:v2026.10\n",
    "no tag": "docker run -it ghcr.io/example/node\n",
}


def self_test() -> int:
    failures: list[str] = []

    def run_case(
        label: str,
        workflow: str,
        manifest: str,
        expected: set[str],
        readme: str = GOOD_README,
        release_workflow: str = GOOD_RELEASE_WORKFLOW,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="supply-chain-self-test-") as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / "docker").mkdir()
            (root / ".github" / "workflows" / "sample.yml").write_text(workflow)
            (root / ".github" / "workflows" / "create-release.yml").write_text(release_workflow)
            (root / "docker" / "node.yaml").write_text(manifest)
            (root / "docker" / "README.md").write_text(readme)
            codes = {finding.code for finding in check_tree(root)}
        if codes != expected:
            failures.append(f"{label}: expected {sorted(expected)}, got {sorted(codes)}")

    good_without_pr_write = GOOD_WORKFLOW.replace("  pull_request:\n", "")
    run_case("good samples", good_without_pr_write, GOOD_MANIFEST, set())
    for label, workflow in BAD_WORKFLOWS.items():
        code = label.strip()
        sample = (
            workflow
            if code in ("PR_WRITE", "UNTRUSTED_TRIGGER")
            else workflow.replace("  pull_request:\n", "")
        )
        run_case(f"bad workflow {label!r}", sample, GOOD_MANIFEST, {code})
    for label, release_workflow in BAD_RELEASE_WORKFLOWS.items():
        assert release_workflow != GOOD_RELEASE_WORKFLOW, label
        run_case(
            f"bad release workflow {label!r}",
            good_without_pr_write,
            GOOD_MANIFEST,
            {label.strip()},
            release_workflow=release_workflow,
        )
    # The publisher's own sample, written under any other name, is not designated.
    run_case(
        "release workflow under another name",
        GOOD_RELEASE_WORKFLOW,
        GOOD_MANIFEST,
        {"RELEASE_WRITER_NOT_DESIGNATED"},
    )
    for label, manifest in BAD_MANIFESTS.items():
        expected = {label, "IMAGE_NOT_DIGEST"} if label == "MUTABLE_IMAGE_TAG" else {label}
        run_case(f"bad manifest {label}", good_without_pr_write, manifest, expected)
    for label, readme in BAD_READMES.items():
        run_case(
            f"bad README {label}",
            good_without_pr_write,
            GOOD_MANIFEST,
            {"MUTABLE_IMAGE_TAG"},
            readme,
        )

    if failures:
        for failure in failures:
            print(f"SUPPLY_CHAIN_SELF_TEST_FAILURE: {failure}", file=sys.stderr)
        return 1
    total = (
        2 + len(BAD_WORKFLOWS) + len(BAD_RELEASE_WORKFLOWS) + len(BAD_MANIFESTS) + len(BAD_READMES)
    )
    print(f"supply-chain checker self-test: {total} samples behaved")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(argv[1]) if len(argv) == 2 else Path(__file__).resolve().parent.parent
    findings = check_tree(root)
    for finding in findings:
        print(f"SUPPLY_CHAIN_FAILURE: {finding}", file=sys.stderr)
    if findings:
        return 1
    print("workflow and deployment supply-chain check: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
