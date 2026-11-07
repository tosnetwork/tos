#!/usr/bin/env python3
"""Check the frozen Service Actor release against its manifest and a fresh build.

scripts/test-tos-service-actor-v1.sh builds the contract twice and then runs

    tos_service_actor_release.py <first.boc> <build-output.txt> <func-binary>

which requires: the rebuilt BOC equals the committed base64 artifact and the
SDK constant SERVICE_ACTOR_CODE_B64 byte for byte; every manifest field equals
what the build reported (code hash, BOC SHA-256 and size, compiler arguments)
or what the compiler reports about itself (semantic version); and, when the
manifest's tos_commit is in local history, that the contract source and every
file it includes are unchanged since that commit.

compiler.source_commit is recorded provenance: only its format is checked, as
nothing in a built executable proves which commit produced it.

Standard library only.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "crypto/smartcont/tos-service-actor-v1.release.json"
SDK = REPO / "tosctl/src/node-control/contracts/src/service_actor.rs"

EXPECTED_FIELDS = {
    "schema": "tos.contract.release.v1",
    "protocol": "tos_service_v1",
    "contract": "tos-service-actor-v1",
    "source": "crypto/smartcont/service-actor-code.fc",
    "stdlib": "crypto/smartcont/stdlib.fc",
    "build_script": "scripts/build-tos-service-actor-v1.sh",
    "artifact_base64": "crypto/smartcont/tos-service-actor-v1.boc.base64",
}
COMMIT = re.compile(r"^[0-9a-f]{40}$")
INCLUDE = re.compile(r'^\s*#include\s+"([^"]+)"\s*;', re.MULTILINE)


class ReleaseError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def decode_base64_file(path: Path) -> bytes:
    return base64.b64decode(b"".join(path.read_bytes().split()), validate=True)


def sdk_code(path: Path = SDK) -> bytes:
    match = re.search(
        r'pub const SERVICE_ACTOR_CODE_B64: &str = "([A-Za-z0-9+/=]+)";', path.read_text()
    )
    require(match is not None, "SERVICE_ACTOR_CODE_B64 was not found in the SDK source")
    return base64.b64decode(match.group(1), validate=True)


def parse_build_output(text: str) -> dict[str, str]:
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            require(key not in fields, f"build output repeats {key}")
            fields[key] = value
    for key in ("code_hash", "boc_sha256", "boc_bytes", "compiler_arguments"):
        require(key in fields, f"build output has no {key}")
    return fields


def compiler_semantic_version(func: Path) -> str:
    output = subprocess.run([str(func), "-V"], check=True, capture_output=True, text=True).stdout
    match = re.search(r"FunC semantic version: (v[0-9]+\.[0-9]+\.[0-9]+)", output)
    require(match is not None, f"{func} -V did not report a semantic version")
    return match.group(1)


def include_closure(source: Path, root: Path) -> list[str]:
    """The source and every file it transitively includes, relative to root."""
    seen: list[Path] = []
    pending = [source]
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        require(path.is_file(), f"included file is missing: {path}")
        seen.append(path)
        for name in INCLUDE.findall(path.read_text()):
            pending.append((path.parent / name).resolve())
    return sorted(str(path.relative_to(root)) for path in seen)


def check_provenance(commit: str, paths: list[str], root: Path) -> str:
    """'checked' when the files equal those at commit; 'unavailable' when the
    commit is not in local history. Anything else is a refusal."""
    require(COMMIT.match(commit) is not None, "tos_commit must be 40 lower-case hex digits")
    try:
        kind = subprocess.run(
            ["git", "cat-file", "-t", commit], cwd=root, capture_output=True, text=True
        )
    except FileNotFoundError as error:
        raise ReleaseError("git is not available to check tos_commit") from error
    if kind.returncode != 0:
        if "Not a valid object name" in kind.stderr or "could not get object info" in kind.stderr:
            return "unavailable"
        raise ReleaseError(f"git cat-file failed for tos_commit: {kind.stderr.strip()}")
    require(
        kind.stdout.strip() == "commit", f"tos_commit names a {kind.stdout.strip()}, not a commit"
    )
    diff = subprocess.run(
        ["git", "diff", "--quiet", commit, "--", *paths], cwd=root, capture_output=True, text=True
    )
    if diff.returncode == 1:
        raise ReleaseError(f"contract source differs from tos_commit {commit}")
    if diff.returncode != 0:
        raise ReleaseError(f"git diff failed for tos_commit: {diff.stderr.strip()}")
    return "checked"


def check_release(built: bytes, build_output: str, func: Path, root: Path = REPO) -> list[str]:
    manifest = json.loads((root / MANIFEST.relative_to(REPO)).read_text())
    for key, value in EXPECTED_FIELDS.items():
        require(manifest.get(key) == value, f"manifest {key} must be {value!r}")
    reported = parse_build_output(build_output)
    require(
        manifest.get("code_hash") == reported["code_hash"],
        "manifest code_hash differs from the build",
    )
    require(
        manifest.get("boc_sha256") == reported["boc_sha256"],
        "manifest boc_sha256 differs from the build",
    )
    require(
        type(manifest.get("boc_bytes")) is int
        and str(manifest["boc_bytes"]) == reported["boc_bytes"],
        "manifest boc_bytes differs from the build",
    )
    require(manifest["boc_bytes"] == len(built), "manifest boc_bytes differs from the built BOC")

    compiler = manifest.get("compiler")
    require(isinstance(compiler, dict), "manifest compiler must be an object")
    require(compiler.get("name") == "FunC", "manifest compiler.name must be FunC")
    require(
        compiler.get("semantic_version") == compiler_semantic_version(func),
        "manifest compiler.semantic_version differs from the compiler",
    )
    require(
        isinstance(compiler.get("source_commit"), str) and COMMIT.match(compiler["source_commit"]),
        "manifest compiler.source_commit must be 40 lower-case hex digits",
    )
    require(
        compiler.get("arguments") == reported["compiler_arguments"].split(" "),
        "manifest compiler.arguments differs from the build script",
    )

    frozen = decode_base64_file(root / manifest["artifact_base64"])
    require(frozen == built, "frozen artifact differs from the rebuild")
    require(
        sdk_code(root / SDK.relative_to(REPO)) == built,
        "SDK SERVICE_ACTOR_CODE_B64 differs from the rebuild",
    )

    paths = include_closure((root / manifest["source"]).resolve(), root.resolve())
    paths = sorted(set(paths) | {manifest["stdlib"]})
    notes = []
    commit = manifest.get("tos_commit")
    require(isinstance(commit, str), "manifest tos_commit must be a string")
    if check_provenance(commit, paths, root) == "unavailable":
        notes.append(
            f"NOTE: tos_commit {commit} not in local history; provenance not checked, artifact bound by rebuild"
        )
    return notes


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    built = Path(sys.argv[1]).read_bytes()
    build_output = Path(sys.argv[2]).read_text()
    try:
        for note in check_release(built, build_output, Path(sys.argv[3])):
            print(note)
    except ReleaseError as error:
        print(f"Service Actor release check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
