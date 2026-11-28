#!/usr/bin/env python3
"""Check the frozen Service Actor release against its manifest and a fresh build.

scripts/test-tos-service-actor-v1.sh builds the contract twice and then runs

    tos_service_actor_release.py [--allow-missing-tos-commit] <first.boc> <build-output.txt> <func-binary> [profile]

once per profile (each rail's release build, and its test-only build), which
requires: the rebuilt BOC equals the profile's committed base64 artifact and
its SDK constant (named by the profile, in the rail's SDK module) byte for
byte; every manifest field equals
what the build reported (code hash, BOC SHA-256 and size, compiler arguments)
or what the compiler reports about itself (semantic version); and that the
contract source and every file it includes are unchanged since the manifest's
tos_commit.

The tos_commit must be in local history. A checkout without it (a shallow
clone) fails, because a provenance check that cannot run must not pass.
--allow-missing-tos-commit is for a local shallow checkout only: with it, an
absent commit is reported as a NOTE and the artifact is bound by the rebuild
alone. The flag is refused when CI or GITHUB_ACTIONS is set to any non-empty
value other than false, 0, no or off; CI checks out full history instead.

compiler.source_commit is recorded provenance: only its format is checked, as
nothing in a built executable proves which commit produced it.

A release manifest must carry no profile fields at all. A test manifest must
declare itself test-only, list exactly the overrides
tos_service_actor_profile.py applies, and pin a code hash and BOC that differ
from its release's pins; its check also requires the committed release
artifact to still match the release manifest byte for byte.

Standard library only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tos_service_actor_profile as profiles  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / profiles.PROFILES[profiles.RELEASE]["manifest"]
SDK = REPO / "tosctl/src/node-control/contracts/src/service_actor.rs"

EXPECTED_FIELDS = {
    "schema": "tos.contract.release.v1",
    "protocol": "tos_service_v1",
    "contract": "tos-service-actor-v1",
    "source": "crypto/smartcont/service-actor-code.fc",
    "stdlib": "crypto/smartcont/stdlib.fc",
    "build_script": "scripts/build-tos-service-actor-v1.sh",
}


def expected_fields(name: str) -> dict:
    """The fixed manifest fields of a profile: its rail's contract and source."""
    selected = profiles.PROFILES[name]
    return {
        **EXPECTED_FIELDS,
        "contract": selected["contract"],
        "source": selected["source"],
        "artifact_base64": selected["artifact_base64"],
    }


PROFILE_FIELDS = ("profile", "test_only", "notice", "constant_overrides", "release_manifest")
TEST_NOTICE = "TEST NETWORKS ONLY"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
INCLUDE = re.compile(r'^\s*#include\s+"([^"]+)"\s*;', re.MULTILINE)


class ReleaseError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def decode_base64_file(path: Path) -> bytes:
    return base64.b64decode(b"".join(path.read_bytes().split()), validate=True)


def sdk_code(path: Path = SDK, constant: str = "SERVICE_ACTOR_CODE_B64") -> bytes:
    match = re.search(rf'pub const {constant}: &str = "([A-Za-z0-9+/=]+)";', path.read_text())
    require(match is not None, f"{constant} was not found in the SDK source")
    return base64.b64decode(match.group(1), validate=True)


def check_profile_fields(manifest: dict, name: str, root: Path) -> None:
    """The release manifest carries no profile fields; the test manifest
    labels itself test-only, lists exactly the overrides the build applies
    and pins code that differs from a release whose artifact is unchanged."""
    release_name = profiles.PROFILES[name]["release"]
    if release_name is None:
        present = [key for key in PROFILE_FIELDS if key in manifest]
        require(not present, f"the release manifest must not carry profile fields: {present}")
        return
    require(manifest.get("profile") == name, f"manifest profile must be {name!r}")
    require(manifest.get("test_only") is True, "the test manifest must set test_only to true")
    require(
        isinstance(manifest.get("notice"), str) and manifest["notice"].startswith(TEST_NOTICE),
        f"the test manifest notice must start with {TEST_NOTICE!r}",
    )
    require(
        manifest.get("constant_overrides") == profiles.PROFILES[name]["overrides"],
        "manifest constant_overrides differ from the overrides the build applies",
    )
    release_path = profiles.PROFILES[release_name]["manifest"]
    require(
        manifest.get("release_manifest") == release_path,
        f"manifest release_manifest must be {release_path!r}",
    )
    release = json.loads((root / release_path).read_text())
    require(
        manifest.get("code_hash") != release.get("code_hash"),
        "the test code hash equals the release code hash",
    )
    require(
        manifest.get("boc_sha256") != release.get("boc_sha256"),
        "the test BOC equals the release BOC",
    )
    release_artifact = decode_base64_file(root / profiles.PROFILES[release_name]["artifact_base64"])
    require(
        "sha256:" + hashlib.sha256(release_artifact).hexdigest() == release.get("boc_sha256")
        and len(release_artifact) == release.get("boc_bytes"),
        "the release artifact differs from the release manifest",
    )


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


def check_provenance(commit: str, paths: list[str], root: Path, allow_missing: bool = False) -> str:
    """'checked' when the files equal those at commit. A commit that is not in
    local history is a refusal, unless allow_missing is set, when it is
    'unavailable'. Anything else is a refusal."""
    require(COMMIT.match(commit) is not None, "tos_commit must be 40 lower-case hex digits")
    try:
        kind = subprocess.run(
            ["git", "cat-file", "-t", commit], cwd=root, capture_output=True, text=True
        )
    except FileNotFoundError as error:
        raise ReleaseError("git is not available to check tos_commit") from error
    if kind.returncode != 0:
        if "Not a valid object name" in kind.stderr or "could not get object info" in kind.stderr:
            if allow_missing:
                return "unavailable"
            raise ReleaseError(
                f"tos_commit {commit} is not in local history, so provenance cannot be checked; "
                "fetch it (git fetch origin <tos_commit>, or a full-history checkout), or pass "
                "--allow-missing-tos-commit for a local shallow checkout"
            )
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


def check_release(
    built: bytes,
    build_output: str,
    func: Path,
    root: Path = REPO,
    name: str = profiles.RELEASE,
    allow_missing_commit: bool = False,
) -> list[str]:
    try:
        selected = profiles.profile(name)
    except profiles.ProfileError as error:
        raise ReleaseError(str(error)) from error
    manifest = json.loads((root / selected["manifest"]).read_text())
    expected = expected_fields(name)
    for key, value in expected.items():
        require(manifest.get(key) == value, f"manifest {key} must be {value!r}")
    check_profile_fields(manifest, name, root)
    reported = parse_build_output(build_output)
    require(reported.get("profile") == name, f"the build output is not for profile {name!r}")
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
    constant = selected["sdk_constant"]
    require(
        sdk_code(root / selected["sdk"], constant) == built,
        f"SDK {constant} differs from the rebuild",
    )

    paths = include_closure((root / manifest["source"]).resolve(), root.resolve())
    paths = sorted(set(paths) | {manifest["stdlib"]})
    notes = []
    commit = manifest.get("tos_commit")
    require(isinstance(commit, str), "manifest tos_commit must be a string")
    if check_provenance(commit, paths, root, allow_missing_commit) == "unavailable":
        notes.append(
            f"NOTE: tos_commit {commit} not in local history; provenance not checked, artifact bound by rebuild"
        )
    return notes


ALLOW_MISSING_COMMIT = "--allow-missing-tos-commit"


# Values that mark a CI variable as explicitly off. CI runners set CI to "true",
# "1" or another non-empty value, so any other non-empty value means CI.
CI_OFF_VALUES = frozenset({"false", "0", "no", "off"})


def in_ci(environ: dict[str, str]) -> bool:
    for name in ("CI", "GITHUB_ACTIONS"):
        value = environ.get(name, "").strip().lower()
        if value and value not in CI_OFF_VALUES:
            return True
    return False


def main(argv: list[str] | None = None, environ: dict[str, str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    environ = dict(os.environ if environ is None else environ)
    allow_missing = bool(args) and args[0] == ALLOW_MISSING_COMMIT
    if allow_missing:
        args = args[1:]
        if in_ci(environ):
            print(
                f"Service Actor release check failed: {ALLOW_MISSING_COMMIT} is for a local "
                "shallow checkout and is refused in CI, which must fetch tos_commit",
                file=sys.stderr,
            )
            return 1
    if len(args) not in (3, 4):
        print(__doc__, file=sys.stderr)
        return 2
    built = Path(args[0]).read_bytes()
    build_output = Path(args[1]).read_text()
    name = args[3] if len(args) == 4 else profiles.RELEASE
    try:
        for note in check_release(
            built, build_output, Path(args[2]), name=name, allow_missing_commit=allow_missing
        ):
            print(note)
    except ReleaseError as error:
        print(f"Service Actor release check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
