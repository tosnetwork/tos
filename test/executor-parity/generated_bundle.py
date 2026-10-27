"""Small source/run/attempt-bound generated fixture artifacts for the rescue gate."""

# ruff: noqa: E402
import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

from generated_roots import POST, RELEASE, ROOT, validate

FOLDERS = {RELEASE: "release", POST: "post"}
RUNNERS = ("ubuntu-24.04", "ubuntu-24.04-arm")
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_BUNDLES = 32
CONTROL_CASES = (
    "missing",
    "extra",
    "reordered",
    "roots",
    "native",
    "boc",
    "rejection",
    "rejection-exit",
    "rejection-message",
    "time",
    "lt",
    "context",
    "code",
    "workchain",
    "config",
    "source",
    "producer",
)


def filenames():
    paths = {"controls.json"}
    for family, folder in FOLDERS.items():
        files = ["config.boc", "scenarios.tsv", "native.tsv", "rust.tsv", "result.json"]
        files += [
            family + suffix
            for suffix in (
                "-receipt.json",
                "-roots.tsv",
                "-root-native.json",
                "-root-expected.tsv",
                "-root-driver.stdout",
            )
        ]
        paths.update(folder + "/" + name for name in files)
    return paths


def children(path, maximum):
    result = []
    with os.scandir(path) as entries:
        for entry in entries:
            assert len(result) < maximum, "generated directory population limit"
            result.append(Path(entry.path))
    return result


def bounded(path):
    assert path.is_file() and not path.is_symlink(), "invalid generated bundle file"
    assert path.stat().st_size <= MAX_FILE, "generated bundle file size limit"
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    assert len(data) <= MAX_FILE
    return data


def control_result(value, source):
    assert value == {
        "source": source,
        "passed": True,
        "families": {family: list(CONTROL_CASES) for family in FOLDERS},
    }, "generated controls incomplete"


def metadata(source, runner):
    return dict(
        source=source,
        event=os.environ["GITHUB_EVENT_NAME"],
        run_id=os.environ["GITHUB_RUN_ID"],
        run_attempt=os.environ["GITHUB_RUN_ATTEMPT"],
        suite="release-wallet",
        runner=runner,
    )


def bundle(output, release, post, controls, source, runner):
    assert not output.exists(), "generated bundle destination exists"
    sources = {"controls.json": controls}
    for family, original in [(RELEASE, release), (POST, post)]:
        for name in filenames():
            folder, _, filename = name.partition("/")
            if folder == FOLDERS[family]:
                sources[name] = original / filename
    manifest = metadata(source, runner)
    manifest["files"] = {}
    payloads, total = {}, 0
    # Admit every source before creating output paths or copying any bytes.
    for name in sorted(sources):
        assert total + sources[name].stat().st_size <= MAX_TOTAL, (
            "generated bundle total size limit"
        )
        value = bounded(sources[name])
        total += len(value)
        assert total <= MAX_TOTAL, "generated bundle total size limit"
        payloads[name] = value
        manifest["files"][name] = dict(bytes=len(value), sha256=hashlib.sha256(value).hexdigest())
    control_result(json.loads(payloads["controls.json"]), source)
    encoded = (json.dumps(manifest, indent=2) + "\n").encode()
    assert len(encoded) <= MAX_FILE and total + len(encoded) <= MAX_TOTAL, (
        "generated bundle total size limit"
    )
    output.mkdir(parents=True)
    for name, value in payloads.items():
        path = output / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(value)
    (output / "bundle.json").write_bytes(encoded)
    validate_bundle(output, source, manifest["event"], manifest["run_id"], manifest["run_attempt"])


def validate_bundle(directory, source, event, run_id, attempt):
    assert not directory.is_symlink() and directory.is_dir(), "invalid generated bundle directory"
    entries = children(directory, 4)
    assert {p.name for p in entries} == {"bundle.json", "controls.json", *FOLDERS.values()}, (
        "unexpected generated bundle entries"
    )
    expected = filenames()
    actual = {"controls.json", "bundle.json"}
    for folder in FOLDERS.values():
        child = directory / folder
        assert child.is_dir() and not child.is_symlink()
        entries = children(child, 10)
        assert len(entries) == 10, "generated bundle file count mismatch"
        actual.update(folder + "/" + p.name for p in entries)
    assert actual == expected | {"bundle.json"}, "unexpected generated bundle paths"
    value = json.loads(bounded(directory / "bundle.json"))
    assert set(value) == {"source", "event", "run_id", "run_attempt", "suite", "runner", "files"}
    assert (value["source"], value["event"], value["run_id"], value["suite"]) == (
        source,
        event,
        run_id,
        "release-wallet",
    ), "generated bundle source/run/event/suite mismatch"
    assert value["runner"] in RUNNERS, "generated bundle runner mismatch"
    assert isinstance(value["run_attempt"], str) and re.fullmatch(
        r"[1-9][0-9]*", value["run_attempt"]
    )
    assert 0 < int(value["run_attempt"]) <= int(attempt), "generated bundle future attempt"
    assert set(value["files"]) == expected, "generated bundle manifest paths mismatch"
    total = len(bounded(directory / "bundle.json"))
    for name in sorted(expected):
        data = bounded(directory / name)
        total += len(data)
        assert total <= MAX_TOTAL, "generated bundle total size limit"
        assert value["files"][name] == dict(
            bytes=len(data), sha256=hashlib.sha256(data).hexdigest()
        ), "generated bundle file digest mismatch"
    control_result(json.loads(bounded(directory / "controls.json")), source)
    signatures = tuple(
        validate(directory / folder, family, source) for family, folder in FOLDERS.items()
    )
    return value, signatures


def receipt_guard():
    spec = importlib.util.spec_from_file_location(
        "generated_rescue_guard", ROOT / "scripts/check-rescue-context-ci.py"
    )
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    return guard


def compare_bundles(directory, receipts, source, event, run_id, attempt):
    assert re.fullmatch(r"[1-9][0-9]*", attempt)
    guard = receipt_guard()
    coverage = guard.validate(
        guard.WORKFLOW.read_text(),
        json.loads(guard.CONTRACT.read_text()),
        (ROOT / ".github/workflows/source-guards.yml").read_text(),
    )
    selected = guard.verify_receipts(receipts, source, run_id, attempt, coverage, event)
    paths = children(directory, MAX_BUNDLES)
    assert 0 < len(paths) <= MAX_BUNDLES, "generated bundle population limit"
    seen, candidates = set(), {}
    # Every candidate is fully validated first. An invalid newer attempt cannot
    # disappear behind an older successful artifact.
    for path in paths:
        value, signature = validate_bundle(path, source, event, run_id, attempt)
        key = value["runner"], int(value["run_attempt"])
        assert key not in seen, "duplicate generated bundle attempt"
        seen.add(key)
        candidates[key] = signature
    chosen = []
    for runner in RUNNERS:
        key = runner, selected[("release-wallet", runner)]
        assert key in candidates, "missing generated bundle for successful suite attempt"
        chosen.append(candidates[key])
    assert chosen[0] == chosen[1], "generated architecture mismatch"
    print(
        "PASS: generated15 outcomes/13 three-root transactions; exact source/run/suite attempts and controls"
    )


def artifact_selection(artifacts, attempt):
    selected = [a for a in artifacts if a["name"].startswith("rescue-roots-")]
    assert 0 < len(selected) <= MAX_BUNDLES, "generated download population limit"
    names = set()
    total = 0
    for artifact in selected:
        match = re.fullmatch(
            r"rescue-roots-(ubuntu-24\.04(?:-arm)?)-attempt-([1-9][0-9]*)", artifact["name"]
        )
        assert match and int(match[2]) <= int(attempt), "invalid generated download identity"
        assert artifact["name"] not in names, "duplicate generated download identity"
        names.add(artifact["name"])
        assert artifact["expired"] is False and type(artifact["size_in_bytes"]) is int
        assert 0 < artifact["size_in_bytes"] <= MAX_TOTAL, "generated download size limit"
        total += artifact["size_in_bytes"]
    assert total <= MAX_TOTAL * MAX_BUNDLES
    return len(selected)


def preflight():
    repository, run_id = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_RUN_ID"]
    assert re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
    assert re.fullmatch(r"[1-9][0-9]*", run_id)
    artifacts, page = [], 1
    while True:
        url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100&page={page}"
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": "Bearer " + os.environ["GH_TOKEN"],
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(MAX_FILE + 1)
        assert len(data) <= MAX_FILE, "generated artifact metadata size limit"
        body = json.loads(data)
        assert type(body["total_count"]) is int and 0 <= body["total_count"] <= 2048, (
            "generated metadata population limit"
        )
        entries = body["artifacts"]
        assert isinstance(entries, list) and len(entries) <= 100
        artifacts.extend(entries)
        assert len(artifacts) <= 2048
        if len(artifacts) >= body["total_count"]:
            assert len(artifacts) == body["total_count"]
            break
        assert len(entries) == 100 and page < 21, "incomplete generated artifact metadata"
        page += 1
    print(
        "PASS: bounded generated artifact selection",
        artifact_selection(artifacts, os.environ["GITHUB_RUN_ATTEMPT"]),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--bundle", type=Path)
    action.add_argument("--compare", type=Path)
    action.add_argument("--check-download", action="store_true")
    parser.add_argument("--release", type=Path)
    parser.add_argument("--post", type=Path)
    parser.add_argument("--controls", type=Path)
    parser.add_argument("--receipts", type=Path)
    parser.add_argument("--runner", choices=RUNNERS)
    args = parser.parse_args()
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if args.bundle:
        bundle(args.bundle, args.release, args.post, args.controls, source, args.runner)
    elif args.compare:
        assert os.environ["SOURCE_SHA"] == source, "generated expected checkout mismatch"
        compare_bundles(
            args.compare,
            args.receipts,
            source,
            os.environ["GITHUB_EVENT_NAME"],
            os.environ["GITHUB_RUN_ID"],
            os.environ["GITHUB_RUN_ATTEMPT"],
        )
    else:
        preflight()


if __name__ == "__main__":
    main()
