#!/usr/bin/env python3
"""Exercise the CI selector, registration and independent-oracle guards."""

import argparse
import json
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CASES = {
    "selector": (
        ".github/workflows/branch-chain-python.yml",
        "^getter-context-(context|vm|libraries|liteserver)$",
        "^getter-context-(context|vm|libraries)$",
        "getter-context independent parity gate is absent",
    ),
    "registration": (
        "CMakeLists.txt",
        "foreach(context_case context vm libraries liteserver)",
        "foreach(context_case context vm libraries)",
        "getter-context CTest registrations or fixture dependency are absent",
    ),
    "core-selector": (
        ".github/workflows/branch-chain-python.yml",
        "^control-getter-(executor|shutdown|limits|actor|vm|context|delete|budget)$",
        "^control-getter-(executor|shutdown|limits|actor|vm|context|delete)$",
        "bounded control-getter behavior and budget gate is absent",
    ),
    "core-registration": (
        "CMakeLists.txt",
        "add_test(NAME control-getter-budget",
        "add_test(NAME unregistered-control-budget",
        "bounded control-getter CTest registrations are absent",
    ),
    "core-target": (
        ".github/workflows/branch-chain-python.yml",
        "test-control-getter-budget test-control-getter-query",
        "test-control-getter-query",
        "native fixture targets are missing: ['test-control-getter-budget']",
    ),
    "oracle": (
        "test/validator/getter-context-reference.h",
        "td::make_refint(now)",
        "td::make_refint(0)",
        "independent context oracle differs from the frozen source",
    ),
}


def run(command, cwd):
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=90, check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--only", choices=CASES)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    build = args.build.resolve()
    patch = run(["git", "diff", "--binary", "HEAD"], source)
    if patch.returncode:
        raise RuntimeError("cannot capture candidate patch")
    cases = [args.only] if args.only else list(CASES)
    with tempfile.TemporaryDirectory(prefix="getter-context-ci-controls-") as directory:
        root = Path(directory)
        patch_file = root / "candidate.patch"
        patch_file.write_text(patch.stdout)

        def control(name):
            checkout = root / name
            added = run(["git", "worktree", "add", "--detach", str(checkout), "HEAD"], source)
            if added.returncode:
                raise RuntimeError(added.stderr)
            try:
                if patch.stdout:
                    applied = run(["git", "apply", str(patch_file)], checkout)
                    if applied.returncode:
                        raise RuntimeError(applied.stderr)
                relative, before, after, reason = CASES[name]
                command = ["python3", str(checkout / "scripts/check-branch-chain-python-ci.py")]
                if name == "oracle":
                    fixture_build = checkout / "control-build"
                    (fixture_build / "crypto").mkdir(parents=True)
                    for dependency in ("create-state", "smartcont"):
                        (fixture_build / "crypto" / dependency).symlink_to(
                            build / "crypto" / dependency
                        )
                    command = [
                        "python3",
                        str(checkout / "test/validator/prepare-getter-context.py"),
                        "--source",
                        str(checkout),
                        "--build",
                        str(fixture_build),
                    ]
                green = run(command, checkout)
                if green.returncode:
                    raise RuntimeError(green.stdout + green.stderr)
                path = checkout / relative
                original = path.read_text()
                if original.count(before) != 1:
                    raise RuntimeError(f"{name}: expected exactly one mutation anchor")
                line = original[: original.index(before)].count("\n") + 1
                path.write_text(original.replace(before, after))
                red = run(command, checkout)
                if red.returncode != 1 or reason not in red.stdout + red.stderr:
                    raise RuntimeError(
                        f"{name}: not an intended refusal: {red.returncode}\n{red.stdout}{red.stderr}"
                    )
                path.write_text(original)
                restored = run(command, checkout)
                if restored.returncode:
                    raise RuntimeError(restored.stdout + restored.stderr)
                return {
                    "control": name,
                    "file": relative,
                    "line": line,
                    "anchors": 1,
                    "green_exit": 0,
                    "red_exit": 1,
                    "restored_exit": 0,
                    "reason": reason,
                }
            finally:
                removed = run(["git", "worktree", "remove", "--force", str(checkout)], source)
                if removed.returncode:
                    raise RuntimeError(removed.stderr)

        with ThreadPoolExecutor(max_workers=3) as pool:
            for result in pool.map(control, cases):
                print(json.dumps(result), flush=True)
    print(f"GETTER_CONTEXT_CI_CONTROLS controls={len(cases)} not_red=0")


if __name__ == "__main__":
    main()
