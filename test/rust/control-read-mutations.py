#!/usr/bin/env python3
"""Run each control-read mutation in an isolated detached worktree and target."""
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import threading
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--parallel", type=int, default=10)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--only", nargs="*")
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = source / "doc/evidence/elector-control-client/mutations.json"
    mutations = json.loads(manifest.read_text())
    if args.only:
        mutations = [m for m in mutations if m["name"] in args.only]
    if not mutations:
        raise SystemExit("zero mutation anchors selected")
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    patch = subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=source)
    (output / "source.patch").write_bytes(patch)
    lock = threading.Lock()

    def run(mutation):
        root = output / ("worktree-" + mutation["name"])
        with lock:
            subprocess.run(["git", "worktree", "add", "--detach", str(root), base], cwd=source, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if patch:
                subprocess.run(["git", "apply", "-"], input=patch, cwd=root, check=True)
            path = root / mutation["file"]
            text = path.read_text()
            start = -1
            for _ in range(mutation["occurrence"]):
                start = text.find(mutation["old"], start + 1)
                if start < 0:
                    raise RuntimeError("zero source anchors for " + mutation["name"])
            line = text[:start].count("\n") + 1
            path.write_text(text[:start] + mutation["new"] + text[start + len(mutation["old"]):])
            command = ["cargo", "test", "-p", mutation["package"], "--locked", "-j", str(args.jobs)]
            if mutation["kind"] == "test":
                command += ["--test", "control_reads"]
            else:
                command += ["--" + mutation["kind"]]
            command += [mutation["anchor"], "--", "--nocapture"]
            if mutation["kind"] != "doc":
                command += ["--exact"]
            env = os.environ.copy()
            env.update(RUSTC_WRAPPER="sccache", CARGO_TARGET_DIR=str(root / ".cargo-target"),
                       CARGO_TERM_COLOR="never", RUST_BACKTRACE="0", SCCACHE_BASEDIRS=str(root))
            log = output / (mutation["name"] + ".log")
            with log.open("w") as stream:
                result = subprocess.run(command, cwd=root / "tosctl/src", env=env,
                                        stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
            text = log.read_text(errors="replace")
            anchor_failed = any(mutation["anchor"] in line and "FAILED" in line
                                for line in text.splitlines())
            # Compiler failures, timeouts and a filtered-out suite are not red evidence.
            red = result.returncode != 0 and anchor_failed and bool(re.search(r"running [1-9][0-9]* tests?", text))
            record = dict(name=mutation["name"], base=base, file=mutation["file"], line=line,
                          command=command, exit=result.returncode, anchor_failed=anchor_failed,
                          red=red, sha256=hashlib.sha256(log.read_bytes()).hexdigest())
            (output / (mutation["name"] + ".json")).write_text(json.dumps(record, indent=2) + "\n")
            print(mutation["name"], "RED" if red else "INVALID", result.returncode, flush=True)
            return record
        finally:
            with lock:
                subprocess.run(["git", "worktree", "remove", "--force", str(root)], cwd=source, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
        records = list(pool.map(run, mutations))
    (output / "results.json").write_text(json.dumps(records, indent=2) + "\n")
    if not all(record["red"] for record in records):
        raise SystemExit("at least one mutation did not fail its named anchor")
    print(f"{len(records)} mutations failed their named anchors", flush=True)


if __name__ == "__main__":
    main()
