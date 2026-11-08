#!/usr/bin/env python3
"""Write a committed evidence index for one bench run.

    uv run python bench/make_evidence_index.py RUN_DIR bench/evidence/NAME --retention "..."

The index keeps what a reviewer needs in Git: the run's results.json (the command's
parameters, the source commit, the live ConfigParams with hashes and every stage
record) plus the path, SHA-256 and size of each bulky raw file that stays in the
retained run directory (block and timeline CSVs, the bench log, the validators'
collation records). Raw output itself is not committed.
"""

import argparse
import hashlib
import json
import shutil
from pathlib import Path

RAW_GLOBS = (
    "bench.log",
    "stage-*/blocks.csv",
    "stage-*/timeline.csv",
    "stage-*/result.json",
    "contracts/*.boc",
    "contracts/contracts.json",
    "network/node*/session-logs",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("run", type=Path, help="a run directory written by run_local_bench.py")
    p.add_argument("out", type=Path, help="new evidence directory inside the repository")
    p.add_argument(
        "--retention", required=True, help="where and how long the raw run directory is kept"
    )
    p.add_argument("--command", required=True, help="the exact command that produced the run")
    a = p.parse_args()
    run = a.run.resolve()
    results = run / "results.json"
    if not results.is_file():
        raise SystemExit(f"{run} has no results.json; the run did not finish")
    a.out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(results, a.out / "results.json")
    raw = []
    for pattern in RAW_GLOBS:
        for path in sorted(run.glob(pattern)):
            if path.is_file():
                raw.append(
                    {
                        "path": str(path.relative_to(run)),
                        "sha256": sha256(path),
                        "bytes": path.stat().st_size,
                    }
                )
    report = json.loads(results.read_text())
    index = {
        "run_directory": str(run),
        "retention": a.retention,
        "command": a.command,
        "exit_status": 0,
        "source_commit": report.get("source_commit"),
        "results_json_sha256": sha256(results),
        "chain_config_hashes": {k: v["hash"] for k, v in report.get("chain_config", {}).items()},
        "raw_files": raw,
    }
    (a.out / "INDEX.json").write_text(json.dumps(index, indent=2) + "\n")
    print(a.out / "INDEX.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
