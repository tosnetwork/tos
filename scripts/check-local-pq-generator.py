#!/usr/bin/env python3
"""Exercise the real generator with its original checkout temporarily unavailable.

For disposable CI checkouts only. This validates message/proof generation, not
on-chain acceptance. It prints no notes, keys, proofs or private request bodies.
"""

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generator", required=True, type=Path)
    parser.add_argument("--checkout", required=True, type=Path)
    args = parser.parse_args()
    repo = args.checkout.resolve()
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or repo != Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    ):
        raise SystemExit(
            "checkout isolation is restricted to this disposable GitHub Actions workspace"
        )
    spec = importlib.util.spec_from_file_location(
        "resource_check", repo / "scripts/check-local-pq-resources.py"
    )
    resource_check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(resource_check)
    contract = (repo / resource_check.CONTRACT).read_text()
    fixture = (repo / resource_check.FIXTURE).read_text()
    hidden = repo.with_name(repo.name + ".pq-isolation-" + str(os.getpid()))
    if hidden.exists():
        raise SystemExit("isolation destination already exists")
    with tempfile.TemporaryDirectory(prefix="pq-generator-") as temporary:
        directory = Path(temporary)
        generator = directory / "local_pool_traffic"
        shutil.copy2(args.generator.resolve(), generator)
        os.chdir(directory)
        repo.rename(hidden)
        process = None
        try:
            process = subprocess.Popen(
                [str(generator)],
                cwd=directory,
                env={"PATH": "/usr/bin:/bin", "HOME": str(directory), "RAYON_NUM_THREADS": "2"},
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            def request(value):
                process.stdin.write(json.dumps(value) + "\n")
                process.stdin.flush()
                line = process.stdout.readline()
                if not line:
                    raise RuntimeError("generator stopped before replying")
                result = json.loads(line)
                if result.get("ok") is not True:
                    raise RuntimeError("generator rejected isolated " + value["operation"])
                return result["result"], line

            resources, line = request(dict(operation="resources"))
            resource_check.validate(line, contract, fixture)
            value, _ = request(dict(operation="init"))
            state = value["state"]
            count = 0
            for operation in ("deposit", "deposit", "transfer", "withdraw"):
                amount = 10_000_000_000 if operation != "withdraw" else 1_000_000_000
                req = dict(
                    operation=operation,
                    state=state,
                    amount=amount,
                    owner=1,
                    pool="01" * 32,
                    recipient="02" * 32,
                    global_id=3,
                    valid_until=int(time.time()) + 3600,
                )
                if operation != "deposit":
                    req["inputs"] = [state["notes"][0]["index"], state["notes"][1]["index"]]
                result, _ = request(req)
                if not result.get("body_hex") or result["value"] <= 0:
                    raise RuntimeError("no payable message from generator")
                liability = state["liability"]
                if operation == "deposit":
                    liability += amount
                if operation == "withdraw":
                    liability -= amount + resources["withdrawal_fee"]
                if (
                    result["expected"]["native_liability"] != liability
                    or result["state"]["liability"] != liability
                ):
                    raise RuntimeError("generator liability mismatch")
                if (
                    operation != "deposit"
                    and len(result["state"]["nullifiers"]) != len(state["nullifiers"]) + 2
                ):
                    raise RuntimeError("two nullifiers not added")
                state = result["state"]
                count += 1
                print(json.dumps({"operation": operation, "generated": True}), flush=True)
            process.stdin.close()
            if process.wait(timeout=10):
                raise RuntimeError("generator exited unsuccessfully")
            print(
                json.dumps(
                    {
                        "isolated_operations": count,
                        "resource_match": True,
                        "claim": "real proof/message generation; not live-chain acceptance",
                    }
                )
            )
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            hidden.rename(repo)


if __name__ == "__main__":
    main()
