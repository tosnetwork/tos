#!/usr/bin/env python3
"""Exercise receipt guards using an already executed isolated-chain request.

Every invocation of the acceptance driver uses verify mode. No submission,
signing, service lifecycle operation or replacement transaction is performed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "request", "token", "capture", "case", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    root = source.parents[2]
    os.umask(0o077)
    args.out.mkdir(mode=0o700, exist_ok=False)
    rows = []
    for guard in ("request_id", "reply_sha256"):
        for stage in ("baseline", "wrong-binding", "guard-removed", "restored"):
            name = guard + "-" + stage
            out = args.out / name
            out.mkdir(mode=0o700)
            for filename in ("submit-started.json", "prepare-reply-lost.json"):
                shutil.copyfile(args.case / filename, out / filename)
            if stage in ("wrong-binding", "guard-removed"):
                receipt = out / "prepare-reply-lost.json"
                value = json.loads(receipt.read_bytes())
                value[guard] = "00" * 32
                receipt.write_text(json.dumps(value))
            script = source / "prepared_reply.py"
            if stage == "guard-removed":
                temporary = args.out / (name + "-source")
                temporary.mkdir(mode=0o700)
                for filename in ("control.py", "prepared_reply.py"):
                    shutil.copyfile(source / filename, temporary / filename)
                target = temporary / (
                    "prepared_reply.py" if guard == "request_id" else "control.py"
                )
                anchor = (
                    'fault.get("request_id") != identity'
                    if guard == "request_id"
                    else "hashlib.sha256(encode(prepared)).hexdigest() != prepared_sha256"
                )
                text = target.read_text()
                if text.count(anchor) != 1:
                    raise RuntimeError("receipt guard anchor drift")
                target.write_text(text.replace(anchor, "False"))
                script = temporary / "prepared_reply.py"
            command = [sys.executable, str(script), "--mode", "verify"]
            for key in ("config", "request", "token", "capture"):
                command += ["--" + key, str(getattr(args, key))]
            command += ["--out", str(out)]
            result = subprocess.run(
                command,
                env={
                    **os.environ,
                    "PYTHONPATH": str(source) + ":" + str(root / "tools/bonded-relayer"),
                },
                capture_output=True,
                text=True,
                timeout=150,
            )
            log = result.stdout + result.stderr
            raw = log.encode()
            filename = name + ".log"
            (args.out / filename).write_bytes(raw)
            if stage == "wrong-binding":
                expected = (
                    "matching completed crash evidence required"
                    if guard == "request_id"
                    else "persisted prepared bytes differ from the lost native reply"
                )
                if result.returncode != 1 or expected not in log or (out / "VERDICT.json").exists():
                    raise RuntimeError("wrong binding did not refuse at the intended guard")
            elif result.returncode != 0 or "BR1_PREPARED_REPLY_RECOVERY_PASS" not in log:
                raise RuntimeError("baseline, removed-guard or restoration result changed")
            rows.append(
                {
                    "case": name,
                    "exit": result.returncode,
                    "false_acceptance": stage == "guard-removed",
                    "log": filename,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                }
            )
    report = {
        "result": "PASS",
        "source_sha256": {
            name: hashlib.sha256((source / name).read_bytes()).hexdigest()
            for name in ("prepared_reply.py", "control.py", Path(__file__).name)
        },
        "rows": rows,
    }
    (args.out / "REPORT.json").write_text(json.dumps(report, indent=2) + "\n")
    print("BR1_PREPARED_REPLY_CONTROLS_PASS", len(rows))


if __name__ == "__main__":
    main()
