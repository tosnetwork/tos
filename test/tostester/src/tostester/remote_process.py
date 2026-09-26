"""Execute one process specification received from RemoteCommandBackend."""

from __future__ import annotations

import argparse
import base64
import json
import os
import signal
import subprocess
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-base64", required=True)
    args = parser.parse_args()
    spec = json.loads(base64.urlsafe_b64decode(args.spec_base64).decode())
    resource_path = spec["env"].get("TOS_N6_RESOURCE_JSONL")
    if resource_path is None:
        os.chdir(spec["cwd"])
        os.execvpe(spec["executable"], [spec["executable"], *spec["args"]], spec["env"])
    process = subprocess.Popen(
        [spec["executable"], *spec["args"]], cwd=spec["cwd"], env=spec["env"]
    )

    def terminate(_signal: int, _frame: object) -> None:
        process.terminate()

    signal.signal(signal.SIGTERM, terminate)
    with Path(resource_path).open("w") as stream:
        while process.poll() is None:
            try:
                status = Path(f"/proc/{process.pid}/status").read_text()
                stat = Path(f"/proc/{process.pid}/stat").read_text().split()
            except FileNotFoundError:
                break
            stream.write(
                json.dumps(
                    {
                        "monotonic_ns": time.monotonic_ns(),
                        "wall_unix_ns": time.time_ns(),
                        "status": status,
                        "cpu_ticks": int(stat[13]) + int(stat[14]),
                    },
                    sort_keys=True,
                )
                + "\n"
            )
            stream.flush()
            time.sleep(0.2)
    raise SystemExit(process.wait())


if __name__ == "__main__":
    main()
