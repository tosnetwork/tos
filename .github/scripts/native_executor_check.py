"""Keep native executor failures visible without changing their exit status."""

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

PHASES = (
    ("build", ["cmake", "--build", "build", "--target", "test-fift", "test-cells", "-j2"]),
    ("test-fift", ["./build/test-fift"]),
    ("test-cells", ["./build/test-cells"]),
)
TAIL_BYTES = 65536
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
FAILURE_LINE = re.compile(r"error:|fatal|fail|assert|exception|not found|cannot", re.I)


def diagnostics(phase: str, status: int, text: str) -> list[str]:
    lines = [ANSI_ESCAPE.sub("", line).strip() for line in text.splitlines() if line.strip()]
    important = [line for line in lines if FAILURE_LINE.search(line)]
    selected = important[:6] if important else lines[-6:]
    result = [f"{phase}: exit {status}"]
    for line in selected:
        # Single-line, bounded metadata; never interpret output as a command.
        item = " ".join(line.split())[:350]
        if item not in result:
            result.append(item)
    return result


def run_phases(phases, directory: Path) -> tuple[int, list[str]]:
    directory.mkdir(parents=True, exist_ok=True)
    receipts = []
    for phase, command in phases:
        print(f"Starting native executor phase: {phase}", flush=True)
        with tempfile.TemporaryFile() as log:
            try:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
                status = result.returncode
            except OSError as error:
                status = 127
                log.write(str(error).encode("utf-8"))
            size = log.tell()
            log.seek(max(0, size - TAIL_BYTES))
            tail = log.read().decode("utf-8", errors="replace")
        (directory / f"{phase}.tail.txt").write_text(tail, encoding="utf-8")
        receipts.append({"phase": phase, "command": command, "exit": status, "log_bytes": size})
        (directory / "receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
        # Prefix lines so raw test output cannot inject runner workflow commands.
        for line in tail[-12000:].splitlines():
            print(f"[native {phase}] {line}")
        if status != 0:
            return (status if status > 0 else 128 - status), diagnostics(phase, status, tail)
    return 0, ["PASS: native executor build, test-fift and test-cells"]


def main() -> int:
    directory = Path(os.environ["RUNNER_TEMP"]) / "native-executor-diagnostics"
    status, messages = run_phases(PHASES, directory)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as stream:
            stream.write("diagnostics=" + json.dumps(messages, ensure_ascii=True) + "\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(f"## Native executor checks\n\nExit status: `{status}`\n\n")
            for message in messages:
                stream.write("    " + message + "\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
