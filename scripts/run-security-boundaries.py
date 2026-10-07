#!/usr/bin/env python3
"""Run native boundary tests on macOS without the baseline Linux-only exporter.

The full CMake target is the Linux/CI authority. This local unit runner compiles
production HTTP/explorer code and the registered tests with CMake's own flags,
then omits only two unused libraries (exporter and toslib) from the unit link.
It does not validate the full daemon or a malicious consensus block.
"""

import argparse
import json
import shlex
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(build: Path, test_filter: str | None = None):
    commands = json.loads((build / "compile_commands.json").read_text())
    line = subprocess.check_output(
        ["ninja", "-C", str(build), "-t", "commands", "test-security-boundaries"], text=True
    ).splitlines()[-1]
    args = shlex.split(line)
    start = args.index("&&") + 1
    args = args[start : args.index("&&", start)]
    with tempfile.TemporaryDirectory(prefix="boundary-tests-") as tmp:
        for source in [
            "test/test-security-boundaries.cpp",
            "blockchain-explorer/blockchain-explorer-http.cpp",
            "http/http.cpp",
        ]:
            entry = next(x for x in commands if x["file"] == str(ROOT / source))
            cmd = shlex.split(entry["command"])
            out = str(Path(tmp) / (Path(source).name + ".o"))
            old_output = cmd[cmd.index("-o") + 1]
            cmd[cmd.index("-o") + 1] = out
            subprocess.run(cmd, cwd=entry["directory"], check=True)
            if source == "http/http.cpp":
                args.insert(args.index("http/libtoshttp.a"), out)
            elif source.startswith("blockchain-explorer/"):
                for index, value in enumerate(args):
                    if value.endswith("blockchain-explorer-http.cpp.o"):
                        args[index] = out
            else:
                args = [out if x == old_output else x for x in args]
        args = [x for x in args if x not in {"metrics/libmetrics.a", "toslib/libtoslib.a"}]
        output = str(Path(tmp) / "test-security-boundaries")
        args[args.index("-o") + 1] = output
        subprocess.run(args, cwd=build, check=True)
        test_args = [output] + (["-f", test_filter] if test_filter else [])
        subprocess.run(test_args, cwd=build, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--filter")
    options = parser.parse_args()
    run(options.build_dir.resolve(), options.filter)
