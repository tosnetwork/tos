#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"

python3 - "$root" <<'PY'
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
tracked = subprocess.run(
    ["git", "-C", str(root), "ls-files", "*CMakeLists.txt"],
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines()

resolved = []
for relative in tracked:
    path = root / relative
    lines = path.read_text().splitlines()
    for line_number, line in enumerate(lines):
        marker = "${CMAKE_SOURCE_DIR}/scripts/embed-"
        if marker not in line or ".sh" not in line:
            continue
        script = line.split(marker, 1)[1].split(".sh", 1)[0] + ".sh"
        command_start = line_number
        while command_start >= 0:
            keyword = lines[command_start].lstrip().split(maxsplit=1)
            if keyword and keyword[0] in {
                "COMMAND",
                "DEPENDS",
                "MAIN_DEPENDENCY",
                "OUTPUT",
                "WORKING_DIRECTORY",
                "COMMENT",
            }:
                break
            command_start -= 1
        if command_start < 0 or not lines[command_start].lstrip().startswith("COMMAND "):
            continue
        command = "\n".join(lines[command_start : line_number + 1])
        required = (
            "COMMAND ${CMAKE_COMMAND} -E env",
            "FUNC_BIN=$<TARGET_FILE:func>",
            "FIFT_BIN=$<TARGET_FILE:fift>",
        )
        if any(token not in command for token in required):
            raise SystemExit(
                f"FROZEN_BOC_TOOLCHAIN_SOURCE_FAILURE: {relative}:{line_number + 1} "
                f"{script} is a bare embed command without target-resolved func and fift"
            )
        resolved.append((relative, line_number + 1, script))

if not resolved:
    raise SystemExit("FROZEN_BOC_TOOLCHAIN_SOURCE_FAILURE: no frozen-artifact embed commands were found")

print(
    f"FROZEN_BOC_TOOLCHAIN_SOURCE_OK: all {len(resolved)} CMake frozen-artifact rules use "
    "$<TARGET_FILE:func> and $<TARGET_FILE:fift>"
)
PY
