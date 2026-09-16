"""Require the consensus admission path to name nothing a node happens to hold.

A block is produced once and re-executed by everyone. What admits a registry
update must therefore be decidable from the block: the parent state and the
message. The finality an approval relies on is carried by that message as a
fixed-surface witness and authenticated against the parent state's own history
index, which reads no archive.

Anything node-local in this path -- a cache filled asynchronously, a resolver, a
reader that can reach an archive -- makes the answer depend on what one node
happened to have. A producer would admit an update, a validator would defer,
execute the privileged instruction against nothing, rebuild a different block and
reject a candidate that was correct. Neither side could see why.

A comment saying so would not survive the next refactor. This is the type
boundary written down: these names may not appear in the functions that decide
admission, and this refuses when they do.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# What may not appear in the consensus admission path.
NODE_LOCAL = ("NativeAnchorCache", "NativeHistoryResolutionQueue", "NativeBlockReader", "resolve_declared_history")

# The declarations that decide admission. Their signatures are the boundary.
DECIDING = {
    "validator/auth/native-registry-admission.h": "admit_registry_message",
    "validator/auth/native-collation-authority.h": "assemble_registry_authority",
}
# And the structure the assembler is handed.
INPUTS = ("validator/auth/native-collation-authority.h", "CollationAuthorityInputs")


def declaration(text: str, name: str) -> str:
    match = re.search(re.escape(name) + r"\s*\([^;]*\);", text)
    return match.group(0) if match else ""


def structure(text: str, name: str) -> str:
    start = text.find(f"struct {name}")
    return text[start:text.index("};", start)] if start >= 0 else ""


def verify(files: dict[str, str]) -> None:
    for path, name in DECIDING.items():
        signature = declaration(files[path], name)
        if not signature:
            raise ValueError(f"{name} is not declared in {path}")
        for token in NODE_LOCAL:
            if token in signature:
                raise ValueError(f"{name} accepts {token}")
    fields = structure(files[INPUTS[0]], INPUTS[1])
    if not fields:
        raise ValueError(f"{INPUTS[1]} is not declared")
    for token in NODE_LOCAL:
        if token in fields:
            raise ValueError(f"{INPUTS[1]} carries {token}")


def main() -> int:
    files = {path: (ROOT / path).read_text() for path in {*DECIDING, INPUTS[0]}}

    # Silence is not evidence. Each way back in is planted in memory and this
    # has to reject it; a checker that cannot see a violation reports a clean
    # boundary for the same reason an empty search does.
    header, name = INPUTS
    probes = [
        {**files, path: files[path].replace(f"{name}(", f"{name}(const NativeAnchorCache&, ", 1)}
        for path, name in DECIDING.items()
    ]
    probes.append({**files, header: files[header].replace("  tos::ShardIdFull shard;",
                                                          "  const NativeAnchorCache* anchors;\n  tos::ShardIdFull shard;", 1)})
    for probe in probes:
        try:
            verify(probe)
        except ValueError:
            pass
        else:
            raise RuntimeError("consensus admission boundary negative control survived")

    try:
        verify(files)
    except ValueError as reason:
        print(f"CONSENSUS-ADMISSION-IS-NODE-LOCAL {reason}", file=sys.stderr)
        return 1

    # And nothing in the path reaches one another way. The sweep covers files
    # that are not in the index yet, because a caller written today is a caller.
    listing = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                             cwd=ROOT, capture_output=True, text=True, check=True)
    for path in ("validator/auth/native-registry-admission.cpp", "validator/auth/native-collation-authority.cpp"):
        if path not in listing.stdout.split():
            continue
        body = (ROOT / path).read_text()
        for token in NODE_LOCAL:
            if token in body:
                print(f"CONSENSUS-ADMISSION-REACHES {token} in {path}", file=sys.stderr)
                return 1

    print("PASS: admission decides from the parent state and the message, and names nothing a node holds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
