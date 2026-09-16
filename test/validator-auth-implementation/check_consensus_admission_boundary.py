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
boundary written down, in three parts: these names may not appear in the
functions that decide admission, those headers may not even reach a node-local
one, and nothing may decide before the assembler at the seams that call it.

The third part is the one a clean signature does not give you. An assembler that
takes only block facts is still bypassed by a caller that asks a cache whether
to call it at all -- the signature stays perfect and the producer goes back to
being node-local. So the seams are pinned by shape: exactly one decision stands
between entering the seam and reaching the assembler, and it is the declared
precondition.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# What may not appear in the consensus admission path.
NODE_LOCAL = ("NativeAnchorCache", "NativeHistoryResolutionQueue", "NativeBlockReader", "resolve_declared_history")
# Reaching one of those types is enough, even unused: an include is how the next
# caller finds out the option exists.
NODE_LOCAL_HEADERS = ("native-anchor-cache.h", "native-history-queue.h")

# The declarations that decide admission. Their signatures are the boundary.
DECIDING = {
    "validator/auth/native-registry-admission.h": "admit_registry_message",
    "validator/auth/native-collation-authority.h": "assemble_registry_authority",
}
# And the structure the assembler is handed.
INPUTS = ("validator/auth/native-collation-authority.h", "CollationAuthorityInputs")

# The seams that call the assembler. Each must reach it with one decision made:
# the declared precondition, which reads only what the caller already holds.
# Production and validation are both here because the bypass is the same on
# either side, and a gate in front of only one of them is exactly the divergence
# the whole path exists to prevent.
SEAMS = {"validator/impl/collator.cpp": "Collator::offer_validator_auth",
         "validator/impl/validate-query.cpp": "ValidateQuery::offer_validator_auth"}
ASSEMBLER = "assemble_registry_authority("


def declaration(text: str, name: str) -> str:
    match = re.search(re.escape(name) + r"\s*\([^;]*\);", text)
    return match.group(0) if match else ""


def structure(text: str, name: str) -> str:
    start = text.find(f"struct {name}")
    return text[start:text.index("};", start)] if start >= 0 else ""


def approach(text: str, name: str) -> str:
    """Everything between entering the seam and reaching the assembler."""
    start = text.find(f"bool {name}(")
    if start < 0:
        return ""
    opened = text.find("{", start)
    call = text.find(ASSEMBLER, opened)
    if opened < 0 or call < 0:
        return ""
    body = text[opened + 1:call]
    # Comments are prose, not decisions, and this counts decisions.
    return re.sub(r"//[^\n]*", "", body)


def verify(files: dict[str, str]) -> None:
    for path, name in DECIDING.items():
        signature = declaration(files[path], name)
        if not signature:
            raise ValueError(f"{name} is not declared in {path}")
        for token in NODE_LOCAL:
            if token in signature:
                raise ValueError(f"{name} accepts {token}")
        for header in NODE_LOCAL_HEADERS:
            if f'#include "{header}"' in files[path]:
                raise ValueError(f"{path} includes {header}")
    fields = structure(files[INPUTS[0]], INPUTS[1])
    if not fields:
        raise ValueError(f"{INPUTS[1]} is not declared")
    for token in NODE_LOCAL:
        if token in fields:
            raise ValueError(f"{INPUTS[1]} carries {token}")
    for path, name in SEAMS.items():
        body = approach(files[path], name)
        if not body:
            raise ValueError(f"{name} does not reach the assembler in {path}")
        decisions = len(re.findall(r"\bif\s*\(", body))
        refusals = len(re.findall(r"\breturn\s+false\s*;", body))
        if decisions != 1 or refusals != 1:
            raise ValueError(f"{name} makes {decisions} decisions and {refusals} refusals before the assembler")


def main() -> int:
    paths = {*DECIDING, INPUTS[0], *SEAMS}
    files = {path: (ROOT / path).read_text() for path in paths}

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
    probes += [{**files, path: '#include "native-anchor-cache.h"\n' + files[path]} for path in DECIDING]
    for path in SEAMS:
        # The bypass this part exists for: the assembler is untouched and a
        # cache decides whether it is reached. Nothing in a signature sees this.
        probes.append({**files, path: files[path].replace(
            f"  auto admitted = tos::auth::{ASSEMBLER}",
            "  if (!manager_cache_has_required_history(msg_root)) {\n    return false;\n  }\n"
            f"  auto admitted = tos::auth::{ASSEMBLER}", 1)})
        # And the two halves of that shape on their own, so a violation is not
        # recognised only when it arrives in the exact form imagined here.
        probes.append({**files, path: files[path].replace(
            f"  auto admitted = tos::auth::{ASSEMBLER}",
            f"  if (deferred_)\n    ;\n  auto admitted = tos::auth::{ASSEMBLER}", 1)})
        probes.append({**files, path: files[path].replace(
            f"  auto admitted = tos::auth::{ASSEMBLER}",
            f"  return false;\n  auto admitted = tos::auth::{ASSEMBLER}", 1)})
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

    print(f"PASS: admission decides from the parent state and the message, names nothing a node holds, "
          f"and {len(SEAMS)} calling seams reach it undecided")
    return 0


if __name__ == "__main__":
    sys.exit(main())
