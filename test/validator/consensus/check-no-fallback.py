#!/usr/bin/env python3
"""The consensus layer must have no way back to the classical primitives.

Two of the no-fallback invariants are properties of the source, not of any run, and a
runtime test cannot see either of them. A seam that built a legacy block signature set
and then threw it away would satisfy every end-to-end assertion while doing exactly what
the seam forbids; and a keyring signature that is produced but discarded leaves nothing
for a test to observe either. So both are checked where they exist: in the code.

The third invariant in that list -- that a transport identity is never derived from a
post-quantum public key -- is checked here too, and the first attempt to argue it did not
need checking was wrong. `block::validator_adnl_identity` being the single accessor is a
property of today's bridge, not something any registered test holds in place: the harness
builds its PeerValidators directly, so a bridge that derived an ADNL id from
`el.pq_public_key` would pass every runtime gate. The rule below is the name that catches
it -- a post-quantum key may be touched only where the consensus key is filled.

N5 replaces the refusal with a post-quantum carrier and will need the first rule below to
name that one instead.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONSENSUS = ROOT / "validator" / "consensus"

RULES = [
    (
        re.compile(r"BlockSignatureSet::(create(?!_simplex_pq_)\w*|fetch)"),
        "constructs a legacy block signature set",
        None,
    ),
    (
        # The keyring signs for the transport plane. Consensus signs with the custodied
        # post-quantum store and nothing else.
        re.compile(r"\bsign_message\b|\bsign_messages\b|\bsign_add_get_public_key\b"),
        "asks the keyring to sign",
        None,
    ),
    (
        # A post-quantum key is consensus authority and nothing else. The one place the
        # consensus layer may touch a descriptor's post-quantum key is where it fills the
        # consensus key; anywhere else -- an ADNL id, a transport key hash -- would be
        # deriving a transport identity from it, which is the invariant this rule holds.
        re.compile(r"\bpq_public_key\b"),
        "uses a post-quantum public key away from the consensus key",
        re.compile(r"consensus_key"),
    ),
    (
        # No classical key type reaches the consensus layer at all, so a field or a local
        # that could hold one is a regression regardless of what it is named.
        re.compile(r"\bEd25519_PublicKey\b|\bpubkeys::Ed25519\b"),
        "names a classical public key type",
        None,
    ),
]


def main() -> int:
    if not CONSENSUS.is_dir():
        sys.exit(f"consensus sources not found at {CONSENSUS}")
    offenders = []
    scanned = 0
    for path in sorted(CONSENSUS.rglob("*")):
        if path.suffix not in (".cpp", ".h", ".hpp"):
            continue
        scanned += 1
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            for pattern, what, allowed_with in RULES:
                if not pattern.search(line):
                    continue
                # A rule may name a companion that makes the use legitimate, so the rule
                # can forbid a misuse without forbidding the one correct use.
                if allowed_with is not None and allowed_with.search(line):
                    continue
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {what}: {line.strip()}")
    if scanned == 0:
        sys.exit("scanned no consensus sources; the guard is not looking at anything")
    if offenders:
        print("the consensus layer has a path back to the classical primitives:", file=sys.stderr)
        for offender in offenders:
            print("  " + offender, file=sys.stderr)
        return 1
    print(f"OK: {scanned} consensus sources, {len(RULES)} no-fallback rules, no offenders")
    return 0


if __name__ == "__main__":
    sys.exit(main())
