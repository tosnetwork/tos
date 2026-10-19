#!/usr/bin/env sh
# One participant's whole part in the phase-2 ceremony.
#
# Build the contributor from source at the commit the ceremony published, run
# it, and produce a signed attestation. Nothing else.
#
#   ./scripts/shielded-pool-phase2-contribute.sh <ceremony-dir> \
#       [--sign-with gpg:<key-id> | ssh:<private-key-file>] \
#       [--entropy-file <path>]
#
# WHY IT BUILDS RATHER THAN SHIPPING A BINARY
#
#   Your contribution is worth something only if your scalar was destroyed,
#   and that is a property of source you can read -- not of a binary somebody
#   handed you. If you run a binary I built, the thing you are attesting to is
#   my honesty, which is exactly what your participation was supposed to
#   remove. So this builds, and you should read two short files first:
#
#       tools/shielded-pool-ceremony/src/secret.rs     (~110 lines)
#       tools/shielded-pool-ceremony/src/entropy.rs    (~170 lines)
#
#   They are the whole of the discipline. The scalar is drawn from
#   /dev/urandom inside contribute(), used, and wiped; it is not a return
#   value, not a parameter, and cannot be printed -- Secret has no Display and
#   its Debug prints only a placeholder.
#
# SIGNING IDENTITY
#
# Supply an existing or newly generated signing key with --sign-with. Publish
# its public half under your identity and register it before your contribution
# is accepted. Registration remains open during the contribution window. The
# script does not generate a key or publish identity evidence on your behalf.
#
# WHAT TOUCHES YOUR DISK
#
#   The ceremony directory, which is public and carries no secret, and the
#   attestation, which you are about to publish. Nothing else.

set -eu

usage() {
    echo "usage: $0 <ceremony-dir> [--sign-with gpg:<key-id>|ssh:<key-file>] [--entropy-file <path>]" >&2
    exit 2
}

CEREMONY=""
SIGN_WITH=""
ENTROPY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --sign-with) [ $# -ge 2 ] || usage; SIGN_WITH="$2"; shift 2 ;;
        --entropy-file) [ $# -ge 2 ] || usage; ENTROPY="$2"; shift 2 ;;
        --*) echo "unknown option $1" >&2; usage ;;
        *) [ -z "$CEREMONY" ] || usage; CEREMONY="$1"; shift ;;
    esac
done
[ -n "$CEREMONY" ] || usage
[ -d "$CEREMONY" ] || { echo "no such ceremony directory: $CEREMONY" >&2; exit 1; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CRATE="$ROOT/tools/shielded-pool-ceremony"

# --- 1. what you are about to build -------------------------------------
#
# Compare this against the commit the ceremony published. If it differs you
# are contributing with different code from everyone else, which is not
# automatically an attack and is automatically worth stopping to ask about.
COMMIT=$(git -C "$ROOT" rev-parse HEAD)
echo "building from $COMMIT"
if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
    echo
    echo "WARNING: this checkout has uncommitted changes, so '$COMMIT' does not" >&2
    echo "describe what is about to be built. Stash or reset before contributing." >&2
    exit 1
fi

# --- 2. build, from source ----------------------------------------------
( cd "$CRATE" && cargo build --release --bin phase2-contribute )
BIN="$CRATE/target/release/phase2-contribute"
[ -x "$BIN" ] || { echo "the contributor did not build" >&2; exit 1; }

# --- 3. contribute -------------------------------------------------------
#
# Not captured into a variable and echoed later: it prints progress for two
# minutes and you should see it happen. The two digests are read back from
# the ceremony record afterwards, which is where they are authoritative.
echo
if [ -n "$ENTROPY" ]; then
    [ -r "$ENTROPY" ] || { echo "cannot read entropy file: $ENTROPY" >&2; exit 1; }
    "$BIN" "$CEREMONY" --entropy-file "$ENTROPY"
else
    "$BIN" "$CEREMONY"
fi

# --- 4. the attestation --------------------------------------------------
RECORD="$CEREMONY/ceremony.json"
[ -r "$RECORD" ] || { echo "no ceremony.json after contributing" >&2; exit 1; }

# The last entry is the one just added. Read with python rather than a regex
# so a reordered or reformatted record cannot be misread as agreement.
DIGESTS=$(python3 - "$RECORD" <<'PY'
import json, sys
record = json.load(open(sys.argv[1]))
entry = record["entries"][-1]
if entry["kind"] != "participant":
    sys.exit(f'the last step is a {entry["kind"]}, not a contribution')
print(entry["index"], entry["sha256"], entry["transcript_after"],
      record["starting_key_sha256"])
PY
)
INDEX=$(echo "$DIGESTS" | cut -d' ' -f1)
CONTRIBUTION=$(echo "$DIGESTS" | cut -d' ' -f2)
TRANSCRIPT=$(echo "$DIGESTS" | cut -d' ' -f3)
STARTING=$(echo "$DIGESTS" | cut -d' ' -f4)

# The four digests are the whole of what is verifiable here; the prose around
# them is yours to change. `test/shielded-pool/verify-attestations.py` reads
# them by label and compares each against the record, so a document naming a
# contribution the chain does not contain, or naming the right one at the
# wrong index, is refused rather than filed.
ATTESTATION="$CEREMONY/../attestation-$INDEX.txt"
cat > "$ATTESTATION" <<ATTEST
TOS shielded pool, phase 2 -- contribution $INDEX

I drew a scalar from my machine's random generator, applied it, and destroyed
it. I did not record it, copy it, or transmit it, and I do not have it.

  built from     $COMMIT
  starting key   $STARTING
  contribution   $CONTRIBUTION
  transcript     $TRANSCRIPT

The starting key says which ceremony this is: it is a function of the circuit
and the phase-1 slice, so a contribution cannot be moved to a ceremony over a
different circuit. The transcript names my position within it: every later
contribution's challenge is derived from it, so this record cannot be
reordered, shortened or substituted without invalidating what follows.
ATTEST

echo
echo "attestation written to $ATTESTATION"

# --- 5. sign it, with your registered key ------------------------
case "$SIGN_WITH" in
    "")
        echo
        echo "NOT SIGNED. Pass --sign-with gpg:<key-id> or ssh:<private-key-file>," 
        echo "or publish the text above from an account that is already publicly"
        echo "yours -- the identity has to come from somewhere, and this script"
        echo "will not invent one for you."
        ;;
    gpg:*)
        KEY=${SIGN_WITH#gpg:}
        gpg --local-user "$KEY" --clearsign --output "$ATTESTATION.asc" "$ATTESTATION"
        echo "signed with GPG key $KEY -> $ATTESTATION.asc"
        ;;
    ssh:*)
        KEY=${SIGN_WITH#ssh:}
        [ -r "$KEY" ] || { echo "cannot read ssh key: $KEY" >&2; exit 1; }
        ssh-keygen -Y sign -f "$KEY" -n file "$ATTESTATION"
        echo "signed with SSH key $KEY -> $ATTESTATION.sig"
        ;;
    *)
        echo "--sign-with must be gpg:<key-id> or ssh:<private-key-file>" >&2
        exit 2
        ;;
esac

echo
echo "Publish the attestation, then hand the ceremony directory to the next"
echo "participant. It is about 6 MB and carries no secret, so any transport"
echo "will do."
echo
echo "Nothing on this machine holds your scalar. It existed only in the"
echo "contributor's memory and was wiped; there is no file to shred. Swap, if"
echo "this host has any, is yours to think about."
