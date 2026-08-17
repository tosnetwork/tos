#!/usr/bin/env bash
set -euo pipefail

# Builds a configuration proposal that changes ConfigParam 17's max_stake_factor,
# and refuses to build one that would let a single validator stall consensus.
#
# The factor caps effective stake at a multiple of the smallest elected stake,
# so it decides how concentrated voting weight can get. What binds is not how
# many validators happen to be active today but how small a set the config still
# permits -- ConfigParam 16's min_validators -- because the Elector may install
# exactly that many in a future round. Raising the factor therefore usually has
# to follow a raise of min_validators, not accompany it.
#
# Usage:
#   propose-stake-factor.sh --state <state.boc> --factor 3 [--out <dir>]
#
# The state BOC supplies the stake limits that are carried over unchanged and
# the value hash the proposal pins. Fetch it from a node before proposing so the
# proposal is built against what the chain actually has.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FIFT_BIN=${FIFT_BIN:-"$REPO_ROOT/build/crypto/fift"}
PYTHON_BIN=${PYTHON_BIN:-"$REPO_ROOT/.venv/bin/python"}
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN=python3

STATE=""
FACTOR=""
OUT_DIR="."
MIN_VALIDATORS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --state) STATE=${2:?--state needs a path}; shift 2 ;;
    --factor) FACTOR=${2:?--factor needs a value}; shift 2 ;;
    --out) OUT_DIR=${2:?--out needs a path}; shift 2 ;;
    --min-validators) MIN_VALIDATORS=${2:?--min-validators needs a value}; shift 2 ;;
    -h|--help) sed -n '3,22p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$STATE" || -z "$FACTOR" ]]; then
  echo "usage: propose-stake-factor.sh --state <state.boc> --factor <value> [--out <dir>]" >&2
  exit 2
fi
if [[ ! -x "$FIFT_BIN" ]]; then
  echo "required binary is unavailable: $FIFT_BIN" >&2
  exit 1
fi

CHECK_ARGS=(--zerostate "$STATE" --factor "$FACTOR")
if [[ -n "$MIN_VALIDATORS" ]]; then
  CHECK_ARGS+=(--validators "$MIN_VALIDATORS")
fi

# The gate. A failing check is the whole point of this wrapper: it stops an
# unsafe factor from ever being turned into a signable proposal.
if ! VERDICT=$("$PYTHON_BIN" "$REPO_ROOT/scripts/check-stake-factor-safety.py" "${CHECK_ARGS[@]}" --json); then
  echo "refusing to build a proposal for an unsafe stake factor" >&2
  echo >&2
  "$PYTHON_BIN" "$REPO_ROOT/scripts/check-stake-factor-safety.py" "${CHECK_ARGS[@]}" >&2 || true
  exit 1
fi

read -r MIN_STAKE MAX_STAKE MIN_TOTAL FACTOR_SCALED OLD_HASH < <(
  printf '%s' "$VERDICT" | "$PYTHON_BIN" -c '
import json
import sys

data = json.load(sys.stdin)
print(
    data["min_stake"],
    data["max_stake"],
    data["min_total_stake"],
    data["proposed_max_stake_factor"],
    data["current_value_hash"],
)
'
)

mkdir -p "$OUT_DIR"
VALUE_BASENAME="$OUT_DIR/config-param-17-factor-$FACTOR_SCALED"

FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" -s \
  "$REPO_ROOT/crypto/smartcont/build-stake-limits-value.fif" \
  "$MIN_STAKE" "$MAX_STAKE" "$MIN_TOTAL" "$FACTOR_SCALED" "$VALUE_BASENAME"

# ConfigParam 17 is listed in the genesis critical_params set, so the proposal
# has to be a critical one to be votable at all.
FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" -s \
  "$REPO_ROOT/crypto/smartcont/create-config-proposal.fif" \
  17 "${VALUE_BASENAME}.boc" -c -H "$OLD_HASH" \
  "$OUT_DIR/config-msg-body-stake-factor.boc"

echo
echo "proposal built for max_stake_factor=$FACTOR_SCALED (1/65536 units)"
echo "  pinned previous value hash: $OLD_HASH"
echo "  message body: $OUT_DIR/config-msg-body-stake-factor.boc"
echo
echo "Send it from the wallet that will pay the proposal deposit, then have the"
echo "current validator set vote on it. Nothing about pooled stake changes until"
echo "the new value is installed."
