#!/usr/bin/env bash
set -euo pipefail

# Builds a configuration proposal that changes ConfigParam 16's min_validators.
#
# This exists because raising the stake factor requires raising the minimum
# validator set first, and the order is not interchangeable. The factor bounds
# how concentrated voting weight can get relative to the smallest set the
# configuration still permits:
#
#   raise min_validators first -> elections get stricter, weight stays capped
#   raise the factor first     -> a window where one entry can take half the
#                                 weight of a set the config still allows
#
# So this script is the first half of that sequence, and
# scripts/propose-stake-factor.sh refuses until it has been applied.
#
# It also refuses to propose a minimum the network cannot currently sustain.
# An election needs at least min_validators participants; set the floor at
# exactly the number of validators you have and a single absence -- maintenance,
# a funding gap, a validator whose stake is frozen from the previous round --
# fails the election, the set stops rotating, and everything that waits on a
# rotation waits indefinitely. Pooled stake is one of those things.
#
# Usage:
#   propose-validator-count.sh --state <state.boc> --min-validators 8 [--out <dir>]
#                              [--margin 2]

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FIFT_BIN=${FIFT_BIN:-"$REPO_ROOT/build/crypto/fift"}
PYTHON_BIN=${PYTHON_BIN:-"$REPO_ROOT/.venv/bin/python"}
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN=python3

STATE=""
MIN_VALIDATORS=""
OUT_DIR="."
# Absences the network should be able to absorb and still elect.
MARGIN=2

while [[ $# -gt 0 ]]; do
  case "$1" in
    --state) STATE=${2:?--state needs a path}; shift 2 ;;
    --min-validators) MIN_VALIDATORS=${2:?--min-validators needs a value}; shift 2 ;;
    --out) OUT_DIR=${2:?--out needs a path}; shift 2 ;;
    --margin) MARGIN=${2:?--margin needs a value}; shift 2 ;;
    -h|--help) sed -n '3,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$STATE" || -z "$MIN_VALIDATORS" ]]; then
  echo "usage: propose-validator-count.sh --state <state.boc> --min-validators <n> [--out <dir>] [--margin <n>]" >&2
  exit 2
fi
if [[ ! -x "$FIFT_BIN" ]]; then
  echo "required binary is unavailable: $FIFT_BIN" >&2
  exit 1
fi

read -r MAX_VALIDATORS MAX_MAIN CURRENT_MIN CURRENT_SET OLD_HASH < <(
  "$PYTHON_BIN" -c '
import sys
from pathlib import Path

repo = Path(sys.argv[1])
sys.path.insert(0, str(repo / "test/tostester/src"))
import importlib

boc = importlib.import_module("pytosiq_core.boc.deserialize")
core = importlib.import_module("pytosiq_core")
config_tlb = importlib.import_module("pytosiq_core.tlb.config")

root = boc.Boc(Path(sys.argv[2]).read_bytes()).deserialize()[0]
state = core.ShardStateUnsplit.deserialize(root.begin_parse())
config = state.custom.config.config

param16 = config_tlb.ConfigParam16.deserialize(config[16].copy())
current_set = 0
if 34 in config:
    current_set = config_tlb.ConfigParam34.deserialize(config[34].copy()).cur_validators.total

print(
    param16.max_validators,
    param16.max_main_validators,
    param16.min_validators,
    current_set,
    config[16].copy().to_cell().hash.hex(),
)
' "$REPO_ROOT" "$STATE"
)

echo "current ConfigParam 16 : max=$MAX_VALIDATORS main=$MAX_MAIN min=$CURRENT_MIN"
echo "current validator set  : $CURRENT_SET"
echo "proposed min_validators: $MIN_VALIDATORS (absences tolerated: $MARGIN)"

if (( MIN_VALIDATORS <= CURRENT_MIN )); then
  echo >&2
  echo "refusing: $MIN_VALIDATORS does not raise the current minimum of $CURRENT_MIN" >&2
  exit 1
fi

REQUIRED=$(( MIN_VALIDATORS + MARGIN ))
if (( CURRENT_SET < REQUIRED )); then
  echo >&2
  echo "refusing to propose a minimum the network cannot absorb an absence under" >&2
  echo "  a set of $MIN_VALIDATORS needs $REQUIRED validators to tolerate $MARGIN absences" >&2
  echo "  the current set has $CURRENT_SET" >&2
  echo >&2
  echo "An election short of the minimum simply fails. The current set then stays" >&2
  echo "in place and never rotates, and pooled stake cannot be recovered until it" >&2
  echo "does -- the recover guard counts rotations." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
VALUE_BASENAME="$OUT_DIR/config-param-16-min-$MIN_VALIDATORS"

FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" -s \
  "$REPO_ROOT/crypto/smartcont/build-validator-count-value.fif" \
  "$MAX_VALIDATORS" "$MAX_MAIN" "$MIN_VALIDATORS" "$VALUE_BASENAME"

# ConfigParam 16 is in the genesis critical_params set.
FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" -s \
  "$REPO_ROOT/crypto/smartcont/create-config-proposal.fif" \
  16 "${VALUE_BASENAME}.boc" -c -H "$OLD_HASH" \
  "$OUT_DIR/config-msg-body-validator-count.boc"

echo
echo "proposal built for min_validators=$MIN_VALIDATORS"
echo "  pinned previous value hash: $OLD_HASH"
echo "  message body: $OUT_DIR/config-msg-body-validator-count.boc"
echo
echo "Apply this before proposing a higher stake factor. Until it is installed,"
echo "scripts/propose-stake-factor.sh will keep refusing, because the factor is"
echo "bounded by the smallest set the configuration permits rather than by the"
echo "set that happens to be running."
