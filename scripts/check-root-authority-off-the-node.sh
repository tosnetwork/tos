#!/usr/bin/env bash
set -euo pipefail

# A validator node spends its consensus key only for the account it answers for.
#
# The elector names a member by the account that sends its stake, and the node signs the
# stake over that account's address. A node that signed for any account it was asked
# about would let a client elect a validator under someone else's identity, so the
# signing surfaces are gated as authority and the stake creator refuses every account
# but the node's configured validator id. Each of these fails silently when lost: nothing
# else in the tree breaks when a gate or a comparison is removed.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
status=0

# The consensus key is authority, and the node's surfaces that spend it are gated as
# such. A client permitted only to read the node must not be able to have it commit a
# stake, cast a vote, or change which consensus keys the node signs with.
ENGINE="$REPO_ROOT/validator-engine/validator-engine.cpp"
for query in createPqStakeAuthorization createPqStakeAuthorizationWithKey addPqConsensusKey delPqConsensusKey \
    createProposalVote createComplaintVote; do
  handler=$(awk -v q="engine_validator_${query} &query" '
    index($0, q) { grab = 1 }
    grab { print }
    grab && /vep_/ { exit }
  ' "$ENGINE")
  if [[ -z "$handler" ]]; then
    echo "no control handler found for $query" >&2
    status=1
  elif ! grep -q "vep_modify" <<<"$handler"; then
    echo "$query is not gated on vep_modify, and it signs with the consensus key" >&2
    status=1
  fi
done

# A stake is how a node enters a validator set, so the creator that signs one must not
# require membership in one. The lookup it may use resolves configured identity and
# custodied key and nothing about any set.
CREATOR=$(awk '
  /^class PqStakeAuthorizationCreator/ { grab = 1 }
  grab { print }
  grab && /^};/ { exit }
' "$ENGINE")
if [[ -z "$CREATOR" ]]; then
  echo "the stake authorisation creator is missing" >&2
  status=1
elif grep -q "get_current_validator" <<<"$CREATOR"; then
  echo "the stake authorisation creator consults the current validator set: a node could never sign its first stake" >&2
  status=1
elif ! grep -q "get_local_pq_identity" <<<"$CREATOR"; then
  echo "the stake authorisation creator does not resolve the node's local identity" >&2
  status=1
fi

# The signed preimage carries the sending account, and the node signs only for its own.
if [[ -n "$CREATOR" ]]; then
  if ! grep -q "src_addr_ != self.validator_id.value" <<<"$CREATOR"; then
    echo "the stake authorisation creator signs for an account other than the node's validator id" >&2
    status=1
  fi
  if ! grep -qE "sign_stake_authorization\([^;]*[ ,(]src_addr_[,)][^;]*;" <<<"$(tr -d '\n' <<<"$CREATOR")"; then
    echo "the stake authorisation creator does not sign over the sending account" >&2
    status=1
  fi
fi

# The node and the operator tool must sign a stake through the one shared routine, so the
# path a review can run and the path a real validator takes cannot diverge. The creator
# delegates to it and assembles no preimage of its own; a bespoke stake_preimage call here
# would be a second, untested road back. The tool must reach the same routine.
if [[ -n "$CREATOR" ]]; then
  if ! grep -q "sign_stake_authorization" <<<"$CREATOR"; then
    echo "the stake authorisation creator does not use the shared sign_stake_authorization routine" >&2
    status=1
  fi
  if grep -q "stake_preimage" <<<"$CREATOR"; then
    echo "the stake authorisation creator assembles its own stake preimage instead of using the shared routine" >&2
    status=1
  fi
fi
TOOL="$REPO_ROOT/crypto/pq/vote-tool.cpp"
if [[ ! -f "$TOOL" ]]; then
  echo "the operator vote/stake tool is missing" >&2
  status=1
elif ! grep -q "sign_stake_authorization" "$TOOL"; then
  echo "the operator tool signs a stake by a route other than the shared sign_stake_authorization" >&2
  status=1
fi

# The node must still be able to load its own consensus key: a boundary that removed
# both halves would pass every check above and leave a validator unable to sign.
if ! grep -q "load_consensus_key" "$REPO_ROOT/validator-engine/validator-engine.cpp"; then
  echo "validator-engine no longer loads a consensus key at all" >&2
  status=1
fi

if [[ "$status" -eq 0 ]]; then
  echo "the node signs stakes and votes only through gated surfaces, and only for its own validator id"
fi

exit "$status"
