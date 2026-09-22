#!/usr/bin/env bash
set -euo pipefail

# A validator node must not be able to authorise a controller action.
#
# The offline-root split separated two secrets so that compromising the machine that validates costs an
# operator the key it can rotate and not the authority that rotates it. That separation
# is only real while the node cannot sign a controller authorisation -- not "does not",
# but cannot, because the code that would is not in it.
#
# So this checks the two things that would end it: the node linking the offline root
# library, and the node's own sources reaching for the root's header, loader, signer or
# signing context. A node that gains any of those has lost the boundary, and would have
# lost it silently: nothing else in the tree fails when a library is added to a link
# line.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
status=0

# The node's own code. validator-engine loads and installs the consensus key; everything
# under validator/ runs on the validating host.
NODE_PATHS=(validator-engine validator validator-session adnl overlay catchain)

# What only the offline domain may name.
ROOT_SYMBOLS=(
  "ValidatorControllerRootKeyStore"
  "controller-root-signer.h"
  "controller-root-file.h"
  "load_controller_root_key"
  "sign_controller_authorization"
  "controller_auth_context"
  "tos_pq_controller_root"
)

for symbol in "${ROOT_SYMBOLS[@]}"; do
  found=$(cd "$REPO_ROOT" && grep -rIl --fixed-strings "$symbol" "${NODE_PATHS[@]}" 2>/dev/null || true)
  if [[ -n "$found" ]]; then
    echo "a validator node names the controller root: $symbol" >&2
    printf '  %s\n' $found >&2
    status=1
  fi
done

# The link line itself. A library reached transitively is still linked, so this reads
# what CMake records rather than what a CMakeLists file appears to say.
ENGINE_LINKS=$(cd "$REPO_ROOT" && grep -rn "target_link_libraries(validator-engine" -A 6 \
  validator-engine/CMakeLists.txt CMakeLists.txt 2>/dev/null || true)
if grep -q "tos_pq_controller_root" <<<"$ENGINE_LINKS"; then
  echo "validator-engine links the offline controller-root library" >&2
  status=1
fi

# And the reverse: the offline library must not drag node code in, or "offline" would
# only describe where the file sits.
OFFLINE_SOURCES=(crypto/pq/controller-root-signer.cpp crypto/pq/controller-root-file.cpp
                 crypto/pq/controller-tool.cpp)
for source in "${OFFLINE_SOURCES[@]}"; do
  if [[ ! -f "$REPO_ROOT/$source" ]]; then
    echo "the offline controller-root domain is missing $source" >&2
    status=1
    continue
  fi
  if grep -qE '#include "(validator|adnl|overlay|catchain)/' "$REPO_ROOT/$source"; then
    echo "$source reaches into node code" >&2
    status=1
  fi
done

# The consensus key is authority too, and the node's surfaces that spend it are gated as
# such. A client permitted only to read the node must not be able to have it commit a
# stake or cast a vote.
ENGINE="$REPO_ROOT/validator-engine/validator-engine.cpp"
for query in createPqStakeAuthorization createProposalVote createComplaintVote; do
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
  echo "the node holds a consensus key and no way to authorise a controller"
fi

exit "$status"
