#!/usr/bin/env bash
# Keeps the removed validator-authority paths removed.
#
# The post-quantum cutover deleted several ways to exercise validator authority: the
# classical stake operation, the classical validator-vote operations, the unilateral
# administrator, and the proposal that appointed one. Each was deleted rather than
# refused by name, which means nothing in the contracts announces their return. A
# reintroduction would be a working authority path with no test against it, because the
# tests that covered them were inverted into proofs of their absence.
#
# So the check is on the source: each pattern below must not appear in the files that
# decide validator authority. An inventory of allowed exceptions would be a way to add
# one back quietly, so there is none.
set -euo pipefail

root="${1:-.}"
failed=0

# file<TAB>pattern<TAB>what it would mean
while IFS=$'\t' read -r file pattern meaning; do
  case "$file" in ''|'#'*) continue ;; esac
  path="$root/$file"
  if [ ! -f "$path" ]; then
    echo "authority check failed: $file is missing, so this check no longer checks it" >&2
    failed=1
    continue
  fi
  if grep -q -- "$pattern" "$path"; then
    echo "authority check failed: $file contains '$pattern' -- $meaning" >&2
    failed=1
  fi
done <<'SITES'
crypto/smartcont/elector-code.fc	0x4e73744b	the classical stake operation is back
crypto/smartcont/elector-code.fc	0x56744370	the classical complaint-vote operation is back
crypto/smartcont/elector-code.fc	check_data_signature	the elector authorises something with Ed25519 again
crypto/smartcont/config-code.fc	0x566f7465	the classical configuration-vote operation is back
crypto/smartcont/config-code.fc	check_data_signature	the config contract authorises something with Ed25519 again
crypto/smartcont/config-code.fc	check_signature	the config contract authorises something with Ed25519 again
crypto/smartcont/config-code.fc	0x43665021	the administrator can change a parameter again
crypto/smartcont/config-code.fc	0x50624b21	the administrator key can be replaced again, so there is one
crypto/smartcont/config-code.fc	0x4e43ef05	the administrator can replace the elector code again
crypto/fift/lib/Validator.fif	566f7465	a script builds the classical configuration vote again
crypto/fift/lib/Validator.fif	566f7445	a script builds the classical internal configuration vote again
crypto/fift/lib/Validator.fif	56744350	a script builds the classical complaint-vote request again
crypto/fift/lib/Validator.fif	56744370	a script builds the classical complaint-vote body again
crypto/fift/lib/Validator.fif	4e436f64	a script builds the administrator's code replacement again
tosctl/src/node-control/contracts/src/elector/messages.rs	0x56744350	the tooling builds the classical complaint-vote request again
tosctl/src/node-control/contracts/src/elector/messages.rs	0x56744370	the tooling builds the classical complaint-vote body again
tosctl/src/node-control/contracts/src/config_contract/messages.rs	0x566f7465	the tooling builds the classical configuration vote again
SITES

# The scripts that produced those messages. A validator's vote is signed with a
# post-quantum key over a preimage that names the validator set counting it, which a
# script has no way to learn, so a file here is either a vote nothing accepts or a way
# to sign one outside the node that holds the key.
while read -r file; do
  case "$file" in ''|'#'*) continue ;; esac
  if [ -e "$root/$file" ]; then
    echo "authority check failed: $file exists again -- a removed authority has tooling" >&2
    failed=1
  fi
done <<'GONE'
crypto/smartcont/config-proposal-vote-req.fif
crypto/smartcont/config-proposal-vote-signed.fif
crypto/smartcont/complaint-vote-req.fif
crypto/smartcont/complaint-vote-signed.fif
crypto/smartcont/update-config-smc.fif
crypto/smartcont/update-elector-smc.fif
GONE

# The node builds its own votes. Running a script to do it would mean the signed bytes
# have a second definition, and the one the contract verifies would be whichever the
# node happened to run. (The election-bid path still runs a script; it produces a stake
# request the elector no longer accepts, and it is not this check's subject.)
engine="$root/validator-engine/validator-engine.cpp"
for script in config-proposal-vote-req config-proposal-vote-signed complaint-vote-req complaint-vote-signed; do
  if grep -q -- "$script" "$engine"; then
    echo "authority check failed: validator-engine.cpp runs $script.fif again" >&2
    failed=1
  fi
done
# The node produced a stake by generating Ed25519 keys and running a Fift script. It
# cannot produce one at all now: a stake is placed by a controller account, authorised by
# a root key that never reaches a validator host. What it produces is the signature the
# elector checks, over one tuple it was asked to agree to.
for gone in 'ValidatorElectionBidCreator' 'validator-elect-req.fif' 'createElectionBid'; do
  if grep -q -- "$gone" "$engine"; then
    echo "authority check failed: validator-engine.cpp has $gone again -- the node builds a stake" >&2
    failed=1
  fi
done
if ! grep -q -- 'PqStakeAuthorizationCreator' "$engine"; then
  echo "authority check failed: validator-engine.cpp no longer signs a stake authorisation" >&2
  failed=1
fi

for builder in 'block::pq::config_vote_body' 'block::pq::complaint_vote_body'; do
  if ! grep -q -- "$builder" "$engine"; then
    echo "authority check failed: validator-engine.cpp no longer builds its vote with $builder" >&2
    failed=1
  fi
done

# The operator tooling builds the same two votes. An Ed25519 signature is 64 bytes, so a
# builder that takes one is a builder for the authority that was removed.
while IFS=$'\t' read -r file expected meaning; do
  case "$file" in ''|'#'*) continue ;; esac
  if ! grep -q -- "$expected" "$root/$file"; then
    echo "authority check failed: $file no longer builds $expected -- $meaning" >&2
    failed=1
  fi
done <<'BUILDERS'
tosctl/src/node-control/contracts/src/elector/messages.rs	0x5051636f	the post-quantum complaint vote
tosctl/src/node-control/contracts/src/config_contract/messages.rs	0x5051766f	the post-quantum configuration vote
BUILDERS

# The external entry point exists only to refuse. A body that does anything else is an
# external authority path, whatever it is called.
external="$(awk '/^\(\) recv_external/,/^}/' "$root/crypto/smartcont/config-code.fc")"
if ! printf '%s' "$external" | grep -q 'throw(32);'; then
  echo "authority check failed: recv_external no longer refuses outright" >&2
  failed=1
fi
if printf '%s' "$external" | grep -q 'accept_message'; then
  echo "authority check failed: recv_external accepts a message, so it does something" >&2
  failed=1
fi

# The proposal that appointed an administrator is refused by a rule, not by a name, so
# there is nothing here to grep for: renaming the constant would satisfy a source check
# while the rule stayed gone. It is held instead by an elector-sandbox test that votes
# such a proposal through and requires it not to take effect, and by the mutation that
# removes the refusal and requires that test to go red.

if [ "$failed" -eq 0 ]; then
  echo "no removed validator-authority path has returned"
fi
exit "$failed"
