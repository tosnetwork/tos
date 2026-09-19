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
SITES

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
