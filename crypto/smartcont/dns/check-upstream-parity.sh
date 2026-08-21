#!/bin/sh
# Upstream-parity check for the .tos DNS contracts (design rule: zero
# semantic divergence; see doc/tos-blockchain/DNS.md §6.1).
#
# Fetches the upstream reference repository and verifies:
#   1. nft-item.fc, nft-collection.fc, op-codes.fc, params.fc are
#      byte-identical to the pinned upstream commit;
#   2. dns-utils.fc differs from upstream ONLY by the extraction of
#      auction_start_time into tos-config.fc;
#   3. upstream main has not moved past the pinned commit — new upstream
#      commits require an explicit review before release.
#
# Exit codes: 0 = parity holds and upstream is unchanged; 1 = drift in a
# byte-identical file or an unreviewed dns-utils.fc difference; 2 = upstream
# main has new commits to review; 3 = environment/network failure.
#
# Usage: ./check-upstream-parity.sh [<upstream-git-url>]
set -eu

UPSTREAM_URL="${1:-https://github.com/ton-blockchain/dns-contract.git}"
PINNED_COMMIT="d08131031fb659d2826cccc417ddd9b98476f814"
HERE="$(cd "$(dirname "$0")" && pwd)"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM

if ! git clone --quiet "$UPSTREAM_URL" "$WORKDIR/upstream" 2>/dev/null; then
  echo "FAIL: cannot clone upstream $UPSTREAM_URL" >&2
  exit 3
fi

UP="$WORKDIR/upstream"
UPSTREAM_HEAD="$(git -C "$UP" rev-parse origin/main)"

if ! git -C "$UP" cat-file -e "$PINNED_COMMIT" 2>/dev/null; then
  echo "FAIL: pinned commit $PINNED_COMMIT not found upstream" >&2
  exit 3
fi
git -C "$UP" checkout --quiet "$PINNED_COMMIT"

status=0

# 1. byte-identical files
for f in nft-item.fc nft-collection.fc op-codes.fc params.fc; do
  if cmp -s "$HERE/func/$f" "$UP/func/$f"; then
    echo "OK   func/$f is byte-identical to the pinned upstream commit"
  else
    echo "DRIFT func/$f differs from the pinned upstream commit:" >&2
    diff -u "$UP/func/$f" "$HERE/func/$f" >&2 || true
    status=1
  fi
done

# 2. dns-utils.fc: the only allowed difference is replacing the
#    auction_start_time constant line with the pointer comment.
if diff -u "$UP/func/dns-utils.fc" "$HERE/func/dns-utils.fc" \
    | grep '^[-+][^-+]' \
    | grep -v 'auction_start_time' >/dev/null; then
  echo "DRIFT func/dns-utils.fc has differences beyond the auction_start_time extraction:" >&2
  diff -u "$UP/func/dns-utils.fc" "$HERE/func/dns-utils.fc" >&2 || true
  status=1
else
  echo "OK   func/dns-utils.fc differs only by the auction_start_time extraction"
fi

echo "NOTE func/root-dns.fc is an intentional single-zone adaptation (reviewed source change)"
echo "NOTE func/tos-config.fc is TOS deployment configuration (no upstream counterpart)"

# 3. upstream movement
if [ "$UPSTREAM_HEAD" != "$PINNED_COMMIT" ]; then
  echo "REVIEW upstream main is at $UPSTREAM_HEAD (pinned: $PINNED_COMMIT):" >&2
  git -C "$UP" log --oneline "$PINNED_COMMIT..$UPSTREAM_HEAD" >&2 || true
  echo "REVIEW classify each upstream change (security/compatibility/economics/tooling) before release" >&2
  [ "$status" -eq 0 ] && status=2
else
  echo "OK   upstream main is exactly the pinned commit"
fi

exit "$status"
