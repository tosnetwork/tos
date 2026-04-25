#!/usr/bin/env bash
# Pack core source code into ~/tos.zip for external security audit.
# Uses git archive (excludes .gitignore'd / untracked files), then drops
# vendored / non-source top-level dirs we don't want audited.
set -euo pipefail

REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
OUT="${OUT:-$HOME/tos.zip}"

EXCLUDE_DIRS=(
  third-party
  tosctl
  doc
)

cd "$REPO_ROOT"

rm -f "$OUT"
git archive --format=zip -o "$OUT" --prefix=tos/ HEAD

for d in "${EXCLUDE_DIRS[@]}"; do
  zip -q -d "$OUT" "tos/$d/*" || true
done

echo "Excluded: ${EXCLUDE_DIRS[*]}"
ls -lh "$OUT"
