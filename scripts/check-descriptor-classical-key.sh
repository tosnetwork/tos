#!/usr/bin/env bash
# Keeps the inventory of classical-consensus-key readers honest.
#
# A post-quantum validator descriptor has no Ed25519 key, so every caller of
# classical_key() is either guarded against reaching one or is a site that has to be
# converted before post-quantum descriptors can be authoritative. The inventory lives in
# test/pq-native/classical-key-sites.tsv; this check fails when the tree and the
# inventory disagree in either direction, so neither a new caller nor a converted one
# can pass unnoticed.
set -euo pipefail

root="${1:-.}"
manifest="$root/test/pq-native/classical-key-sites.tsv"

if [ ! -f "$manifest" ]; then
  echo "classical-key check failed: missing inventory $manifest" >&2
  exit 1
fi

failed=0

# What the tree actually contains, one "path<TAB>count" line per file.
actual="$(grep -rc --include='*.cpp' --include='*.hpp' --include='*.h' 'classical_key()' "$root" \
  | grep -v ':0$' \
  | grep -v "$root/build/" \
  | sed "s|^$root/||" \
  | sed 's|:|\t|' \
  | sort)"

declared=""
while IFS=$'\t' read -r file sites _status _why; do
  case "$file" in ''|'#'*) continue ;; esac
  declared="$declared$file"$'\n'
  found="$(printf '%s\n' "$actual" | awk -F'\t' -v f="$file" '$1 == f { print $2 }')"
  if [ -z "$found" ]; then
    echo "classical-key check failed: $file no longer reads a classical key; update the inventory" >&2
    failed=1
  elif [ "$found" != "$sites" ]; then
    echo "classical-key check failed: $file has $found sites, inventory says $sites" >&2
    failed=1
  fi
done < "$manifest"

while IFS=$'\t' read -r file count; do
  [ -n "$file" ] || continue
  if ! printf '%s' "$declared" | grep -qxF "$file"; then
    echo "classical-key check failed: $file reads a classical key ($count sites) and is not in the inventory" >&2
    echo "  a post-quantum descriptor refuses; say in the inventory why this site is safe or when it is converted" >&2
    failed=1
  fi
done <<< "$actual"

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "classical-key inventory matches the tree"
if grep -q $'\taborts-on-pq\t' "$manifest"; then
  echo "classical-key check failed: aborts-on-pq inventory rows remain" >&2
  exit 1
fi
echo "classical-key inventory has no aborts-on-pq rows"
