#!/usr/bin/env bash
# Check out the conformance vectors repository at the commit pinned in VECTORS:
#     test/conformance/fetch-vectors.sh <destination>
# then configure with -DCONFORMANCE_VECTORS_DIR=<destination>. The repository is private; the caller
# needs read access (git credentials or a deploy key).
set -euo pipefail
dest=${1:?usage: fetch-vectors.sh <destination>}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
read -r repository commit < <(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["repository"], d["commit"])' "$here/VECTORS")
if [ ! -d "$dest/.git" ]; then
  git clone --quiet --no-checkout "$repository" "$dest"
fi
git -C "$dest" fetch --quiet origin "$commit"
git -C "$dest" checkout --quiet --detach "$commit"
python3 "$here/runner/vectors_pin.py" check "$dest"
