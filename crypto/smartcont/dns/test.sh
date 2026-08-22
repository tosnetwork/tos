#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
if [ -x "$REPO_ROOT/build/crypto/func" ] && [ -x "$REPO_ROOT/build/crypto/fift" ]; then
  PATH="$REPO_ROOT/build/crypto:$PATH"
fi
if [ -z "${FIFTPATH:-}" ]; then
  FIFTPATH="$REPO_ROOT/crypto/fift/lib:$REPO_ROOT/crypto/smartcont"
fi
export PATH FIFTPATH
cd "$SCRIPT_DIR"

node test/root.js &&
node test/collection.js &&
node test/collection-config.js &&
#node test/collection-get.js &&
node test/item.js &&
node test/item-already-init.js &&
node test/item-bid.js &&
node test/item-bid-prolong.js &&
node test/item-config.js &&
#node test/item-config-transfer.js &&
node test/item-delete-record.js &&
node test/item-edit-record.js &&
node test/item-fill-up.js &&
node test/item-finish-auction-change-content.js &&
node test/item-get.js &&
node test/item-get-static-data.js &&
node test/item-loss.js &&
node test/item-transfer.js &&
echo "OK"
