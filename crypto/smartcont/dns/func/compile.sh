#!/bin/sh
# Compile the .tos DNS contracts.
#
# Requires `func` and `fift` on PATH (e.g. from a TOS build tree:
#   export PATH="<repo>/build/crypto:$PATH")
# and FIFTPATH pointing at the fift library:
#   export FIFTPATH="$(pwd)/../../../fift/lib"
set -e

rm -f build/nft-item-code.fif
rm -f build/nft-collection-code.fif
rm -f build/root-dns-code.fif

func -o build/nft-item-code.fif -SPA stdlib.fc params.fc op-codes.fc tos-config.fc dns-utils.fc nft-item.fc
func -o build/nft-collection-code.fif -SPA stdlib.fc params.fc op-codes.fc tos-config.fc dns-utils.fc nft-collection.fc
func -o build/root-dns-code.fif -SPA stdlib.fc tos-config.fc dns-utils.fc root-dns.fc

fift -s build/print-hex.fif
