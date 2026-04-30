# Slice 3 NFT Walkthrough

Generate a project:

```sh
tol new --pattern nft --name MyCollection --output my-nft
```

The scaffold imports `@stdlib/nft`, derives NFT item state-init/address
from the collection address and item code, and builds the deploy message
with the same raw StateInit/body placement covered by the Stage 4 tests.

Use the generated opcode and replay artifacts as the starting point for
collection-specific mint and transfer cases.
