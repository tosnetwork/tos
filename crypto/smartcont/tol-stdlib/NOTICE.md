# Third-party notices for tol-stdlib and its FunC counterparts

This file records where stdlib modules come from when that is not the TOS
project itself, and how each was produced. Every Tol module listed here has a
FunC counterpart in `crypto/smartcont/` with the same rules and throw codes
(and, where a module stores state, the same cell layout), tested against the
same vector matrix in
`crypto/func/auto-tests/tests/lib-*.fc`; provenance applies to both.

## Adapted from MIT-licensed sources

Each module below re-implements the mechanism of the listed upstream file.
The code was rewritten rather than transliterated, the FunC counterparts
included: the upstream audits cover the upstream FunC, not these modules. The
TOS tests (`tol-tester/tests/stdlib-*-positive.tol` and
`crypto/func/auto-tests/tests/lib-*.fc`) are what establish the behavior
here.

| Modules | Upstream | Path | Commit | License |
|---|---|---|---|---|
| `jetton-fees.tol`, `../jetton-fees.fc` | `ton-blockchain/stablecoin-contract` | `contracts/gas.fc` | `5a3b500267b0bdfc6505a08e5ac661c805cab8b0` | MIT |
| `replay-guard.tol`, `../replay-guard.fc` | `ton-blockchain/highload-wallet-contract-v3` | `contracts/highload-wallet-v3.func` | `f5d9b592bd5ab5c9ae6ca627819929e140f6bd61` | MIT |

How each module differs from its upstream:

- `jetton-fees.tol` does not carry the upstream gas and size constants. They
  measure the upstream wallet build, so each TOS wallet build has to supply
  its own measured `JettonFeeProfile`. A profile with any zero field is
  rejected. Insufficient value is reported with the existing
  `@stdlib/jetton` throw codes, so `jettonWalletErrorForFuncThrow` maps it
  unchanged.
- `replay-guard.tol` rejects query ids whose bit index is 1023. Upstream
  leaves that case to a cell-overflow exception. The current time is read
  from the block rather than passed in by the caller.

### MIT license texts

`ton-blockchain/stablecoin-contract`:

```
MIT License

Copyright (c) 2025 TON Core

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

`ton-blockchain/highload-wallet-contract-v3`:

```
MIT License

Copyright (c) 2024 TON - The Open Network

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Independent implementations

`ordered-delivery`, `quorum-signatures` and `multisig-order`, in both their
`.tol` and `.fc` forms, contain no third-party code. They implement general mechanisms: a bounded
out-of-order completion window, M-of-N Ed25519 authorization, and
one-contract-per-proposal multisig. Their data layouts, interfaces, opcodes
and error codes are TOS's own.

Two implementations of similar mechanisms were studied while designing these
modules. Their code was deliberately not copied, because neither can be
included in TOS:

- A cross-chain messaging endpoint under a source-available business
  license. It permits only non-production use before its change date, and
  its restrictions extend to derivative works.
- A per-proposal multisig implementation that publishes no license.

Published security reviews of those implementations were used only to pick
the failure cases these modules must reject. The tests cover each such case:

- A verifier set replaced by one smaller than the quorum.
- A slot read or overwritten under a nonce that merely shares its index.
- An execution admitted under a signer set or threshold that has since
  changed.

Do not paste code from either source into these modules. Before reusing
anything from them, check its license again.
