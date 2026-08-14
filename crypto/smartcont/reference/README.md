# Third-party contract references (read-only)

Upstream TON mainnet contracts, vendored **verbatim for study only**. They are NOT
TOS contracts, are NOT part of any build target (the CMake `GenFif` targets name our
own sources explicitly; nothing here is compiled or deployed), and their original
copyright and license headers are preserved unchanged. Do not edit these files in
place — if we adapt any idea, we write a fresh TOS-owned contract under
`crypto/smartcont/` and cite the idea, not the code.

## Contents

### `usdt-jetton-master/` — the contract USDT-on-TON is based on
- Upstream: `ton-blockchain/stablecoin-contract`
- Pinned commit: `5a3b500267b0bdfc6505a08e5ac661c805cab8b0` (branch `main`)
- License: **MIT** (© TON Core) — see `usdt-jetton-master/LICENSE`
- Primary file: `contracts/jetton-minter.fc` (the jetton master / minter), plus its
  wallet (`jetton-wallet.fc`) and includes (`jetton-utils.fc`, `op-codes.fc`,
  `gas.fc`, `workchain.fc`, `stdlib.fc`, `helpers/librarian.func`) and the TL-B
  schema `jetton.tlb`. TEP-74 (jetton) + TEP-89 (discovery) compatible, with the
  centralised-stablecoin admin ops (mint, force-transfer, burn, lock/unlock wallet).
  Tether's live USDT master on TON is a deployment of this code.

### `stonfi-dex-router/` — STON.fi DEX v1 router
- Upstream: `ston-fi/dex-core`
- Pinned tag: `v1.0.0` (the release matching the deployed STON.fi v1 router)
- License: **GPL-3.0** — see `stonfi-dex-router/LICENSE`
- Primary file: `contracts/router.func` (the swap router entrypoint), plus its
  `router/*` modules (op / params / errors / storage / getters / admin-calls / utils)
  and shared `common/*` includes. The router's counterpart contracts in the same
  repo — `pool.func`, `lp_account.func`, `lp_wallet.func` and their submodules — were
  not vendored here; pull them from the upstream tag if the full AMM is needed.

## License compatibility

TOS is licensed GPL-3.0 (repo root `LICENSE`). Both references are compatible:
MIT is GPL-3-compatible, and STON.fi's GPL-3.0 matches TOS's own license. If any of
this code (especially the GPL-3.0 STON.fi router) is ever incorporated rather than
merely studied, the GPL-3.0 obligations and upstream attribution must be carried
through — treat that as a deliberate, reviewed decision, not an accident of it living
in this tree.
