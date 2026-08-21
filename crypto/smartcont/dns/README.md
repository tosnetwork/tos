# TOS DNS Smart Contracts

Smart contracts of the `.tos` zone, vendored in-tree at
`crypto/smartcont/dns/` and ported from the upstream reference DNS contracts
at pinned commit `d08131031fb659d2826cccc417ddd9b98476f814` with **zero
semantic divergence** in the auction, renewal, release, and resolution state
machine. The upstream repository identity and parity rules are recorded in
`doc/tos-blockchain/DNS.md` §6.1 (in `tosnetwork/doc`); this directory is
the sole home of the `.tos` contracts.

## Contracts

- `func/root-dns.fc` — `.tos` root resolver (masterchain, immutable). Serves a
  single zone and stores one delegated resolver address. This is the only
  source-level adaptation: the upstream root compiles its suffix literals into
  code, so a `.tos` root is necessarily a source change.
- `func/nft-collection.fc` — `.tos` Collection / TLD resolver and domain
  minter. **Unchanged from upstream.**
- `func/nft-item.fc` — Domain Item with built-in open ascending auction,
  renewal (`last_fill_up_time`), and 366-day release. **Unchanged from
  upstream.**
- `func/dns-utils.fc` — shared helpers. One change: `auction_start_time` moved
  to `func/tos-config.fc` so the launch-timestamp decision is explicit.
- `func/tos-config.fc` — the single TOS deployment decision (launch
  timestamp). The committed value is a localnet/test placeholder; mainnet
  requires the governance-approved value (DNS.md §6.6).

Item index is `slice_hash` (TVM `HASHSU`) of the label slice and is out of
order; `get_collection_data` always returns `next_item_index = -1`.

## Building

Requires `func` and `fift` from a TOS build tree (all paths relative to
this directory, `crypto/smartcont/dns/`):

```sh
export PATH="<repo>/build/crypto:$PATH"
export FIFTPATH="$(pwd)/../../fift/lib"
cd func && sh compile.sh
```

`test/funcer.js` is adapted to the TOS fift library naming (`TosUtil.fif`,
`Tomi,` instead of the upstream `TonUtil.fif`, `Gram,`); both use the same
1e9 base-unit scale, so the adaptation changes no test semantics.

## Testing

```sh
./run-tests.sh
```

The script locates the enclosing source tree automatically and expects the
toolchain in `<repo>/build`; override with `TOS_SRC`/`TOS_BUILD` if your
build directory lives elsewhere. It runs the vendored upstream suite (root, collection, item: bids, prolongation,
records, transfer, fill-up, loss, finish, config/governance) against the TOS
toolchain. `test/root.js` is adapted to the single `.tos` zone and additionally
asserts that foreign suffixes (`.ton`, `.t.me`) and prefix-sharing labels
(`tosx`) do **not** resolve. `test/utils.js` `AUCTION_START_TIME` must equal
`func/tos-config.fc`'s `auction_start_time`.

The item-code BOC embedded in `test/utils.js` `makeStorageCollection` is the
compiled output of `func/nft-item.fc`, used as collection storage in tests;
after any item-code change, regenerate it from the
`func/build/nft-item-code.boc` written by `deploy/gen-deploy.fif`.

## Deployment artifacts

Run from this directory with `FIFTPATH` set as in the build step:

```sh
fift -s deploy/gen-deploy.fif [<collection-content-url>]
```

Prints the code hashes and the deterministic Collection (basechain) and Root
(masterchain) addresses, and writes StateInit BOCs under `func/build/`. The
printed root address is the value a ConfigParam 4 proposal must carry; the
code hashes are what the reproducible-build record must pin.

## Upstream parity

Before every release, re-compare against the upstream repository's `main`
branch (pinned in `doc/tos-blockchain/DNS.md` §6.1) and account for every
source difference. The intended full diff is:

| File | Difference |
|---|---|
| `func/root-dns.fc` | single `.tos` zone (source adaptation, same semantics) |
| `func/dns-utils.fc` | `auction_start_time` moved to `tos-config.fc` |
| `func/tos-config.fc` | new; deployment decision only |
| `func/compile.sh`, `deploy/`, `test/funcer.js`, `test/root.js`, `test/utils.js` | toolchain, deployment, and zone adaptation |

Anything beyond this list is a semantic fork and requires its own TIP, review,
and vectors.
