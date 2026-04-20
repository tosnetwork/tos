# plonky3-uno — vendored Plonky3 for the Uno workchain (wc=2)

This directory holds a vendored copy of [Polygon
Plonky3](https://github.com/Plonky3/Plonky3) pinned for the TOS Uno
workchain's `uno_plonky3_ffi` crate.

## Pin

- **Upstream commit**: `6374a36ff50fc641821513852263cc61ca7a1278`
- **Upstream tag (closest)**: `v0.5.1`
- **Vendored on**: 2026-04-20
- **Vendoring method**: `git subtree add --prefix=third-party/plonky3-uno
  https://github.com/Plonky3/Plonky3.git 6374a36f --squash`

## Rationale

Per `doc/uno-workchain.md` §16 decision #43: Plonky3 is not yet published
to crates.io, so a git-rev pin requires network at first build. Vendoring
the pinned state as a subtree

- isolates us from upstream API churn,
- gives auditors a stable in-repo artifact to review,
- lets reproducible offline builds work without the upstream git host.

## Update policy

- **Security fixes** — cherry-pick with explicit subtree-pull or direct
  patch. Every pull must be audited before it lands.
- **Feature / API churn** — we do **not** auto-track. Breaking changes
  require a deliberate decision, a documented migration, and a bump of
  the vendor pin above.
- **Upgrade to crates.io** — switch to versioned `crates.io` dependencies
  once Plonky3 publishes a 0.6.x (or later) release line suitable for our
  use; retire this vendor tree at that point.

## Consumers

- `uno/plonky3-ffi/Cargo.toml` points at these crates via `path =
  "../../third-party/plonky3-uno/<crate-name>"`.
- No other TOS subsystem consumes Plonky3; wc=0 (TVM) and wc=1 (EVM) do
  not link against this tree.

## License

Plonky3 ships under dual Apache-2.0 / MIT; see `LICENSE-APACHE` and
`LICENSE-MIT` in this directory. TOS consumes the code under Apache-2.0.
