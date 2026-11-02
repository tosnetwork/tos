# Offline public-testnet pilot scope controls

The provider README describes the explicit build/runtime opt-in and live gates.
The recipe in `../evidence/testnet-pilot-guards-20261101.json` freezes the core,
exact eight replacement anchors and per-case commands. The adjacent runtime
failure file contains bounded actual failure sections; compilation errors do not
count. `pilot_mutations.py` requires a NEW absolute `--scratch`, NEW private
`--out` outside source trees and an absolute `--target-dir`. It creates only its
own detached worktree, restores each mutation in finally, then restores27 native
tests in both builds plus the CLI suite and removes its clean worktree without
force. On toserver wrap it in the existing thermal guard and keep new worktrees
under `/tos/worktrees`. No custody/configuration/chain is mutated by this runner.

Provisioning controls create ephemeral fresh keys in private temporary directories
and sign an offline wallet envelope. They never fund or send. The check proves
that release, Bond and signed wallet use the selected global ID while subwallet3
remains independent; unsupported networks refuse before creating custody. Python
controls cover opt-in, mode/network and CLI forwarding. CLI forwarding mocks only
the downstream call and is not native/public readiness evidence.

Public receipts/runner remain in normal Git history without scheduled expiry.
Raw logs indexed in `testnet-pilot-preparation-20261101.json` remain private on
toserver through at least2027-02-01 UTC, retrievable by existing authorized SSH.
No new/public access or credentials are granted. No live keys, status tokens,
payloads or SQL blobs are committed. Public-chain provisioning, funding,
activation, transfer and production approval remain unexecuted by these controls.
