# Retired shielded-pool components

These files are historical evidence, not a supported engine or an optional
production implementation. No active CMake target includes this directory.
Their original include paths are intentionally preserved as historical bytes;
the archive is not directly buildable in the current tree. For reproduction,
use the original recorded source commit, or the pre-removal tree `0b120a07d`.

Archived together: the note/frontier/anchor state, permanent spent set and refund
reservations, wide note accounting and bundle permissions, old slot scheduling,
their tests and public-context vectors, and the retired state-partition measurement drivers. The archived
wide-amount helpers expose note/bundle conversion semantics and had no active
V2 caller, so they were not presented as V2 accounting infrastructure.

The current model uses per-address encrypted balances and does not use these
structures. Its cryptographic verifier and separate wallet prover remain in
`uno/crypto` and `uno/prover`. Neither the archive nor this cleanup establishes
live host acceptance, privacy beyond hidden amounts, or a capacity guarantee.

Native storage/import/restart tests remain active. Their plain empty-value
dictionary fixture lives only under `crypto/test`; it conveys no spend, asset,
ownership or production account-state semantics. Historical measurement tables
are retained, but are not measurements of the V2 account layout.
