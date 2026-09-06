# Third audit: state codec fixes

This disposition covers Y-3 and B5-3 only. It does not modify the single-account
host contract, choose the Y-1/Y-2 architecture, or implement B3-1 preflight.

## Y-3: bound the standalone codec and contain builder failures

AnchorWindow construction and loading reject capacity above the Cell depth
limit (currently 1024), independently of a larger caller resource limit. This
is the standalone linked-list codec limit, not a production window setting:
the header's depth equals the number of roots, and enclosing wrappers consume
additional depth. Full executor admission/resource policy still needs to bound
the entire representation before accepting a configuration or new obligation.

All four UNO state `to_cell` boundaries now catch CellBuilder's CellWriteError
and CellCreateError separately from the existing VM exceptions and return a
Status. No catch-all converts allocation failures or arbitrary local exceptions
into consensus rejection. Higher-level classification remains a separate issue.

Tests demonstrate:

- Capacity 1025 is rejected both at genesis and while loading an otherwise
  valid one-root state; a full 1024-root standalone window round-trips and rolls.
- Windows of sizes 1022, 1023 and 1024 distinguish standalone, NoteState and
  PrivateTransferState depth boundaries. An oversized enclosing representation
  returns Error instead of allowing CellWriteError to escape.
- Injecting either builder exception at every creation point in each of the
  four encoders returns Error, leaves the source unchanged and permits retry.

Before the fix, the capacity rejection test failed, the real enclosing-depth
test terminated with CellWriteError, and the injection test terminated with
CellCreateError. Those failures were observed on the unchanged implementation,
not inferred from error strings. Valid small-window encodings are unchanged.

## B5-3: exact flags/reference correspondence

The nullifier-root envelope now requires its reference count to equal the
number of set bits in its three presence flags before consuming any optional
root. A missing reference can no longer be interpreted as an empty dictionary.

The negative fixture uses an empty valid tree/nullifier state so later count
and accounting invariants cannot reject it incidentally. All seven nonzero
flag masks with zero refs must fail; zero flags/no refs must round-trip to the
original canonical hash. Before the fix the nonzero case was accepted. Existing
joint-root restoration tests retain positive cases with real nonempty roots.

## Evidence and remaining scope

After rebuilding, the state/anchor suite passed 17 tests. CTest passed
`test-uno-tree-cell` and the real-proof `test-uno-crypto-abi-real` fixture.
Pre-fix logs are `build/uno-third-anchor-before.log`,
`build/uno-third-depth-before.log`, `build/uno-third-builders-before.log`, and
`build/uno-third-roots-before.log`; the restored state suite log is
`build/uno-third-nullifier-regression.log`.

This fixes codec acceptance and exception escape, not growing-state liveness,
storage pricing, production configuration selection, or the separate tree ABI
local-failure/invalid-input classification. B3-1 remains open until structural
and semantic preflight is wired and exercised before expensive replay work.
