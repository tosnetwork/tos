# Shared Native destination review disposition

Base: bf1f7e434. Transcript:
`~/memo/reviews/uno-v2-native-destination-review.txt`.

The reviewer compared both 114-line bodies: the only algorithmic substitution
is account.addr becoming the explicit sender argument. Both ordinary call sites
still use the member wrapper and pass account.addr. The shared function does
not extend ingress policy or implement multi-account disposal.

## Findings

1. Fixed: re-test the anycast destination after changing the permitted address
   to its matching zero address. The earlier mismatched-address case could not
   distinguish the dedicated anycast rejection from the later address check.
2. Deferred typed precondition; disputed CHECK remedy. The exported function
   still requires a resolved nonnull workchain table. Adding CHECK would replace
   an invalid access with process termination, not source-aware LocalUnavailable
   or ConfigInvalid handling. No new batch caller is installed here. Its future
   boundary must make resolved configuration a type-level precondition before
   calling this function; a null local table must never become protocol false.
   This prerequisite remains open, not a claim that a comment enforces safety.
3. Deferred coverage: invalid variable lengths and variable-address repacking
   outside addr_std remain unchanged paths without new dedicated witnesses.
   The extraction is not complete Native routing validation coverage.

The existing actual send fixture now initializes both MsgPrices explicitly to
zero. That repairs indeterminate fixture inputs without creating any production
default. No amount computation is added by the extraction. Cell and allocation
exceptions remain uncaught here and require the enclosing source-aware boundary.

Rebuilt manual controls and restored regression are recorded in
`measurements/uno-v2-native-destination-evidence.json`; they are not recurring
mutation CI. M1 remains incomplete.

All three rebuilt controls (anycast ingress, anycast permission, sender prefix)
fail after the expected test starts. Restored five-target regression passes
(35.12 seconds), and the actual sender fixture passes with explicit prices.
