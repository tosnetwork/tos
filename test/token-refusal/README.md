# Local-only receiver refusal fixture

This test build is not a token release. Its source generator is confined to this
test directory and writes only a new private directory outside the checkout whose
name contains `local-only-test`. It never regenerates a release BOC or edits a
release manifest. The production wallet source is SHA-256 pinned; drift refuses.

```sh
python3 test/token-refusal/build-local-only.py \
  --source-root "$TOS_ROOT" --output "$PRIVATE_STATE/local-only-test-build" \
  --global-id 3
python3 test/token-refusal/test_local_only.py
ctest --test-dir "$BUILD_DIR" -L source-guard --output-on-failure
```

The generated wallet has exactly two changes: every internal execution refuses
outside global id 3 (exit 1979), and `receive_reported_tokens` throws exit 1980
**after authenticating S** when its owner is the SHA-256 of
`LOCAL-ONLY-TEST-REFUSAL-RECIPIENT-v1`. Other recipients use the production path.
Ordinary funding transfers are unchanged. The refusal is a real R compute abort;
the network bounces to S, S restores its token balance and reports the refusal,
and the actor applies the normal returned-entry transition. No RPC response or
account state is replaced. The underlying bridge and minter remain unchanged.

The integration driver in the operations repository compiles the staged sources
into `local-only-test-*.fif`, derives an isolated bridge/minter namespace using
ConfigParam 81 and a synthetic test origin, and adds the resulting master and code
hashes through normal ConfigParam 84 governance. It preserves the existing asset
entry. ConfigParam 84 has no label field: its source-token bytes visibly spell
`LOCAL_ONLY_TEST_REFU`; the independent pins/evidence use
`LOCAL-ONLY-TEST-REFUSAL-v1`. Synthetic oracle-authorized supply is test data,
not a lock-backed asset. It must never be offered as a release asset.

A separate actor uses the unchanged pinned test actor code, these independently
pinned wallet/minter/bridge hashes, and the normal recognition checks. A caller
claims its refund to the rejecting recipient, proves the returned entry, then
claims that entry to a normal recipient. The actor's 30-day return window is not
shortened: a sweep stays pending until finalized chain time reaches its deadline.

Upstream comparison: this token settlement test has no corresponding code in
upstream; inherited VM and message delivery code are unchanged.
