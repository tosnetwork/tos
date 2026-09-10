# Additional domain scan: decision pending

No allowlist change was made. All 83 diagnostics concern Uno outside approved
paths: 31 exact diagnostic source lines already occur at a27ff2c77; 52 are new
or rewritten. This is an exact-line comparison, not a claim that 52 independent
mechanisms were added. The scanner itself is unchanged from that baseline.

The 14 concrete paths are:

- `crypto/block/create-state.cpp`
- `crypto/smartcont/gen-zerostate.fif`
- `crypto/smartcont/uno-genesis-config.fif`
- `crypto/smartcont/uno-genesis-operators.fif`
- `scripts/setup-testnet.sh`
- `test/tostester/src/tostester/zerostate.py`
- `test/uno-local-network-config.fif`
- `test/uno-local-profile.md`
- `test/uno-local-profile.py`
- `test/uno-setup-preflight-controls.py`
- `test/workchain-descriptor-controls.py`
- `test/workchain-descriptor-equivalence.md`
- `test/workchain-descriptor-equivalence.py`
- `test/workchain-genesis-operator-controls.py`

The bounded proposed follow-up would admit Uno for only these concrete paths,
retain every other domain/retired-symbol check, and test each path with a
single independent-copy insertion of another forbidden identifier. This proposal
has not been applied; it is separate from the 138 registered regression cases.
