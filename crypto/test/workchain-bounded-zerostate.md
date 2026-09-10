# Bounded resource-policy fixture

`workchain-bounded-zerostate.boc` is a required input of the default
`test-workchain-validator-local-visitors` CTest. Do not delete it while that test
references it. Regenerate with `test/workchain-resource-fixture.py`, providing
current `create-state`, repository and fresh output paths; copy the generated
zerostate only after checking its policy fields and issued ledger.

This is a development network (global ID -23901), generated through production
genesis and shared issuance with fixed public test validators and time 1789434000.
It has no production credentials. Block-preflight allowance 1 and thresholds 0/2/2 are provisional;
the mainnet resource allowlist remains closed. This fixture exercises prepared
local decisions, not a live validator or account-batch execution.

The former input under doc/measurements/uno-local-profile/run-3 remains immutable
historical evidence for the previous policy constructor. The Rust McStateExtra
fixture is extracted from this new zerostate without changing its fields.

Current fixture SHA256: `894f9a606a0fe092d9719caad2df751dd2d6123d8a706b6d2b3d22171f19f30c`.
The root policy tag is `f37fed2f`, with explicit allowance 1 and limits 0/2/2.
