# D78 version-separated vectors

Normative anchor: memo f3f3b0d7, SHA256 prefix ad40640086c95b78.
Old samples were generated with prelock codec source at 2e2738c79 before the new
codec was exercised. They are fixtures, not deployed accounts. `old-prelock/`
retains data/record/control/full-account BOCs: v2 rejects all four, with no dual-read.
Original M3 SEND/COLLECT vectors and historical measurement sources are untouched.

`no-prelock-v2/` has freshly generated data/record/control BOCs for x=100,q=4,f=11,
and separate real-proof vectors for x=137,q=17,f=11, old available=10000. The latter
use six explicit test balance points, domain [42;80], IDs [7;32]/[8;32] and the
synthetic ABI host-context [42;566]. They are not a Native authorization fixture.
T=154, debit=165. No reserve exists; f is separate from T.

The real proof vector was generated once with the wallet prover's normal entropy
and is verified on subsequent runs. The constructor's deterministic points and
statement context must match the frozen bytes. Only explicit
`UNO_D78_CREATE_VECTORS=1 cargo test --manifest-path uno/prover/Cargo.toml --locked
--offline withdrawal_dedicated_abi_real_proof -- --nocapture` permits generation;
create_new prevents overwriting an existing vector. Never set that variable to
repair a failed equality. C++ exact roundtrip tests bind the three new BOCs.

Independent measurements: C++ encoded host context=566; Rust full statement
context=684. The host context carries hashes, not inline amounts. Its metering
length stays unchanged. Statement tag is `uno-v2/withdrawal-statement/v2`.
Inherited live runs are pre-D78 evidence. These new vectors/checks do not certify
host fee authorization, Native payout/bucket/Paid integration or deployment.
