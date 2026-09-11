# Sequence expiry replacement contract

Specification: memo 19d0446e, SHA256
71968ef2afb0d9176e6e73dfa8aa5366efecdd0d1d9c82028e3de9ee0d2b84c6.
This is a prospective test contract, not host execution evidence.

The first non-Deposit issuer expires B's inventory. Do not refresh its snapshot
alone. A's statement/prepare guard has a different lifetime: retain it until
Native prepare has an authenticated account/pending-cut mutation test. Settlement
is allowed to install backed pending; prepare is not.

## Executable arrival procedure

The existing default CTest expiry diagnostic points here. At that failure run:

```
python3 crypto/test/workchain-system-sequence-handoff.py --build BUILD_DIRECTORY
```

The runner fails if any of the six named tests below is absent or disabled;
it never substitutes synthetic states for a missing host adapter. Register them
in default CTest when their real adapters exist. The runner alone is not an
oracle and cannot certify what a named test actually does. Review their bodies.
Do not retire the inventory until all contracts and their mutation evidence are
installed in the same change. If only Failed is available, retain an explicit
expiry trigger for the still absent sweep producer rather than declaring all
three sources covered. Do not invent a sweep implementation for these tests.

## Fixture and observations shared by all six tests

Extend the actual Native registered-engine fixture reached through
`crypto/test/workchain-m3-node-engine.h`, using Deposit transition setup in
`crypto/test/workchain-deposit-transition-test.h` as the existing source adapter.
Use A's committed custody Failed and type-2 sweep entrypoints once delivered;
their function names are not yet prescribed by this contract. No direct codec
writer or hand-built effects list may stand in for those producers.

Construct authenticated coordinator/account roots, an associated open Attempt,
and a valid type-2 bucket entry. Fees, limits and reserve come from explicit test
configuration, including the unfrozen D70 issuance tariff; do not infer tariff
units from proof-work units. Choose positive post-fee amounts and enough slots.
Failed receives a real authenticated bounced envelope at custody. Keep the
coordinator Deposit rejection of bounced messages intact.

Read the committed coordinator sequence and independently enumerate/decode the
full authenticated account/pending dictionary after each commit. Inspect all
origin variants and both counters, not only proposed effects. Preserve an
unselected sentinel entry byte-for-byte. Trace issuance order at actual staged
state handoffs. Record validator acceptance separately from producer output.
Count actual installed receipts, not operations: one operation may issue more
than one receipt. All increments and fixture arithmetic are checked.

## Exact successor tests

| CTest suffix (prefix `test-workchain-system-sequence-host-`) | Required execution and oracle |
| --- | --- |
| `staged` | Starting at authenticated sequence n, execute Deposit, Failed issuance and sweep in one supported atomic batch, in each supported source order. For actual issuance number j require decoded origin sequence checked(n+j); final coordinator sequence checked(n+k), k actual receipts. Require all new keys unique across user/system pending and their source identities correct; retained sentinel unchanged. If the scheduler forbids an order, demonstrate that restriction rather than simulating the order. Repeat at UINT64_MAX to verify rejection/nonpublication, never wrap. |
| `competing` | From the same authenticated predecessor construct two actual producer candidates that each propose n+1. Individually validate against that predecessor. Attempt to combine their stale successors at the real batch validator/install boundary. Require no committed batch with both receipts and only one increment. Then reconstruct the second against staged state and require n+2. Do not fabricate matching counter expectations from either candidate's effects. |
| `nonpublication` | For every available issuer execute an admission rejection and a permitted no-receipt outcome, plus failure after preparation but before batch installation. Read committed roots: no receipt and no sequence increment for that event. Other normal rejection effects (bounce, bucket or fees) need not be unchanged. In a successful mixed batch containing a no-receipt event, only actual receipts consume increments. In an aborted batch, none of its staged increments is installed. |
| `stale-read-control` | In an isolated source copy make the second real issuer read the original coordinator counter instead of the staged successor. Compile and reach that issuer. The staged/competing oracle must fail specifically on reused sequence or publication inconsistency. A build error or earlier unrelated admission error is not the expected red. Restore and require green. |
| `publish-control` | In isolated copies (a) omit sequence installation on successful issuance and (b) publish an increment on rejection/no-receipt. Each must reach the corresponding committed-state observation and fail its sequence/receipt pairing assertion. Restore and require green. Cover both directions, not just the no-receipt case. |
| `oracle-control` | Disable the pairing assertions in the isolated test oracle while retaining the preceding producer mutations. The mutation driver itself must fail because its expected red disappears. This checks that a failing setup is not masquerading as the sequencing oracle. |

Each mutation CTest passes only when its driver observed the designated failure
and restored green. Log source commit, mutation location, assertion diagnostic,
exit status and restored result. Missing executable, skip or unsupported producer
is incomplete, never a passing mutation. CTest test names are a contract, not
permission to register placeholders that return success.

## Current evidence and limits

The handoff runner currently exits 1 with HANDOFF_NOT_READY because real successor
tests are not registered. That proves missing implementation is visible; it does
not prove any of the host invariants above. The existing expiry inventory and
its original controls remain active and unchanged in scope and predicates.
Behavioral checks cover the observed state slice and executed paths; they do not
prove absence of every unobserved side effect.
