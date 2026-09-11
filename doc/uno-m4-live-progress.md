# M4 live sequence: partial acceptance

The nine-step successful sequence passed on 2026-09-11 using the real local
collator and validator actors under test-constructed authenticated parameters.
This is not closure of the full M4 acceptance checklist. In particular, the
test node engine still lacks the rejected-Deposit settlement connection; its
placeholder is not a valid protocol rejection result.

Commands:

```
cargo build --manifest-path uno/prover/Cargo.toml --example m3-scenario --release --locked --offline --target-dir build-m3-host/m3-vector-wallet-target
cmake --build build-m3-host --target test-m3-live -j3
python3 test/uno-m3-live.py --build build-m3-host --m4
```

The last command exited 0. Authenticated static base=2, slot_fee=3000000,
send_tip=5, collect_tip=7; each Deposit principal was 1000000000. These are
explicit test parameters, not an assertion of production readiness or dynamic
D28 pricing. Billing units are SEND=1 and COLLECT=3, independently of proof work.

| Step | Observed available | Paired engine proof units |
| --- | --- | --- |
| Register A | A=0 | 433 / 433 |
| Register B | B=0 | 433 / 433 |
| Deposit #1 to A | A=0, one system receipt | 7 / 7 |
| Deposit #2 to A | A=0, two system receipts | 7 / 7 |
| A COLLECT #1 | A=999999987 | 2639 / 2639 |
| A COLLECT #2 | A=1999999974 | 2639 / 2639 |
| A SEND to B | A=0, principal=1996999967 | 2649 / 2649 |
| B COLLECT | B=1996999954 | 2639 / 2639 |
| Close A | A=0, closed; B unchanged | 441 / 441 |

Every step was paired with the same-path disabled run: identified phase=3,
zero execution, zero transactions, no candidate export. All nine enabled
blocks were accepted. The assertion helper reads serialized block inputs;
the retained system receipt is compared by its complete record hash and is
subsequently consumed by COLLECT #2. Test wallet expectations are never node
replay inputs.

Final block:
`(2,8000000000000000,9):014B01B4BE77C815A7BF1A29C010E76809F1213135BE2C60EF9A4ECAD264EBDA:92050F68C75D54BA235986A88F1EE6789AC8453CF33E3B2F22312059D779A9BC`.
Its collation took 20.741 ms and validation 9.407 ms; these are single samples,
not throughput measurements. Actual masterchain imports contain 13 for each
COLLECT and 7 for SEND. SEND moves S=3000000 to the coordinator; its F=3000007.
Final custody and liability totals both equal 1996999954.

A read-only inspection of the accepted final state reports registered_accounts=2,
A system/user slots=0/0, B system/user slots=0/0, and coordinator Native
balance=11008999900. D/P/W are zero by the implemented atomic operation set;
they are not three separately stored counters being read from the state.
Reading each actual Block.value_flow gives fees_collected of
21567, 21567, 4341, 4341, 13, 13, 7, 13, 33: total 51895 across the nine wc=2
blocks, excluding source wc=0 and masterchain blocks. These include Native
components and must not be inferred from the D32 tariff alone.

The block-loop checks include nonzero R mismatch, nonzero cross-block D, and
an unpaired confidential fee debit, followed by restored successful checks.
Test keys decrypt available and pending, directly measuring N_hidden for this
sequence. Production has no such aggregate decryption capability:
N_book=N_hidden is conditional on cryptographic and state-machine correctness,
not independently publicly numerically auditable. These observations establish
only this finite sequence in this implementation.

The earlier failure after integrating system receipts was a test search bound:
a receipt's pre-fee amount exceeded the post-fee available used as the bound.
Increasing that finite test-wallet bound does not relax the balance equality
or any node validation rule. Neither earlier failed run counts as acceptance.

The effective minimum Native message value is V_min+slot_fee, not V_min.
Exact equality means an in-flight fee change causes rejection and bounce,
with repeated bounce cost an operational tradeoff. M3's 100:1 fixture cannot
admit a Deposit because its V_max is below V_min; this M4 fixture uses the
specification's 1:1 balance/value bound.

Retirement condition for M3 test funding: remove that test operation and its
allowlisted call sites only after the complete M4 checklist passes, the M3
regression scenario runs using real Deposit instead, and the funding removal
is itself tested with default-off guards unchanged. This successful sequence
alone does not satisfy that condition.

No claim is made of consensus security, cryptographic correctness, production
usability, capacity or hardware sufficiency, multi-node execution, M5 support,
or audited supply-chain dependencies. Closure materializes a one-way historical
deposit refund message; delivery is not guaranteed and recipient credit is not
asserted. D45 remains in effect; production activation is unchanged.
