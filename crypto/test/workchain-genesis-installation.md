# Genesis installation draft

The production generator now constructs an empty wc=2 shard, saves its root and
file hashes, and commits them in the complete creation descriptor. Its basic
descriptor flags are `0xc000`: basic=1, active=1, accept_msgs=0, and thirteen
reserved zero bits. No masterchain root is needed to construct the identity.
Network separation assumes distinct global IDs for distinct networks.

Version 16 and capBlockTransition activate the configuration layer. Absence of
a registered production engine is an execution stop; accept_msgs=0 is an inbound
routing restriction; M3's incomplete implementation is a separate fact. These
are not interchangeable activation checks.

The engine selector has one named production definition,
`uno_v2_workchain_engine_key()` (Basic, ASCII UNO2). create-state exports that
function to Fift; no Fift selector literal duplicates it. Defining the identity
does not register an implementation. The instance proposal and final ledger
issuance share derivation, but issuance independently reads the final serialized
configuration root. The proposal tool never installs its own ledger.

## Provisional resource envelope

These limits are development choices, not measured capacity or a production
approval. Mainnet has an empty resource-policy approval list pending M6. The
profile uses existing admission version 4, including proof-operation metering.

| Field | Value | Provisional rationale |
| --- | ---: | --- |
| input cells / bits | 384 / 392832 | Twelve fee-budget slots with a provisional allowance of 32 cells each; bits are the 1023-bit cell maximum. This allowance is not a measured operation size. |
| roots / inbound | 4 / 1 | Exactly the three mandatory logical roots plus one inbound root. |
| reads / writes | 8 / 8 | At most the frozen K_collect=8 account fan-in; may reject operations needing additional accounts. |
| state cells / bits | 2048 / 2095104 | Eight per-account allowances of 256 cells; dictionary paths also consume the total, so this is deliberately restrictive. |
| per-account cells / bits / depth | 256 / 261888 / 32 | Explicit small development closure allowance, not a measured persistence maximum. |
| proof work units | 1 | Smallest nonzero metered work allowance. It is NOT SEND=1 or COLLECT=3 fee units and may reject every current proof shape. |
| effect cells / bits | 48 / 49104 | Four provisional cells per one of twelve fee-budget slots. |
| output cells / bits | 384 / 392832 | Same small aggregate cell allowance as input; independently enforced. |
| transfers | 12 | No more than twelve transfers regardless of an operation's fee weight. |

SEND=1, COLLECT=3, target=6 and cap=12 describe the economic operation budget;
they do not establish cryptographic work capacity. The cell allowances above
are explicitly provisional choices, not deductions from measured costs. Too
small a bound must fail visibly; none of these figures establishes liveness.
In particular the installed proof budget does not promise a successful SEND.

**Blocker:** D31 resource-policy values remain provisional. Before M6 capacity
acceptance, no claim that wc=2 resource quotas are determined is permitted.

## Remaining acceptance boundaries

The test-network copy of the production generator produced a real zerostate.
Its ledger contains wc=2 with seq=1. The production check_mc_state_extra method
accepted the unchanged state and rejected missing-instance and wrong-descriptor
candidate deltas with final typed CandidateReject. This is method-level evidence,
not full-block consensus acceptance; mutation calibration remains pending.

The initial system record encoded for configuration seeding has layout=1,
base_compute=1000000, registered_accounts=0, and system_pending_count=0. The wc=2
account dictionary is empty; no coordinator account deployment or operational
budget transfer is claimed by encoding this seed.

Before a runtime installation exercises the collator issuance entry, no runtime
entry coverage is claimed. Shared issuance routine coverage from genesis does
not remove this blocker. Before D54 is resolved and measured, runtime workchain
activation is not accepted. Before its independent McStateExtra codec migrates,
tosctl is excluded from claims that the operator toolchain can read this state.
