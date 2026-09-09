# Genesis installation

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
not full-block consensus acceptance. Removing genesis issuance in a committed
source copy leaves a validly encoded empty ledger and trips identity 936.
Removing the independent delta comparison retains positive acceptance and trips
identity 931 for both missing-entry and changed-descriptor candidates. These
are two directions through the same delta guard, not two independent defenses.

The initial system record encoded for configuration seeding has layout=1,
base_compute=1000000, registered_accounts=0, and system_pending_count=0. The wc=2
account dictionary is empty; no coordinator account deployment or operational
budget transfer is claimed by encoding this seed.

Before a runtime installation exercises the collator issuance entry, no runtime
entry coverage is claimed. Shared issuance routine coverage from genesis does
not remove this blocker. Before D54 is resolved and measured, runtime workchain
activation is not accepted. Before its independent McStateExtra codec migrates,
tosctl is excluded from claims that the operator toolchain can read this state.


## Destination routing configurations

The production descriptor uses `0xc000` (basic=1, active=1, accept_msgs=0,
flags=0) because no production engine can service wc=2. The Counter network uses
`0xe000` (basic=1, active=1, accept_msgs=1, flags=0) because its registered Counter
engine can service that workchain. Both configurations are exercised by the
same real-node source-transaction and exported-state inspection code.

Two successive source blocks are validated and exported in each configuration.
With service, each adds one destination message. Without service, action result
36 is recorded, the source remains active, its logical time advances, the
balance loses exactly the transaction fees, and both resulting outbound queues
are empty. These are persistent transaction/state observations, not log text or
absence of reads. The sender's earlier ignored invalid send remains separately
counted as one skipped action. Removing the destination `accept_msgs` predicate
preserves both serving observations and fails the unserved action-code assertion
957. This isolates that guard from the other producers of action result 36.
No claim about all possible send modes follows from this two-block fixture.

## Activation boundary still blocking completion

The two historical full-node activation fixtures remove Param84. With D40,
issuance refuses the resulting incomplete instance configuration (7409), before
the node's activation boundary. They are neither passing activation controls nor
regression passes. Keeping Param84 while closing the capability/version instead
violates the existing configuration-presence constraint during genesis
construction. No production validation exception has been introduced.

Supplementary scoped-resolver probes retain Param84 and use the shared
activation classifier, including its earlier-failure calibration. They do not
start a node and do not observe transaction counts or candidate exports. Before
a closed-configuration control reaches the same live boundary and observes
zero transactions and no export, the required live activation control remains
unestablished. Resolver evidence must not be substituted for it.

The ordinary smart-contract genesis regression now explicitly selects a test
network before using public deterministic validators and development operators.
The production mainnet approval guard is unchanged. The build-wiring regression
passes its actual prepared Python interpreter to child configuration rather than
assuming this worktree has another environment at `.venv`.
