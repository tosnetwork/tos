# M1 inventory outside I13

Read-only source inventory at `1b978f80eb35517826c3772a753e215ba28575ca`.
The companion `doc/measurements/uno-m1-non-i13-inventory.json` pins committed
blobs, SHA256 values, cited lines and the memo revision. Working source bytes
were compared with those blobs. This describes that revision, not subsequent
work on the integration branch. No production code, deployment configuration,
activation gate or test assertion changes are part of this inventory.

The criteria are the V2 memo sections 9.1/9.2, 10, 14, 16 and the five non-I13
entries in section 17. Section 9.1 explicitly permits reuse of old mechanisms
without inheriting their acceptance. “Exists” below means an inspected function
body and its callers; it does not mean that a related filename exists. Negative
findings are bounded to the inspected interfaces and source domains, not proofs
of absence throughout every historical implementation.

| Item | Mechanism present at this revision | Missing or unestablished | Dependency on the six execution/replay seams |
|---|---|---|---|
| Restricted records | Private multi-account binding, storage/settlement/entry transaction preparation, serialization and account replay | Live production/replay of these records; new-account registration participant is explicitly unsupported by the settlement runner | Live integration needs the seams. The new-account restriction is an additional interface gap, not removed by connecting a caller. |
| Custody message value ownership | Private payout pricing/pair construction, custody/operator allocation, inbound/outbound evidence and separate S/C/T fee accounting | Live block aggregation and replay; generic effects plumbing does not itself establish Withdrawal authority, prior protocol lock or fee-schedule authorization | Live host use needs the seams. Business authorization has separate engine/protocol dependencies; connecting the seams does not implement them. |
| Independent value flow | Checked per-account/per-currency arithmetic, with private overlay callers deriving rows from serialized Native artifacts | Complete candidate/block comparison on the live multi-account path; this is not the protocol reserve ledger or an audit of hidden rights | Live full-block use needs the seams. Public reserve accounting is a distinct dependency. |
| Configuration | Generic authenticated resource/profile resolution and configuration installation/transition checks, already called by live collator and validator | Concrete V2 business-profile checks, D36 cadence binding and evidence of the complete readiness/migration/dry-run sequence were not identified | Generic config checks do not wait for the seams. First-use multi-account execution/replay tests do. |
| Real synchronization | Native downloader/manager/CellDb import path and a real-process Counter cold-join/checkpoint/GC/reopen harness | V2 multi-account payload/DA/cold-sync acceptance; the cited historical Counter run was not reverified here | Native import/recovery work is independent. Sync of genuinely produced and replayed V2 blocks needs the seams plus a real V2 state/engine fixture. |

None of these five items is declared end-to-end accepted by this inventory.
“Private pieces exist” is deliberately narrower than “private scope complete.”

## Restricted records

`crypto/block/block.tlb:32` defines the account-specific input/effects binding;
`crypto/block/block.tlb:432` defines the restricted storage description and its
settlement/entry neighbors. `crypto/block/workchain-participant-record.h:18`
constructs participant bindings. These are consumed by actual Native transaction
preparation, not merely decoded by a test.

`crypto/block/transaction.cpp:4910` checks an active account, version and bound
account identity. It rejects ordinary compute/action/storage/credit/bounce phases,
incoming/outgoing messages, changed balance and fees for a storage participant.
It seals the data and metadata. `crypto/block/transaction.cpp:4947` revalidates the
restricted metadata during serialization. Authorized settlement/entry preparations
extend this storage-only base explicitly; the blanket storage-only restrictions
must not be mistaken for prohibiting the approved custody exceptions.

`crypto/block/workchain-account-settlement.h:318` constructs writes from declared
old accounts and dispatches to actual private allocation/payout overlays.
`crypto/block/workchain-account-replay.h:41` compares rebuilt effects, account
root, AccountBlocks, imports, message and end LT with the claimed artifacts.
This is host reconstruction rather than reliance on claimed caches, but shares
implementation with construction; it is not an independent implementation oracle.

There is a concrete additional restriction: at
`crypto/block/workchain-account-settlement.h:322`, a missing declared old account
hash returns `account creation requires a registration participant`. The current
storage preparation also requires an active old account. Thus wiring this runner
alone cannot provide account creation. The registration operation belongs to the
later engine lifecycle work in section 17; the required host participant support
is an interface dependency to schedule, not a newly assigned M1 implementation
in this report.

Live multi-account use remains blocked at the explicit account-binding returns:
`validator/impl/collator.cpp:1614`, `validator/impl/collator.cpp:2311`,
`validator/impl/collator.cpp:2465`, `validator/impl/validate-query.cpp:1150`,
`validator/impl/validate-query.cpp:1296`, `validator/impl/validate-query.cpp:6527`.
All six still report that multi-account admission/replay are not connected at
this pinned revision. The singleton route is not evidence that these records
are produced and independently checked in a multi-account candidate.

Existing archived private evidence includes
`doc/measurements/uno-v2-storage-participant-evidence.json`,
`doc/measurements/uno-v2-storage-overlay-evidence.json` and
`doc/measurements/uno-v2-account-settlement-evidence.json`. The first explicitly
limits itself to an inactive storage wrapper; the last to private settlement.
This inventory neither reruns nor retroactively expands those experiments.

## Custody message value ownership

`crypto/block/transaction.cpp:4529` prices the payout using Native construction.
The subtraction from the old custody balance at
`crypto/block/transaction.cpp:4557` prevents imports/allocations from increasing
that Native principal budget. It is not a read or verification of the protocol's
pre-batch Withdrawal lock.

`crypto/block/transaction.cpp:4600` constructs the actual custody/coordinator pair,
checks input/effects presence and bindings, and checks payout/custody data against
effects. `crypto/block/transaction.cpp:4673` applies the checked payout allocation;
`crypto/block/transaction.cpp:4683` retains collected fees and appends the actual
custody output message. `crypto/block/workchain-payout-accounting.h:21` contains
the checked account allocation and conservation calculation. It explicitly
accounts for principal, forwarding fees and the operator's funding. Its internal
coordinator-to-custody forwarding-fee funding is distinct from the aggregate-fee
state-cost transfer below.

D32 also has concrete plumbing. `crypto/block/workchain-fee-settlement.h:17`
retains S/C/T separately; `crypto/block/workchain-fee-settlement.h:26` bounds and
adds the amounts. `crypto/block/workchain-native-allocation.h:57` allocates S
internally from custody to coordinator. `crypto/block/transaction.cpp:4876`
debits C+T into Native transaction fees, without creating a fee payment message.
`crypto/block/workchain-allocation-overlay.h:155` checks the decoded transaction
fee amount. These implement private accounting, not a recomputation of S/C/T
from the certified fee schedule. The source explicitly says so at
`crypto/block/workchain-fee-settlement.h:14` and
`crypto/block/workchain-allocation-overlay.h:148`.

Remaining host work is to carry these reconstructed artifacts through the live
candidate, block fees/value flow, queues and independent validator comparison.
Separate semantic providers must authorize Withdrawal prepare, match destination
and amount to the protocol lock, and derive each fee component and the paired
protocol N_book debit. The inspected generic interfaces consume effects/data;
they do not supply those protocol operations. Keeping three components encoded
or maintaining their sum does not prove their authorization. Later M3/M4/M5
business milestones must not be silently counted as complete M1 host plumbing,
or silently reassigned by this inventory.

`doc/measurements/uno-v2-native-payout-pair-evidence.json` explicitly excludes
activation, effects authorization, live commit and source-aware admission.
The existing Native pricing/pair pieces are reusable under that boundary.

## Independent value flow

`crypto/block/workchain-value-flow.h:25` enforces the equation for each account:
old balance + imports + internal credits = new balance + exports + fees + internal
debits. Its checked operations include extra currencies, sorted unique account
rows and transfer endpoint membership. The function accepts rows; its existence
alone would not prove independent observation.

The callers supply the stronger part. At
`crypto/block/workchain-allocation-overlay.h:141`, balances and fees are decoded
from the old/new Native account and serialized transaction. Outbound messages
supply value plus remaining forwarding fee. At
`crypto/block/workchain-allocation-overlay.h:209`, actual reconstructed imports
supply account credits before the equation is checked at
`crypto/block/workchain-allocation-overlay.h:217`.
`crypto/block/workchain-payout-overlay.h:206` decodes exported message values;
`crypto/block/workchain-payout-overlay.h:249` reconstructs imports and reaches the
same arithmetic check at `crypto/block/workchain-payout-overlay.h:260`.
Thus these private paths already derive quantities from artifacts distinct from
the engine's accounting claims. Internal-transfer authorization remains a
separate effects obligation.

The six live seams still prevent this private evidence from establishing the
full candidate's account/message/ValueFlow agreement. In addition, the row type
at `crypto/block/workchain-value-flow.h:11` contains Native balances/imports/
exports/fees, not D/N_book/W/P protocol ledgers. The equation is not
R_actual + P = D + N_book + W, and neither equation audits hidden claims. No
concrete V2 protocol reserve reconciliation implementation was identified in the
inspected host interfaces and non-archived UNO sources. This is a boundary on
what “independent value flow” currently establishes, not a new acceptance claim.

`doc/measurements/uno-v2-value-flow-evidence.json` covers the arithmetic utility
and explicitly excludes validator integration. The later overlay source and
settlement evidence must be considered separately, rather than attributing their
stronger data derivation to that earlier utility-only experiment.

## Configuration

This item already has live mechanisms outside the execution seams.
`crypto/block/workchain-execution-dispatch.cpp:160` validates Param84 installation
against Param8 version/capability, the dual-account version, supported admission
profile and nonzero resource bounds. Business parameters are explicitly opaque.
At `crypto/block/workchain-execution-dispatch.cpp:416`, account resolution loads
authenticated configuration, binds resource policy to configuration hash and
engine/descriptor/admission identity, then invokes the registered engine's
`validate_and_resolve_config` callback at
`crypto/block/workchain-execution-dispatch.cpp:451`.

`crypto/block/block.cpp:1936` checks transitions, including removal/address-change
restrictions and initially closed admission for a new ingress descriptor.
Actual callers include `validator/impl/collator.cpp:5383` and
`validator/impl/collator.cpp:5414`, and
`validator/impl/validate-query.cpp:7084` and
`validator/impl/validate-query.cpp:7115`. Therefore describing all configuration
as an unconnected private header would be false.

The generic resource/business split at
`crypto/block/workchain-resource-policy.h:129` does not implement the concrete
V2 economic profile. In the inspected configuration functions there is no D36
comparison of Param30 cadence against the profile's certified K/base_compute
cadence. The engine callback is the unresolved provider boundary, not evidence
that such a callback has been supplied for the actual V2 engine. Readiness of
current/next validators, manifest/zerostate/obligation consistency and the entire
section 14 migration sequence are likewise not established by generic profile
recognition or the first closed installation check.

The inspected CLI configuration command is local tosctl configuration management
(`tosctl/src/node-control/commands/src/commands/nodectl/config_cmd.rs:28`). The
identified `--dry-run` implementation is a validator bid command
(`tosctl/src/node-control/commands/src/commands/nodectl/vote_cmd.rs:1040`). Neither
is the section 14 authenticated configuration-sequence simulation. Searches of
`tosctl/src` and review of these command dispatches did not identify that dry-run
or readiness evidence; this is not a claim that all configuration tooling is
absent.

Concrete profile/cadence validation, migration/readiness checks and tooling can
be assessed independently of the six execution seams. End-to-end first-use
multi-account execution/replay still requires them. Scope and implementation
assignment for these missing providers remain with the coordinator.

## Real synchronization

A real production import path exists. The downloader constructs a bounded
request with the handle's expected state root at
`validator/downloaders/download-state.cpp:1021`, calls the manager at
`validator/downloaders/download-state.cpp:1033`, which delegates to the DB actor
at `validator/manager.cpp:1629`. The CellDb worker compares the parsed root with
the expected root at `validator/db/celldb.cpp:2372`; it seals a private spool,
then the actor commits bounded write batches at
`validator/db/celldb.cpp:2948`. This is not the separately named unsafe test-only
streaming writer. These concrete calls establish implementation availability,
not complete recovery correctness under every interruption.

`scripts/m1-real-manager-sync.py:32` reads the old singleton Counter executor,
checks its wrapper and transaction identity, and optionally checks a fixed
payload. The harness runs real validator/cold-observer processes, stops warm
validators and reopens the cold node's own database
(`scripts/m1-real-manager-sync.py:584`, `scripts/m1-real-manager-sync.py:605`).
Its report at `scripts/m1-real-manager-sync.py:627` explicitly sets
`uno_sync_accepted` and `invalid_proof_rejection_tested` false. A preserved
32,767-cell payload is not growing V2 account/claim state.

`doc/uno-implementation-progress.md:3595` records a successful Counter checkpoint,
archive/GC/cold-reopen experiment at historical source `0256f22b9`, retained under
`build/m1-counter-network-run-8tzvi58s`. That directory was absent at both
`/home/tomi/tos` and `/home/tomi/tos-m2` during this inventory. No matching committed
raw run report was identified in `doc/measurements`. This is a documented
historical result, not a run reverified here; absence at those paths is not a
claim that no copy exists elsewhere. The document itself excludes UNO state
growth, resource ceilings and malicious checkpoint transport acceptance.

V2 still needs its own multi-account payload provenance/DA, state distribution
and rights-preservation, cold import/checkpoint/archive/GC/reopen evidence under
the relevant limits. Native importer and storage tests can proceed without the
execution seams. A synthetic multi-account snapshot alone cannot substitute for
synchronization of blocks actually constructed and replayed by the V2 host; that
requires the seams and the V2 engine/state fixture. Capacity acceptance beyond
M1 remains separately scoped by the later milestones.

## Scheduling facts and evidence limits

The seams are required for live restricted records, custody accounting and
full-block value-flow comparison; they are not sufficient for registration or
business authorization. Generic configuration and Native synchronization already
have live callers. Concrete profile/cadence and migration tooling gaps, the
registration participant boundary, and the provenance of historical sync
artifacts can be investigated without modifying those six callers. This is a
dependency inventory, not an implementation assignment or time estimate.

The old I13 inventory and section 17 snapshot also predate the implemented
private publication/recovery mechanism; their claim that no such mechanism
exists must not be carried forward. See
`crypto/block/workchain-candidate-publication.cpp` and
`crypto/block/workchain-publication-recovery.md` at this inventory's source commit.
Their existence still does not establish live I13e integration.

No tests or mutations were run for this read-only unit. Historical evidence files
are pinned as records, not adopted as fresh verification of the current tree.
For future mutation work, source restoration and executable restoration must be
recorded separately: explicitly rebuild every affected target with `-j32` after
restoration, record target names/commands, and never infer coverage from
`all-tests`. No old artifact is recertified by that prospective rule.
