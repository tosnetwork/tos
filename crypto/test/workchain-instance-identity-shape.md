# D40 state shape proposal and subsequent decisions

The proposal below is historical. D52 approved the location and descriptor
scope. Its revision at memo `58c24c91` additionally permits first issuance when
the authenticated predecessor ledger lacks wc and the proposed configuration
contains its descriptor. Because entries cannot be removed, this predicate is
one-time. The earlier prohibition on inferring first creation below is
superseded; successor issuance remains explicitly unsupported. Implementation
and measurements are separate from this historical proposal.

Source inspected: `1d7b642f9` (production changes last at `7008e8a40`).
This is a proposal for coordinator approval, not a claim of an existing creation
mechanism. No production files or tests were changed for this investigation.
Negative findings are bounded to `crypto/block` and `validator/impl` C++ sources.

## Authenticated location

Propose a mandatory reference in the auxiliary cell of a newly versioned
`McStateExtra` constructor:
`workchain_instances:^WorkchainInstanceLedger`. The ledger is a tagged cell
containing `HashmapE 32 WorkchainInstanceRecord`, keyed by the workchain's signed
32-bit wire representation. It is a sibling of configuration state, never a
ConfigParam and never an account of the workchain instance.

Each present entry retains the last issued `instance_seq:uint64` and the
creation-time descriptor commitment. The latter must survive ordinary descriptor
updates: recomputing from today's descriptor would silently change the identity.
The current instance ID is derived from that record and the authenticated genesis
root, and compared with the configuration shell. A versioned identity cell fits
tag + genesis hash + workchain ID + descriptor hash + sequence in one cell;
its representation hash is used, never its serialized BoC hash.

This reference belongs in the existing auxiliary cell, not as a fifth possible
reference in the main `McStateExtra` cell. The current layout is at
`crypto/block/block.tlb:661`; its auxiliary fields include previous blocks and
optional creator statistics. Exact new tag, bit/ref limits and generated codec
validation remain implementation checks after shape approval. Absence of the
new mandatory ledger is not interpreted as an empty ledger in an existing state.
A newly constructed zerostate can explicitly initialize an empty ledger.

Proposed first issued sequence is 1; empty ledger means no prior issuance, not
a missing-state fallback. At creation, checked `last + 1` is staged with the
configuration installation. Overflow rejects issuance; failure does not consume
a number in the committed state. Ordinary updates preserve the record exactly.
No deletion, reset, decrement or arbitrary increment is allowed.

## The write boundary must be added, not assumed

`Collator::adjust_shard_config` (`validator/impl/collator.cpp:1827`) only calls
`new_workchain` when the workchain is absent from shard configuration (1840–1842).
It cannot be the instance issuance trigger: a successor keeps its descriptor
under section 14.2. It also uses the currently installed configuration, whereas
new configuration is obtained later in `create_mc_state_extra` (5358 onward).

Propose a shared authenticated instance-transition routine called by
`create_mc_state_extra`, after obtaining and validating the proposed configuration
but before installing it into `state_extra.config` (current transition check at
5411). Its inputs must include authenticated predecessor ledger, authenticated
genesis identity, proposed configuration and a validated creation event. The
routine returns a staged ledger; it does not mutate the predecessor or accept
a caller-supplied replacement counter.

The independent validator must reconstruct the permitted delta in
`ValidateQuery::check_mc_state_extra` (`validator/impl/validate-query.cpp:7255`)
and compare it to the entire candidate ledger change, including deletions and
unrelated keys. Merely checking the configuration or the keys read is insufficient.
`block::valid_config_transition` (`crypto/block/block.cpp:1936`) presently receives
only two configuration roots: it cannot enforce this authenticated-state rule.

The intended allowed-writer set is exactly creation transitions (plus explicit
empty zerostate initialization). A malicious candidate can always encode other
bytes; exclusivity means the independent transition validator rejects them,
not that a C++ private member prevents anyone constructing such bytes. Governance
can propose a creation but cannot supply/reset the sequence. Configuration-only
updates and all non-creation blocks must preserve the ledger, even when policy
entries are removed or an instance is retired. No instance engine writes it.

## A creation-event boundary is still missing

The inspected tree contains no instance-creation or authenticated successor
handover mechanism. Section 14.2 requires a single authenticated migration event;
the existing descriptor transition routine instead rejects execution-key/version
changes without an explicit migration rule
(`crypto/block/workchain-execution-dispatch.cpp:317`). ConfigParam 84 destination
changes are similarly rejected by `valid_config_transition`.

Consequently, a configuration difference alone must not be promoted to evidence
that an authorized successor creation occurred. The coordinator must choose the
creation-event admission boundary before this proposal has a complete write
rule. A safe staged implementation can implement first installation and reject
successor issuance until that authenticated handover exists, while retaining the
counter permanently. It must not be reported as live successor support.

When a successor event is eventually validated, it uses the same workchain key
and checked increment routine; it never seeds the counter from the predecessor
instance's account state, the migrated account count, or ConfigParam 84. The old
sequence is never reissued. Ordinary disable/enable or parameter updates do not
constitute successor creation. Exactly what identifies first installation versus
ordinary update versus successor must be an explicit admitted transition, not a
heuristic on changed bytes.

## Genesis and commitment inputs

Propose committing the exact creation-time ConfigParam 12 `WorkchainDescr` cell
(native representation hash), not the ConfigParam 84 engine shell. The descriptor
layout (`block.tlb:756–774`) does not contain that shell; this avoids including
`instance_id` inside its own commitment. This choice of descriptor scope requires
approval because the term must be identical at issuance and verification.

`ConfigInfo` reads the masterchain zerostate reference from authenticated
`OldMcBlocks` at `mc-config.cpp:200–214`. At seqno zero its intermediate fields are
zeroed and are only supplied by `set_block_id_ext` (747–755). The new path must
require the actual authenticated identity; those intermediate zeros are not a
valid substitute. An identity-bearing shell embedded in the very masterchain
zerostate whose root it records would be self-referential. Initial instance
installation after the masterchain zerostate exists avoids that cycle; supporting
an identity-bearing masterchain-zerostate configuration would require a separate
approved bootstrap definition.

## Ownership and proposed implementation footprint

The write rule needs both producer and independent validator wiring; a new
header alone cannot enforce it. Thus this task intersects A's files despite
configuration storage appearing separate initially. Request coordinated ownership
for narrow state-transition calls in `validator/impl/collator.cpp` and
`validator/impl/validate-query.cpp`, with their headers only if context transport
requires it. No such files have been edited.

Other anticipated files: `crypto/block/block.tlb`, a new
`crypto/block/workchain-instance-identity.h` (and `.cpp` if needed),
`crypto/block/mc-config.h/.cpp` for authenticated read access,
`crypto/block/workchain-resource-policy.h` for mandatory shell metadata,
`crypto/block/create-state.cpp` for explicit ledger initialization, generated
`block-auto.h/.cpp`, and new exclusive test/driver files. Existing shell fixture
construction sites will need migration, including `test-workchain-block.cpp` and
`test/test-counter-disk-integration.cmake`; the latter remains A-owned and will
not be edited without reassignment. Additional frozen encoders, if discovered,
will be reported before edits rather than silently added to this footprint.
