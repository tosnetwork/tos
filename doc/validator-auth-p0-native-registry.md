# Persistent native registry application

`NativeRegistry` independently implements persistent native dictionary updates in
C++ and Rust. It produces the same frozen Config46 root as the owned `RegistryState`
oracle. The 400-member committee ceiling never limits the public identity/key
archive. Ordinary block application shares unchanged native cell paths instead of
copying maps, enumerating public keys or rebuilding all indexes.

Bootstrap validates the complete registry with the existing bounded loader, then
constructs maximum-epoch, due-transition and policy-selection indexes. Every
accepted operation maintains these indexes atomically. Canceled key descriptors
remain archived and keep their consumed epochs. A due index entry identifies an
identity at a coordinate; multiple pending slots at that coordinate materialize
together. Removing one identity's schedule preserves all other identities.
VATr remains the sole source of pending intent. The indexes cannot authorize an
operation or introduce a second schedule.

The local/native checkpoint container has the following bit layout. Integers
and dictionary keys are big endian. Its namespace is contract/checkpoint metadata,
not an additional public wire/API constructor or an activation allocation.

| Container | Ordered fields |
| --- | --- |
| Checkpoint | `tag:u32=0x76616e31`, `version:u16=1`, `coordinate:u32`, four refs in the order below |
| Ref 0 | Exact frozen Config46 cell |
| Ref 1 | `HashmapE 296 uint64`: key `identity:bits256, role:u8, suite:u16, parameters:u16`; value maximum archived epoch |
| Ref 2 | `HashmapE 288 True`: key `effective_from:u32, identity:bits256`; empty value |
| Ref 3 | `HashmapE 32 bits256`: effective coordinate to immutable policy ID |

Each dictionary uses an ordinary one-bit presence wrapper and zero/one references.
The checkpoint root is exactly 80 bits and four references. Its caller supplies
an independently authenticated expected registry hash and coordinate. External
restore checks those values, fully validates the registry, reconstructs every
index and compares the complete checkpoint commitment. Missing due entries,
altered epochs, substituted policy indexes and unsupported header versions fail.
An in-memory typed successor needs no external restoration or archive scan.
Contract-owned persistence and native cache/finality integration must preserve
this trust boundary; untrusted serialized indexes cannot obtain a trusted type.

`apply_block` accepts exactly the next complete block. It applies due effects,
selects the inclusion policy and processes updates in order, advancing registry
revision once when identities/keys change. The production `apply_native_block`
builds the real native owner/PoP/current-admin authority against each resulting
view. An old parent view cannot authorize a later same-block rotation. Failed
batches expose no successor and preserve the parent checkpoint. The generic
authority form remains a state-machine integration interface and test oracle;
it does not establish native ownership by itself.

Operational read/write budgets count dictionary entry operations and canonical
object bytes. They are local admission limits, not protocol gas accounting.
The shared 34-case replay corpus checks continuous/restarted native bytes, due
and policy boundaries, cancellation, atomicity and overflow. Eight checkpoint
attacks cover root, coordinate, epoch/due/policy indexes, magic, version and
trailing bits. The 74 real-wallet authority cases also run through the persistent
path. A 501-identity archive admits one rotation within 256 entry operations and
64 KiB; an empty block consumes two index reads and 32 charged bytes for both
three and 501 identities. This establishes bounded archive work, not a measured
native contract gas or network propagation budget.

Eighteen C++ and eighteen Rust mutations must compile and fail their specific
assertions. Full archive baselines pass before/after mutation runs; guard cases
use the smaller equivalent registry for repeated attacks. Full-dependency Ubuntu
ASan/UBSan/leak runs reproduce the replay/checkpoint and real-owner outputs.
Native contract persistence, global operations, allocation and node installation
remain subsequent execution boundaries.
