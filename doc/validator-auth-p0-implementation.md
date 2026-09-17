# P0 production implementation

Implementation branch: `feat/validator-auth-p0`, based on main
`2004ce5e618c4a9d8ed5fe5ae51912d65bb524cd`.
The normative design is v1 revision 4, fingerprint
`8032aa88fe7ec289f81b7419b1f5e1a7f3f7aeb4b117c94c0a62d710ddb84ef1`.
This is an implementation in progress, not P0 acceptance. No network activation
or PQ suite allocation is authorized by this work.

## What decides the order of this work

Three things decide different questions, and confusing them is how a sequence
starts being written by whoever spoke last.

The frozen design under `doc/validator-auth-p0/` decides what is correct. It is
the only authority on semantics, and it has settled real disputes here rather
than being quoted decoratively: the exact field shapes of the global operations,
the list of authority-sensitive parameters that made a hand-written index
whitelist unnecessary, and the four-hundred-signer bound the governance cost is
derived from. It has twice been found to contradict itself, and the amendment
procedure -- one artifact hash, one structured evidence entry, activation
thresholds untouched -- exists so that correcting it leaves a record instead of
a quiet edit.

This table decides what remains. It has been the weakest of the three: six of
its rows were wrong until they were corrected against the code, and one claimed
a subsystem still needed building when nothing was left to build in it. A row
here is a claim about the tree and is worth exactly as much as its last check.

Cases and mutations decide whether the work was actually done. Neither of the
other two has predicted a defect. Every one found so far came from an assertion
going red: a store that discarded the registry it had just installed, a comment
that described the opposite of its branch, a guard whose removal no case
noticed, a measurement taken on the wrong axis, a fixture whose host never ran
the thing the number was said to cover.

## Sequencing

The order below is a plan, not a record. It is written down so that it can be
disagreed with by someone reading the repository rather than reconstructed from
a conversation.

**Phase one: session derivation and consensus call sites.** This is the only
remaining place where both ends are built and nothing references either from the
other: no file under `validator/consensus/` names anything in `validator/auth/`,
and no consensus signer is wired. Its failure mode is also the worst that
remains -- a producer and a validator deriving different session snapshots, each
correct by its own lights -- which is the shape this design has paid for
repeatedly and which costs least to find while the surrounding work is fresh.

Its entry condition is the activation policy: whether the first checkpoint is
seeded at genesis or installed by the first update. Nothing downstream opens a
configuration context without one, so this is not an independent item that can
be scheduled later; it gates the phase.

**Phase two: elector emission and node actor installation.** Receipts,
admission, and hanging the history, proof, signer and provider services on the
manager's lifecycle. These fail loudly -- a thing is wired or it is not -- which
is why they come after the phase whose failures are silent.

**Phase three: a four-validator rehearsal with the design enabled, and whatever
it exposes.** The existing rehearsal runs with it disabled, so nothing yet
proves four nodes agree while it is on.

### Deferred, with the reason

Replacing a pending activation is deferred because the frozen rules say it is
allowed but do not say which fields identify the activation being replaced; it
is not a prerequisite for a first network.

Remote HTTP/2 and its socket adapter, the operator rollout, the public RPC
surface, performance acceptance, PQ suite allocation and any migration are all
deferred. None of them is on the path from a genesis to a finalized block.

### Named blockers

Native governance gas was carried here as a blocker. At the committee this
network installs it is not one, and the figures that made it look like one were
not the figures for that committee.

The figures this paragraph carried were the ones for a hundred-validator
committee, which is not what the zerostate installs. It installs twenty-one, as
`400 21 4 config.validator_num!`, and the capacity bound refuses a genesis and a
bound that name different numbers. Re-measured at the committee actually
installed, and at the ceiling the profile admits:

| signers | whole transaction | signature verification | of the 1,000,000 soft block limit |
| ---: | ---: | ---: | ---: |
| 21 | 97,233 | 44,000 | 9.7% |
| 400 | 2,240,393 | 1,560,000 | 224% |

The credit is not what bounds this, and saying it was applied an ordinary
account's entry conditions to an account that is not ordinary. The
configuration account is special by address, so its compute phase begins at the
special limit rather than at one acceptance would raise. Measured end to end
through the real ingress at the installed committee, a governance operation is
admitted, verifies all twenty-one signatures and commits. A forged certificate
costs 2,664 gas and is refused at its first verification; a stale one is refused
before any.

So at the committee this network installs there is no blocker here. What the
figures show is a ceiling: at the four hundred the profile admits, one operation
is more than twice the soft block limit and nearly the whole hard one. That is a
statement about the ceiling, not about the chain being built.

Whether paid governance ingress is inside P0 at all is recorded separately as a
tariff item; this entry does not settle it, and the two should not be read as
agreeing until one of them says so.

## Execution boundaries and falsifiable checks

| Boundary | Implementation | Verification | Remaining integration |
| --- | --- | --- | --- |
| Ordered binary types | Production C++ library and Rust crate, generated typed bindings to all 70 schema types | Exact frozen bytes and 145 malformed binary inputs through both libraries | Production endpoint/caller wiring |
| C0 provider | Admitted public-key object; canonical, noncofactored verification using existing cryptographic libraries; exact provider-owned active inventory admission and reconciled handle routing | 86 real signature/encoding cases, including valid R=identity; subgroup and equation guard removals | Native session admission installation of the reconciled inventory token |
| Committee and certificate verification | Owned immutable admitted snapshots, expected-duty binding, complete roster and all signatures | 40 cases across five roles; exact quorum, below quorum, corrupt surplus signature, duplicate identities and context mismatch | Native session derivation and consensus call sites |
| Native cells | Canonical AuthBytes and native BOC adapter | 20 round-trip/malformed-BOC cases through 32 MiB of incompressible data; direct hash and canonical-partition guard removals | Nothing in this subsystem. The remaining work is joined evidence that a native cell reaches the installed chain root unchanged, which is tracked with the transaction prefixes |
| Identity lifecycle | C++ and Rust per-identity register/rotate/retire/cancel and consecutive-block due-transition application | 104 differential cases per language with controlled, separately typed authority callbacks; predecessor and block-gap guard removals | Global configuration operations. Policy operations and native transaction storage are in place |
| Object transfer | C++ and Rust canonical inline/manifest readers plus principal/anchor-scoped stores and atomic proof publication | Chunk and whole-object hash substitution, quota, duplicate upload, expiry and aggregate read budget; cross-language scoped-store differential and compiled storage guards | Remote mutual-authentication transport and actor installation |
| Thin transport and API association | C++ and Rust framing and semantic association for all 15 methods, including result receipts, proof attachments and cursors; remote TLS 1.3 mutual-authentication outcome binding, operator-local certificate-to-principal trust and shared transport bounds | Existing framing/semantic guards plus focused remote identity/boundary cases; HTTP/2 framing remains fail-closed and unimplemented | HTTP/2 framing, concrete TLS socket adapter and actor installation |
| Native VM and transaction execution | C++/Rust VAUTH_CHKSIGN, native capability metadata, Fift/FunC and Rust assembly bindings | 168 exact outcome/gas comparisons; getter config and nested VM; eight whole transactions including action rollback | Elector statement construction and native admission |
| Native committee derivation | Explicit native identity/stake descriptor, authenticated Config35/34 and Config46, original native selection, owned transport order and VAM1 | 40 C++/Rust state cases including a full 400-member snapshot, shuffle, shard weights, temporary election and budget exhaustion | Elector emission and session admission |
| Native registry state | C++ and independent Rust Config46 genesis, encoding and identity-update replay; immutable key archive and owned successor state | 501 identities / 2506 keys; 34 cross-language replay cases with checkpoint/continuous equivalence, control retention and rejected-block atomicity | Global configuration apply. Contract installation and the elector/configuration paths consume one block-scoped prefix, and a zero-identity policy operation replays to identical bytes in both languages |
| Native state proofs | C++ and Rust actual masterchain Config8/9/10/16/46 and Merkle proofs for profile, policy, key and registry ranges | State-root substitution, omitted entries, false terminal page, unrelated revealed values, detached physical cells, capability and atomic-publication guard removals | Actor installation |
| Native certificate proofs and RPC | Independent C++/Rust certificate verification from native committee and policy proofs; C++ methods 12/13 and private Rust verified output | 55 shared cases; real local HTTP over 16 snapshots; exact signers/weight, trusted context, error provenance and single-fetch prepared request checks | Native manager installation of the node history adapter and remote serving |
| Native owner execution | C++ and independent Rust VAF1 kind-1 proofs over native account transactions, full trusted anchor and current owner/stake allocation | 68 shared proof cases from real masterchain/workchain-0 wallet transactions; action rollback, forged wallet signatures, block substitution and 52 compiled guards | Native elector receipt processing, normal stake rules and atomic update admission |
| Native registry transaction prefixes | Independent C++/Rust per-transaction immutable candidates, due-before-request order and private block-start revision | 80 real-owner cases match whole-block replay; rejected/discarded candidates, cumulative budget, overflow and nine compiled mutations; 14 joined cases and seven compiled mutations bind a candidate to what the account committed | Global registry operations. A block-scoped sequence now holds the prefix, every transaction of the account opens on it, and a candidate is promoted only after the account itself commits and the committed parameter 46, checkpoint and elected set match exactly what the host handed the contract |
| Native configuration gates | Actual C++ admission/transition and Rust config admission, frozen Config46 registration, capability/version, required parameters and revision continuity | 43 shared cases, 11 legacy transition tests, 47 compiled guards and full-dependency sanitizer parity | Native contract authorization, atomic root installation and approved activation |
| Persistent native registry | Independent C++/Rust immutable cell dictionaries, validated derived indexes and per-operation native authority | 34 replay cases, eight checkpoint attacks, 80 real-owner authority cases and 36 compiled guards; bounded work over 501 historical identities | Global configuration operations and node installation. Zero-identity policy operations and contract-owned persistence are in place: the account's own tick-tock writes the prefix a block with no registry message produced, which is what keeps parameter 46 from naming transitions as due at a coordinate that has passed |
| Native header witnesses | Independent C++/Rust fixed-surface Merkle proofs authenticated by native history; no archive/cache access; carried by the registry message and authenticated at consensus admission | 25 shared cases, independent proof generation, 27 compiled guards and full-dependency sanitizer parity | Concrete transaction host metering: admission authenticates a carried witness uncharged |
| Privileged native VM host | C++/Rust VAUTH_STATE/VAUTH_APPLY/VAUTH_BIND, one purpose-specific host per transaction shape, including a state-only host for the account's own tick-tock, transaction-scoped ownership, no nested VM inheritance and explicit charge callback | 39 exact outcome/gas/host-call comparisons, host-purpose and allowance cases, compiled guards and full-dependency sanitizer parity | Deterministic native gas, which is now a named blocker rather than a note: a certificate from the twenty-one-member masterchain committee this network installs exceeds the masterchain credit on its reads alone, 13,440 against 10,000, and its signature verifications -- now priced at the machine's own tariff, announced before each one is performed -- add forty-four thousand gas more; at the four hundred the profile admits, 256,000 and one million five hundred and sixty thousand. See the named blockers above for what was re-measured and what the earlier figures described. The authority is assembled per transaction by collation, validation and message-pool admission through one assembler, an update host refuses to bind and a binding host refuses to apply, and a refused operation spends the allowance it read rather than restoring it |
| Native configuration account context | Independent C++/Rust binding of actual ShardAccounts code/data/library, Config0, owned config dictionary, complete checkpoint and parent committee | 22 shared cases, 24 compiled guards and full-dependency sanitizer parity | Native commit of the account the contract produced. The contract now carries its checkpoint through every store and replaces it from the state instruction on a registry update, so parameter 46 and the account's checkpoint commit together; which of genesis seeding or first-update migration installs the first one is an activation policy still to be chosen |
| Native transaction evidence | Independent C++/Rust bounded transaction-contained VAA1, typed chunk dictionary, byte-work charging and authenticated owner header | 39 shared cases, 30 compiled guards, identical charge traces and full-dependency sanitizer parity | Concrete native VM pricing and transaction host invocation |
| Native finalized history | Independent C++/Rust resolution of full anchors from authenticated OldMcBlocksInfo and original native block bytes; node-local finalized-head establishment binds final signature-set verification to exact block/state coordinates | 37 shared history cases plus focused finalized-head cases; exact file/root/context/new-state binding, final-vs-approval refusal and monotonic head advancement | Signature-set actor adapter and installation of the established head. No archive adapter remains outstanding: consensus admission authenticates the witness a message carries against the parent state's own history index and reads no archive, so the cache, resolution queue and reporting that fed one are deleted rather than pending |
| Authenticated ordered identity apply | C++ and independent Rust compose native owner proofs, PoP and current administration with per-operation resulting state | 80 shared cases from real wallet approvals, same-block administration rotation, due/policy boundaries, exact native bytes and 22 compiled guards | Native elector/config transaction admission and installed chain root |
| Authority primitives | Independent C++/Rust session/duty derivation, C0 PoP, current identity-role-5 and current governance quorum verification; separate permit/receipt trust | 76 shared context/identity cases, 28 current-governance cases and 25 service-trust/polling cases; expired or rotated governance keys refused | Normal configuration voting and native transaction admission |
| Signer persistence | Native append-only safety ledger, actual C0 secret provider, witness consumption and sign/get-result service | Both-order conflict rules, exact retransmission, journal/provider backup rollback, stale fence, terminal retention, real fsync failure, unknown outcome refusal | Native consensus permissions and remote serving |
| Signer administration | Durable prepare/stage/retire/cancel intent execution, provider preparation IDs and PoP reservation IDs | Real PoP and current admin signatures, owner refusal before reservation, exact receipts, cancellation target, provider rollback and six process-kill boundaries | Native node adapter installation |
| Native Keyring isolation | Factory-installed durable public-key deny set, private-operation guards, shared/exclusive directory locks and an asynchronous drain barrier | Actual signing/decryption/export before designation; every private API refused afterwards; restart, damaged records, competing processes and compiled guard removals | Native session admission installation of the reconciled provider token |
| Service issuer | Purpose-separated persistent C0 service keys, typed permit/receipt signing, local rotation and public policy history; authenticated-local trust installation and verified node permit acquisition | Actual signer receipts, restart, key/policy binding and nine compiled guard removals | Actor installation and operator configuration rollout |
| Operational release | No activation change | No testnet/release acceptance claim | Required testnet, genesis, operator recovery, approvals and C0 performance evidence |

Owner approval production is deliberately outside the validator boundary. An
approval states that the owner's own account already executed a finalized
transaction carrying it; the node verifies that fact against finalized native
history and never manufactures one. Repository test drivers extract approval
fixtures from real executions, and a boundary check requires that no production
library links a symbol able to assemble one.


Generated bindings never rewrite the frozen schema or vectors. Parsed transport
frames do not establish chain authority. Snapshot admission validates an owned
roster, but still requires independently authenticated state/committee inputs.
The library checks do not replace native state proofs or production consensus
integration. The lifecycle test callbacks establish control-flow behavior only;
they are not native owner, governance, PoP or administration proof verification.

`ChunkStore` is one authenticated principal's bounded storage and requires caller
serialization. Its TTL expires storage reservations, not signer journal entries
or historical chain keys. `ObjectReader` charges an aggregate budget before
fetching; callers must use one reader for all attachments of an operation.

## Local evidence and CI

Local native and Rust builds and the cases above passed on macOS/ARM. The guard
harnesses compile isolated production mutations and require assertion failures;
compiler errors, imports and abnormal driver exits are not accepted as kills.
AddressSanitizer and UndefinedBehaviorSanitizer checks also pass for native
transfer and transport. Leak detection is unavailable on the local macOS runtime
and is not claimed. There are 20 C++ core/lifecycle/transport/transfer mutations, 35 Rust mutations
and three native-cell mutations, with restored baseline runs. The added native
state/authority/proof, journal, signer/provider and local channel harnesses kill
25, 11, 7 and 6 compiled guard removals respectively. Scoped object storage,
service issuers and C++ API semantics add eight, nine and eight removals. The
administration harness adds eleven. The combined implementation harness contains
830 compiled production mutations, including 24 authenticated configuration-account/cache and 28 native evidence controls, 12 native VM host isolation/metering and 27 fixed-surface header controls, nine transaction-prefix and 47 native configuration, 36 persistent registry, 34 native finalized-history and 22 authenticated ordered-apply checks,
52 native owner-proof/resource checks,
46 context/identity-authority checks,
33 current-governance checks, 28 independent certificate proof checks,
16 certificate RPC/error checks, seven prepared-client checks, 18 native Rust registry replay checks, three
native certificate benchmark controls, 17 API admission/cache checks, 25
native HTTP checks, 17 Rust native cell/proof checks, 25 native Keyring checks,
18 C++ VM checks, 18 Rust VM checks and five native execution adapter checks.

The native Keyring sanitizer gate uses a separate CMake build with ASan and UBSan
enabled for every linked dependency. Target-only instrumentation conflicted with
the ordinary executable's hidden static-library symbols on ELF and with the
dependency sanitizer macros. A standalone standard-library directory-copy probe
reproduced the hidden-allocator failure. The corrected local Ubuntu/ARM run passes
with leak detection enabled. A separate link regression relinks the actual native
executable with hidden runtime symbols and requires a named assertion before any
fixture or actor runs; this negative control cannot pass through a crash.

The frozen wire/API design and fingerprint remain unchanged. The updated evidence
record inventories exact additive Keyring, capability, elected binding and frozen Config46 insertions: 33 historical
files remain byte-for-byte unchanged, and removing only the registered insertions
from the two Keyring files, capability header, native TL-B schema and config parser recovers their original baseline hashes. The checker rejects changes
to either historical or inserted bytes; the baseline hashes were not replaced. The generated binding check, Rust formatting, Clippy with warnings denied and
whitespace checks pass. These results describe the working tree, not a committed
HEAD or a GitHub CI result.

`.github/workflows/validator-auth-p0-implementation.yml` builds the focused native
libraries and Rust crate on Ubuntu x86_64 and ARM, records the checked HEAD, runs
these checks and uploads evidence. Four independent x86 guard groups cover core,
service, state/proof and native execution mutations without a serial monolithic
guard step; each starts from its own complete passing build/baseline. ARM retains
the full functional and sanitizer baseline. The previous implementation milestone passed both focused CI architectures; each
new addition requires CI evidence attached to its own HEAD.
It neither triggers the full Ubuntu build nor starts a network.

## Native execution context

[Authenticated configuration accounts](validator-auth-p0-native-config-context.md)
now bind the actual parent account and complete private checkpoint.
[Transaction-contained evidence](validator-auth-p0-native-evidence.md)
resolves typed objects without archive/network IO and authenticates full owner anchors.
These inputs still need concrete gas pricing and native transaction commit wiring.

[The privileged VM host boundary](validator-auth-p0-native-vm-host.md) supplies
VAUTH_STATE/VAUTH_APPLY only to a node-injected host under VM16/capability1024. C7 and
nested RUNVM cannot introduce or inherit this host. The current test host measures
routing, isolation, operand order and charging; it does not authorize registry
operations or bind an actual configuration account.

[Native header witnesses](validator-auth-p0-native-header.md) derive resulting-state
hashes from a bounded native Merkle witness and the trusted parent history index.
This provides deterministic owner-anchor resolution without VM-time archive IO.
The witness cannot select its own fork or file hash. Native contract ingress and
the real transaction host remain separate work.

## Native configuration admission

[Native configuration gates](validator-auth-p0-native-config.md) bind the already
frozen Config46 schema to the real configuration entry points. Active P0 requires
VM version 16, mandatory and critical Config46, the fixed 400-validator ceiling
and exact registry revision continuity. Unapproved activation and downgrade are
rejected. Root checks remain bounded; full archive semantics and operation
authority are separate validated execution boundaries.

## Authenticated ordered identity application

[Native registry transaction prefixes](validator-auth-p0-native-transactions.md)
allow the native execution caller to retain only successfully committed requests.
They preserve one revision increment per changed block, cumulative work admission
and current authority across transactions. Eighty shared cases match whole-block
replay; contract data and action-phase commit wiring remain separate.

[Persistent native registry application](validator-auth-p0-native-registry.md)
shares unchanged cell paths and maintains authenticated checkpoint indexes. The
whole archive is validated at bootstrap/external restore; block application reads
only affected identities/keys, due entries and policy selection. Both independent
implementations match the existing 34 replay cases and 80 real-owner authority
cases, and reject eight checkpoint substitutions. Thirty-six compiled controls
cover the new paths. A 501-identity archive passes a 256-entry/64-KiB single-update
budget; empty blocks in both three- and 501-identity registries use two index reads
and 32 charged bytes. These are algorithmic work bounds, not gas/propagation or
native contract acceptance measurements.

[The native finalized-history adapter](validator-auth-p0-native-history.md) resolves
owner-proof coordinates from a trusted masterchain state's native history. It
checks original block file bytes, root, chain/coordinate and Merkle update output.
Its 37 cases and 34 compiled guards include different old/new state hashes;
substituting the old state must fail. Resolving an anchor by coordinate still
takes a native archive reader, and establishing finality independently still
belongs to the eventual node integration. Consensus admission uses neither: it
authenticates the fixed-surface witness the registry message carries against the
parent state's own history index, which reads no archive, so a producer and a
validator holding the same block reach the same authority whatever either
archive happens to contain.

[The native apply boundary](validator-auth-p0-native-apply.md) now verifies actual
owner execution, PoP and current administration during atomic identity replay.
Each operation reads the resulting registry from the preceding operation. Due
transitions and inclusion-time policy selection happen before authorization;
old governing-session keys cannot replace current administration keys. The shared
80-case corpus, 22 compiled mutations and full native Ubuntu sanitizer runs cover
same-block rotation, second-operation rejection, finality substitution, due/policy
boundaries and complete checkpoint bytes. Native elector/configuration transaction
admission and installation of the resulting chain root remain required.

## Native owner execution authority

The additive contract in `validator-auth-p0-native-owner.json` defines the BOC
inside VAF1 kind 1 and the bounded owner approval body. It binds the exact update,
chain domain, stake, current owner allocation and authenticated elector recipient.
The owner must execute a successful ordinary native transaction. Mainchain owners
bind the anchor block and state update; shard owners bind the exact shard block
through authenticated masterchain ShardHashes. A message, operator identity or
wallet signature alone cannot construct `VerifiedOwnerExecution`.

Both implementations independently verify 34 masterchain and 34 shard cases.
Inputs come from twelve real wallet executions with signature checks enabled,
including insufficient-funds action rollback, plus forged-signature refusal in
each workchain. Targeted transaction-field alterations isolate individual compute
and action guards. Controlled block/state containers provide finality fixtures;
they do not establish actual node inclusion, elector execution or public finality.

Twenty-five C++ and 27 Rust compiled mutations fail their named assertions and
restore passing baselines. The corpus includes a canonical proof for a different
shard block under the original masterchain state. Full-dependency Ubuntu/ARM
ASan/UBSan/LSan runs reproduce all 68 exports exactly. The Rust adapter applies
absolute effective Merkle levels and preserves intrinsic lower-level pruned data
under nested state updates. This fixes new P0 proof reconstruction without changing
historical native cell/proof code. The P0 Rust BOC reader explicitly enforces the
native 1024-depth ceiling; a compiled removal must accept the otherwise valid
1025-depth negative input, while the 1024 boundary remains accepted. Unused ordinary leaves are pruned consistently
in both implementations, and memoization includes Merkle depth.

Owner approval still supplies only one of four required authorization types.
Current identity administration, PoP, normal elector value/ownership/timelock and
selection rules, update nonce/predecessor checks and atomic native application
remain separately required. The local signer and native block apply must still
be wired to these independently verified authorities.

## Inclusion-time administration and governance

Both languages independently derive native session and duty domains and verify
new-key possession and current identity administration. The shared context corpus
has 76 cases, including exact bytes, native options and genesis binding, five
roles, oversized payloads, new-key descriptor binding and inclusive 128-block
freshness. Twelve C++ and 34 Rust compiled mutations reach their named assertions.

Operation 4 applies in both languages and both state representations. It writes
the policy, the activation binding it and the zero-identity record that holds
the global admin nonce, and the activation's checkpoint is the anchor the
governing snapshot was derived from -- returned by the authority that verified
the quorum rather than read again, so the record and its authorization are one
fact. The replay corpus carries a global case, and the C++ reference, C++
persistent, Rust reference and Rust persistent implementations produce identical
bytes for it; stamping a different but perfectly legal anchor fails on both
sides.

Normal configuration voting no longer installs on its own. On an active chain a
proposal that reaches its threshold is marked terminal and stays where it is:
nothing is installed, no further vote is registered, and a validator-set
rotation does not return it to an earlier round. The marker is a persisted
sentinel rather than a comparison against the current threshold, because that
threshold is itself a configuration parameter a later proposal can change --
compared against a moving value, a completed proposal would stop being complete
when it rose, and one that never completed would become complete when it fell.
Three separate paths could undo this and each is gated and each is tested: the
vote that crosses the threshold, a later vote arriving at a completed proposal,
and the tick-tock scan, which reaches the rotation reset with no vote at all.
The governance half that finalizes such a proposal is not implemented yet, so
the normative description of the two-stage rule is written once rather than in
parts.

Operation 6 is refused with its own reason. The frozen rules require the
governing quorum *and* the normal configuration vote for a configuration
parameter, and nothing carries an authorization across the rounds of that vote
to the block that installs the result. The proposed cell itself is not what is
missing -- a ConfigProposal already carries one. What is missing is the durable
link proving that the exact parameter, previous hash and proposed hash reaching
acceptance were the ones a governance operation approved. Admitting it on the
quorum alone would be a second configuration governance path rather than an
implementation of the declared one.

The zero-identity record holds the global admin nonce and nothing else. It is
created by the first operation that needs one rather than seeded at genesis, and
every other field an identity carries -- stake, owner, predecessor, keys,
transitions -- must be empty, because each is an authority or a link this record
is not entitled to. Its nonce must also be above zero, so that "no global
operation has happened" has one encoding rather than two.

Native governance gas is not closed, and it is now measured rather than argued.
Verifying a governance certificate costs two entries per signer record -- the
identity, and the administration key it names, read for the validity interval
its active reference does not carry -- and the cost is linear in the records, so
the largest legal certificate is the worst case:

| signer records | entries | bytes | charged gas |
| --- | ---: | ---: | ---: |
| 8 | 16 | 4,096 | 5,120 |
| 21 | 42 | 10,752 | 13,440 |
| 64 | 128 | 32,768 | 40,960 |
| 400 | 800 | 204,800 | 256,000 |

Two of those rows are ceilings, and they answer different questions. Governance
is signed by the masterchain committee, and the masterchain subset of an elected
set is `max_main_validators`, which the zerostate installs as twenty-one. That
is the operation a running chain has to carry. Four hundred is what the frozen
profile admits and what the registry refuses beyond, and it stays reachable
because the validator counts are a configuration parameter a governance
operation may raise up to that same bound -- so it is what the code has to
survive, not what it will usually be asked to do.

Twenty-one is not a decentralization preference; it is what the post-quantum
measurement below leaves room for, decided while the signatures are still
classical because it cannot be decided afterwards. It is held that way rather
than written down: the capacity bound measures the size the genesis installs
and a check refuses the two to differ, so raising the committee either fails
that check or fails the bound's own post-quantum case at the size it was raised
to. Both were removed and seen to go red. Raising or lowering
`max_main_validators` is itself a governance operation, carried by a certificate
of the size in force. A chain that activated a post-quantum suite at a hundred
would need a hundred post-quantum signatures to execute the operation that
lowers it -- twice a whole masterchain block -- and could no longer change its
own configuration at all.

The credit an external message has before it is accepted is ten thousand, and
the installed committee costs more than that in reads alone. That would settle
the ingress for an ordinary account. This one is not ordinary: the masterchain
configuration makes the configuration account special by address, and a special
account's compute phase begins with its limit already raised to the special
limit rather than with a limit acceptance would raise. Run against the real
contract, a governance operation at the installed committee is accepted and
committed.

So the credit is not what bounds this path, and the question it was thought to
answer -- whether a legitimate operation can be admitted at all -- is answered
yes. The same fact appears to open another: if the credit does not bound the
work before acceptance for a legitimate sender, it does not bound it for anyone,
and this account is never charged a gas fee either.

What bounds it is the order. A zero-identity operation settles every condition
an unentitled sender cannot meet -- the operation's shape, the compare-and-swap
against the policy in force, the nonce, the effective height, the policy chain
and its revision -- before the quorum is established, and the verification loop
stops at the first signature that does not verify. Measured against the real
contract at the installed committee and at the profile ceiling:

| what was sent | gas | verifications |
| --- | ---: | ---: |
| a certificate copied off the chain, now bound to a policy that has moved | 2,664 / 3,064 | 0 |
| a certificate of the right shape with signatures that are not signatures | 2,664 / 3,064 | 1 |

Neither is accepted and neither is committed, and both cost less than the ten
thousand of credit an ordinary account would have had -- so the path is not a
way to spend a validator's work for free, despite being a path on which work is
never charged for.

One seam is not covered by any of that, because it happens before there is a
transaction to meter. Admission to the message pool has to decide whether an
arriving external message is a registry update, and deciding opens the evidence
container: the authorizations are unpacked out of their byte tree, decoded, and
every attached object validated. The callback that work is given at
`native-registry-admission.cpp` accepts any size, and at this stage a
certificate is an opaque object identified by its own hash, so nothing in the
container has to be something that would ever verify.

The work is bounded -- one attachment per authorization kind, three kinds, sixty
four kilobytes each, and an inbound message ceiling of two hundred and fifty six
kilobytes below that -- and a container claiming more is refused rather than
unpacked. What is not bounded is the ratio between what the sender spends and
what the node does:

| one sixty-four kilobyte attachment | on the wire | to open | per wire kilobyte |
| --- | ---: | ---: | ---: |
| bytes that repeat | 551 | 2,392 us | 4,445 us |
| bytes that do not | 70,092 | 2,444 us | 35 us |

Identical leaves serialize once and are walked every time, so the same work
costs a sender a hundred and twenty-seven times less to send in one shape than
in the other.

The container states how many bytes it expands to before any of them are
touched, and the opening already charges that declared figure before unpacking
rather than counting afterwards. What was missing was anyone to charge: the
callback admission supplied accepted every size. It now supplies an allowance of
its own, and what it says exactly is this: no single unauthenticated expansion
may declare more than sixty-five thousand five hundred and thirty-six logical
bytes. It is not a budget for a message and not a budget for a container. One
opening expands a container at two points -- the authorizations blob, and the
attachments -- each bounded separately, so one opening may expand at most about
twice that; and the admission path performs one opening, because recognition
opens the container and what follows is handed the value it produced rather than
the root to parse again. Twice sixty-five thousand five hundred and thirty-six
is the figure to hold this against.

The allowance is not what execution allows and should not be -- execution
happens after a block has accepted the work, and this happens on
a stranger's say-so. A governance message declares three and a half thousand
bytes at the committee installed and fifty-eight and a half thousand at the one
the profile admits, so the allowance leaves room for the largest legal message
and refuses four times less than execution would.

| a sixty-four kilobyte attachment | admitted | to decide |
| --- | ---: | ---: |
| bytes that repeat | no | 2,431 ns |
| bytes that do not | no | 2,515 ns |
| a real four-hundred-signer certificate | yes | 1,146 us |

Refused in two microseconds rather than two thousand, and refused the same way
in both shapes, because the answer is about what a container declares and not
about how densely it was written down. The bound is a bound only because it is
applied first: moved after the unpacking it gates, every refusal is still a
refusal and the work it exists to refuse has already been done. That is the
mutation that holds it.

The single opening is held separately, by a check over the admission source
rather than by a test, because removing redundant work breaks nothing when it
comes back: every case still passes, twice as slowly. Reinstating the second
opening was watched to fail that check.

Why per expansion and not summed across them: a container's two expansions do
not measure disjoint bytes. An inline attachment lives inside the authorizations
blob and is declared by both, so summing them counts a four-hundred-signer
message as a hundred and sixteen thousand bytes and refuses it. Removing that
overlap means changing what the shared callback charges, which is what the
virtual machine charges a transaction, so it is a consensus change and belongs
to a tariff review rather than to a hardening patch.

What this does not do is bound repetition. [The ingress
audit](validator-auth-p0-ingress-audit.md) traces what does. A sender can still spend five hundred
bytes for two microseconds of refusal, as many times as they like. Three orders
of magnitude better than the same five hundred bytes buying two thousand
microseconds, and still a ratio. What an attacker can buy per attempt is now
bounded; how many attempts they can buy is a question about the ingress path and
not about this container, and it is open.

That is a property of the order and of nothing else, which is why it is held by
a mutation rather than by a comment: establishing the quorum before the
compare-and-swap leaves every refusal exactly as it was, refused for the same
reason, and costs a full verification the sender never paid for. Moving it there
was watched to turn the stale-certificate case red.

It cost seven entries a record until the identity stopped being revalidated for
every signer. The state is validated in full when it is opened, every key
descriptor loaded and checked once, so repeating that per record answered a
question already answered. What the reference cannot answer is whether the key
has expired, which is why two reads remain and not one.

The signatures are now charged too, and separately, because they are priced
somewhere else. The registry's charge comes from the work allowance it reports,
and certificate verification never touches that allowance -- its only bound is a
byte size. So the verification path announces each check to the caller just
before performing it, and the machine charges at the tariff it already publishes
for that primitive: the classical suite through the schedule and counter
CHKSIGNU uses, the post-quantum suite at the price its own instruction pays. No
number is restated in the registry, so the price and the primitive cannot drift.

Announcing before the work, rather than counting after it, is what makes the
charge worth having. A host that verified four hundred signatures and then found
the transaction could not pay would have done the work regardless. An allowance
covering thirty checks stops at thirty:

| verifications reported | crypto gas |
| ---: | ---: |
| 10 | 0 |
| 11 | 4,000 |
| 21 | 44,000 |
| 400 | 1,560,000 |

Ten are free because the transaction's existing allowance for signature checks
is the one the host draws on rather than a second one of its own. The count is
of verifications actually performed, not of records presented: a certificate
refused while its structure is still being read pays for none of them.

Those are components. The whole transaction has now been run rather than added
up: a real committee, a certificate every member signed, the real registry, the
privileged host and the compiled configuration contract, with the account's own
tick-tock after it.

| masterchain signers | transaction, counted | account tick-tock, not counted |
| ---: | ---: | ---: |
| 21 | 97,233 | 6,119 |
| 400 | 2,240,393 | 6,119 |

The masterchain block gas limits are underload five hundred thousand, soft one
million, hard two and a half million. Both transactions fit under hard. Only the
installed committee fits under soft, which is where a collator stops adding to a
block: at the profile ceiling a governance operation is a transaction that
closes the block it is in rather than one that shares it.

Only the transaction is measured against those limits, because only the
transaction is counted toward them. A tick-tock enters the block's limits with
its gas recorded as zero however much it used -- its logical time and size still
count -- while an ordinary transaction contributes all of its gas unless it is
one of the mint and recover special transactions, which a governance message is
not. So the account's tick-tock is measured as execution and excluded from the
comparison.

The sum of the components is not the transaction. At four hundred signers the
components come to one million eight hundred and sixteen thousand and the
transaction costs two million two hundred and forty thousand; the difference is
the contract, the instruction, and reading a certificate that is itself tens of
kilobytes.

What a post-quantum committee could be. The registry admits no such key, so
nothing here has run one; what follows is arithmetic on measured gas, with the
classical verification taken out of a real transaction and the post-quantum
tariff put in its place. Everything that is not verification -- the reads, the
contract, the instruction, and carrying the certificate -- is left at the
largest figure this suite has ever measured, six hundred and eighty thousand,
which is conservative twice over: a twenty-record ML-DSA certificate already
carries more bytes than the four-hundred-record classical one that figure came
from.

| masterchain signers | verification | with everything else | of the hard limit |
| ---: | ---: | ---: | ---: |
| 21 | 1,050,000 | 1,783,626 | 71% |
| 34 | 1,700,000 | 2,453,771 | 98% |
| 35 | 1,750,000 | 2,505,311 | 100.2% |
| 36 | 1,800,000 | 2,556,651 | 102% |

Thirty-four is the largest that fits and thirty-five is over by five thousand
gas, which is close enough that the boundary should be read as "the middle
thirties" rather than as a number to design against. Twenty-one is the installed
size for exactly this reason: it sits at seventy-one per cent with the boundary
a third of the way further out, rather than against it.

What no change of algorithm rescues is the four hundred the profile admits. The
block leaves 1,819,607 gas for verification there, which over the signatures
that are not free is 4,665 each, and the frozen certificate bound leaves 1,266
bytes each. Ed25519 fits both at 4,000 and 64 with almost nothing to spare. The
budget is within seventeen per cent of the cheapest classical signature, so no
post-quantum scheme reaches it -- a committee that size would have to stop being
one signature per signer, not carry a different signature.

The substitution is conservative twice over, so these are floors. Putting the
boundary exactly requires measuring what a post-quantum certificate costs to
carry rather than borrowing a classical one's cost for it.

The elector's own mandatory tick-tock is measured beside its contract, and
closing an election is larger than this whole limit at either committee size --
three million three hundred and fifty-five thousand at a hundred members before
this design exists, and three million seven hundred and fifty-five thousand with
it. None of that reaches the block's gas budget either, for the same reason, so
a maximum governance transaction and an election close can occupy one block
without the gas accounting objecting. What is left is what that accounting was
never measuring: the wall clock of a validator executing both, and the size and
logical-time limits, which tick-tocks do count toward. The cost is the
elector's, not this design's, and it is reported with its unactivated control
for exactly that reason; what this design adds is four hundred thousand at a
hundred members and six hundred and fifty-three thousand at four hundred.

Multiplying the work allowance by the price is not the bound either. That
allowance is an operational ceiling -- a million entries and two hundred and
sixty-eight megabytes -- and priced at sixty-four gas an entry it exceeds any
transaction envelope by orders of magnitude. The bound has to come from what one
operation can legally be asked to do: the largest admissible certificate, the
largest admissible identity shape, the exact reads and writes each implies, and
the fixed cost of the instructions around them.

Replacing a pending activation is not implemented. The activation rules say a
pending one may be replaced by a new currently authorized admin operation before
its boundary; a policy operation here requires its predecessor to be the policy
in force and adds the activation rather than superseding one, so an already
scheduled activation cannot be withdrawn or overwritten. The frozen rules do not
say which fields of an operation identify the activation being replaced, so the
rule is named as open rather than inferred from what the code happens to do.

`verify_current_governance` is read-only. Its caller must independently establish
the current native governing snapshot and inclusion-time registry state. Only
zero-identity policy/configuration operations and exactly one governance evidence
list are admitted. Verification binds the current policy, masterchain committee,
exact update and full-roster quorum, then checks every counted signer's current
role-5 key at inclusion. Retained historical consensus authority does not allow a
retired or expired management key to approve a new operation. Native configuration
voting, global nonce/CAS checks and atomic native application remain separate.

The C++ exporter and independent Rust verifier agree on 28 governance cases,
including a 400-member quorum, corrupt surplus signatures, extra authority lists,
foreign chain context and actual registry key rotation. Sixteen C++ and 17 Rust
compiled mutations fail their intended assertions. Full Ubuntu/ARM ASan, UBSan
and leak checks pass both new native drivers, with identical governance exports.
These results do not establish native elector/configuration execution or node
session integration.

## Native certificate proofs and verified client calls

The independent verifiers authenticate the native committee and selected policy
against the same complete masterchain anchor, then verify every supplied signature
and derive signer identities and weight from the full roster. `VerifiedNativeCertificate`
has a private constructor. An API result claiming a different weight, signer list,
certificate ID, duty, policy or committee fails whole-result equality.

Certificate claims are lookup locators only. The C++ RPC source must resolve the
expected native session and duty independently; the Rust client receives its own
trusted anchor, chain and expected duty. Method 12 rechecks archived certificate
bytes before publishing proofs. Method 13 validates request proofs and signatures.
Neither archive retrieval nor a remote result substitutes for local verification.
The currently tested history source is a controlled native-state fixture; a live
manager/history/archive adapter remains required.

The Rust client prepares each operation before sending its main request. For
method 13, preparation owns the already verified certificate and exact request ID,
anchor, chain and expected duty. Response verification consumes that value, checks
all bindings and compares the complete result without fetching proofs twice.
There is no ambient verdict cache. Method 12 verifies the proofs in the response.
Both methods enforce the two-million-byte binary bound before decoding.

The C++ public API distinguishes malformed proofs/signatures (`BAD_REQUEST`) from
an independently resolved duty mismatch (`CONTEXT_MISMATCH`). Source-history and
storage failures preserve their original error and retry semantics. The attachment
reader records trusted fetch failures separately from malformed content and clears
that provenance on each resolution. A backend outage cannot become a peer-input
error merely because verification encountered it.

The 55 shared positive/negative cases include full 400-member committees, shard
selection, unrelated anchors, resigned cross-genesis certificates, invalid policy
proofs, wrong sessions, surplus signatures, below-quorum certificates and forged
remote weights. The native RPC corpus uses 16 real snapshot encodings and checks
API error codes, retry flags and unknown/absent request-state semantics. C++ serves
both certificate methods over actual private Unix HTTP to the independent Rust
client, checking exact result bytes and exactly one fetch per proof chunk. Release
and fully instrumented Ubuntu builds agree; these are local RPC checks, not a
P0-enabled network rehearsal or remote HTTP/2/mTLS acceptance.

## Native replay and certificate cost

The independent Rust registry now constructs an offline genesis, preserves every
native control dictionary and applies consecutive identity updates. Its derived
deadline index removes only the canceled identity, retains other identities at the
same coordinate, and drops empty buckets. Canceled descriptors remain in the epoch
archive. The 34 native replay cases compare both continuously executed state and
freshly decoded checkpoints against C++ cell contents and hashes, including an
update beyond the first 400 identities. Controlled authority callbacks exercise
refusal; they do not establish elector or governance authorization. Both current
implementations still clone owned maps and are not persistent-dictionary apply
performance acceptance.

`benchmark-p0-c0` compares a 400-member VAC1 against the actual native Simplex
`BlockSignatureSet::check_signatures` over the same finalize candidate and role-3
keys. It admits all 2000 role keys before timing, checks full weight, corrupt
signatures on both paths and native block-ID substitution, then records 30 paired
post-warmup samples in alternating order. Three compiled removals prove those
controls reach the actual authentication and native context checks. CI executes
the controls; shared-runner timing is not a release performance gate.

The initial local macOS/ARM run measured 492.5 ms P0 versus 31.3 ms historical
median certificate verification. C++ now retains an admitted immutable OpenSSL
public key and uses Pure Ed25519's noncofactored double-scalar equation with a
fresh per-call context. Explicit strong public-key admission and canonical scalar
checks remain. Canonical computed-R equality enforces R encoding without rejecting
valid R=identity. Rust independently uses a public-input double-scalar operation
and the same canonical computed-R equality. Historical verifier code is unchanged.
The same local certificate case then measured 32.0 ms P0 versus 31.3 ms historical
(median +2.3%, p95 +1.9%). Frozen crypto vectors and native VM parity cover the
equation change; this measurement is not integrated native-session or propagation
acceptance. Use `measure_c0.py --build ... --out ... --enforce` on an idle machine
to record source, binary, compiler and available governor metadata. Allocation
counts and end-to-end propagation remain separate required measurements.

A separate isolated four-node historical-path rehearsal used the branch's actual
validator engine and independently queried all nodes' complete finalized block
IDs. It progressed with one validator stopped, rejoined that validator, and
started catchain sessions 0, 1 and 2 before stopping all owned processes. P0 was
disabled in this private genesis. This establishes a native compatibility baseline;
it does not satisfy the required P0-enabled multinode rehearsal.

## Registry capacity and scheduling decision

The confirmed committee limit is 400. It is not an implicit limit on all live
registry identities across elections, committees and future key registrations.
Historical keys and retired identities must remain independently retainable.

The implementation does not invent a 400-identity registry admission rule. Due
indexes are derived only from authenticated VAI1 records and rebuilt during
native state loading/replay. They never replace the committed transitions. The
archive keeps canceled and retired key versions; duplicate per-slot epochs are
rejected. Consecutive blocks apply due effects before administrative requests.

The initial native adapter admits at most one million entries / 256 MiB of decoded
values per local load. These are explicit operational limits: exhaustion fails
without truncating identities or history. It currently owns and copies maps for
transactional successor construction. Persistent native dictionary updates and
measured per-block work remain integration work; this adapter does not claim
constant work independent of archive size.

## Current local signer boundary

The signer validates independently supplied consensus permission, service permit
signature, exact key handle/reference and canonical VAS1 before reserving. It
syncs the journal and witness before a provider invocation. The provider syncs
its own reservation and consumes a witness claim before signing. It retains the
exact signature, verifies it and persists completion. The signer independently
verifies the signature, then syncs its complete result and witness before release.
A repeated completed request returns the original bytes and receipt. An uncertain
request remains reserved; it cannot automatically invoke the provider again.

The file witness is retained separately from signer/provider backup files. It
owns an exclusive OS lock and persists monotonically increasing writer generations,
journal frontiers, receipt hashes and consumed primitive requests. File restoration
against an intact witness fails closed. It is a software C0 deployment component,
not hardware evidence against rolling back the entire host/VM or losing the witness.
All three components currently require serialized ownership; automatic failover
and a remote/HSM witness require their own deployment evidence.

Local tests use real generated provider keys and Ed25519 signatures. Consensus
permissions remain controlled, independently typed test adapters. The issuer
rehearsal and separate-process crash drill use the production persistent receipt
key store; they still do not establish a running native consensus adapter.
Separate signer and provider/witness processes now exercise the production local
channel. The host serializes writer-generation changes and actual C0 primitive
execution in one dispatch loop. Both ends check OS peer credentials; private
socket mode, request bounds and deadlines precede request allocation/handling.

The local drill sends SIGKILL before reservation, before the primitive, after the
primitive and after complete commit. Unknown requests remain reserved without
another provider write; completed replies preserve their original receipt/fence
through signer and provider/witness process restarts. Losing the witness stops
calls. These are process-kill tests, not a claim of physical power-loss testing.
The actual fsync error-injection test separately verifies failure handling.
Multi-node native execution remains open. The frozen
profile, historical signature algorithms and historical encoding bytes remain unchanged.

Permits for a still-live old session can be renewed at a newer independently
trusted masterchain anchor. The VAS1 birth coordinate, keys, committee and policy
remain fixed; permit anchors before session birth are refused. This separates the
permit's bounded freshness window from native session lifetime.

## Service and attachment completion boundaries

`ServiceIssuer` owns a mode-0600 durable store for one independently configured
issuer, audience and purpose. Permit and receipt stores cannot sign each other's
body type. Rotation persists a fresh key and consecutive policy revision before
returning public configuration; it does not install that configuration into any
verifier. Old receipts remain verifiable against retained trust and the independent
witness. Current permit trust rejects older policies after rotation. Only typed
validated local expectations reach permit issuance. No private export/raw-sign
operation is exposed. Operational trust distribution remains separate work.

Native proof publication now stores larger proof BOCs before returning their
manifest. Publication failure produces an error. A real 128-identity registry
with pending operations exercises a proof exceeding 64 KiB. Verification also
counts reachable cells: the generic historical BOC parser can accept a BOC that
contains an unreferenced physical cell, but the P0 proof entry point refuses it.
The historical parser itself is unchanged.

The scoped store reserves complete advertised lengths against principal and
global budgets. Objects cannot be fetched under another principal or full anchor.
Its initial local admission policy limits each principal to four retained objects
in total, including completed objects, and 64 MiB; the global limit is at most
256 MiB. Expiry releases storage only. API parsing and association do not establish
object authority. The shared C++/Rust semantic tests deliberately use proof
fixtures only for attachment integrity; actual Merkle evidence comes from the
separate native proof tests.

Clients can preserve verified request-state observations. The C++ and Rust polling
helpers reject terminal-state regression or byte replacement and prevent a
reserved request from changing statement/fence. Callers must authenticate each
receipt against its original request context before retaining that observation.


## Durable administration and Rust lifecycle parity

The Rust per-identity lifecycle now follows the same frozen oracle as C++: all
four operations, nonce/predecessor checks, archived epochs, exact due coordinates,
bootstrap role-5 admission and read-only session key selection. The 104 shared
cases include missing or denied typed authorizations, 65536-block scheduling and
retained old-session keys. Global native registry storage is still a separate
Rust integration boundary.

Administration uses the existing safety journal and witness, with one shared
sequence of durable frontiers and independently witnessed receipts. Prepare
reserves its canonical request and binds the separate preparation ID to immutable
parameters; renewing a fence cannot change them. The provider first reconciles
that ID, then claims generation before creating private material. A restored
provider cannot regenerate a key after an intact witness consumed its claim.
The local provider admits at most 4096 retained keys; exhaustion does not evict
historical keys. This is an operational storage limit, not a chain registry limit.

Stage performs read-only lifecycle admission, current owner/admin verification,
independent permit verification and exact provider descriptor association before
reservation. That read-only admission requires PoP to be absent and exposes no
successor state. Final chain apply still requires real PoP. The reservation ID is
H(possession-request, complete PoP preimage), excluding permit/fence changes. The
provider persists a reservation, claims the primitive and retains its exact PoP;
the service verifies the signature before committing the complete result and
receipt. An uncertain stage remains reserved and cannot invoke the primitive
again through a renewed request. No generic raw-sign operation is added.

Retire and cancel validate the current administration and exact pending target,
then journal intent only. They never delete provider keys or modify chain state.
All three methods return original complete bytes on an identical request, even
after a new writer generation. Preparation can also reconcile a completed
provider preparation after its signer process died before recording the result.
Reserved/burned sign state receipts remain exclusive to method 5; administration
reservations are internal and expose no alternative public request-state schema.

The added local process rehearsal kills the signer before provider invocation,
after provider completion and after result commit for both prepare and stage. A
separate provider/witness process executes the actual C0 operations over the
credential-checked private channel. It checks exact recovery and refusal across
writer and provider restarts. These six cases supplement the four sign-process
boundaries. They do not replace physical power-loss or native multi-node evidence.
The administration tests use real C0 PoP, current identity signatures and persistent
service issuers; native owner account execution is still an explicitly controlled
admission fixture and is not claimed complete.

## Local API execution and Rust client

The generated route tables come from the frozen 15-method schema. `SignerApi`
dispatches signer methods 1..7 to the persistent services and methods 14/15 to the
principal/anchor-scoped object store. Configured principal, method and identity
admission is enforced before execution; a listener supplies the principal, never
a request header. Public-key reads and cached result queries apply the same
identity restrictions. Cached stage/sign/retire/result responses also require the
configured network/genesis. An unauthorized state query returns UNKNOWN, not an
unproved ABSENT. Malformed framing returns BAD_REQUEST with zero correlation ID
without starting a reservation.

`NativeClientRpc` serves profile, policy, registry and key proofs from an exact
anchor-bound native-state source. Certificate methods 12/13 additionally require
independent native chain, session/duty and certificate-history adapters. Their default
methods refuse unavailable history. The library does not infer finality from a
supplied root or install peer-supplied trust.

The local listener uses HTTP/1.1 over a private Unix socket. This is a local
transport only; remote HTTP/2 with TLS 1.3 mutual authentication remains a separate
implementation/deployment boundary. Both endpoints authenticate OS credentials.
Headers are bounded to 8192 bytes and 16 fields, bodies to 4194304 bytes, with a
five-second absolute I/O deadline. Duplicate headers, transfer encoding,
compression, redirects and protocol upgrades are refused. The private provider
channel retains its separate 2 MiB frame contract and shares credential checks.

The Rust client uses the generated route table, performs one explicit invocation,
checks canonical framing/correlation and semantic association, and fetches proof
attachments at the request's exact anchor with one aggregate reader budget. Its default
semantic verifier returns `UntrustedResult`; the native state verifier returns
`VerifiedNativeResponse` only after checking independently anchored chain proof.
Independent receipt trust remains a separate verification step. No transport error creates an
automatic mutation retry. Nonblocking I/O drains buffered bytes even when a peer
closes immediately after sending; timeout configuration does not discard them.

The API rehearsal runs real preparation, PoP, signatures, receipt verification,
cache reads, scoped chunks and native profile/policy/registry/key proofs over the
local socket, including Rust-to-C++ calls. The Rust native client now verifies the four state-proof methods itself,
including a referenced 128-identity page; receipt checks in the C++ signer
rehearsal use independent service trust and the retained witness. There are 44 HTTP boundary cases across C++/Rust and 37 Rust
client cases, including all 15 semantic fixture methods, fourteen error codes,
referenced proof fetching and exact invocation counts. Fixture responses are not
chain evidence. Seventeen API mutations and twenty-five HTTP mutations must
compile and fail their named behavioral assertion; seven Rust client admission,
association and correlation removals are part of the 35 Rust guard mutations.

## Rust native verification and one-budget client composition

`tos-validator-auth-native` uses the existing native Rust cell, BOC, dictionary
and Merkle implementation. It implements frozen AuthBytes packing/decoding with
exact canonical partitioning, payload SHA-256, size/depth/occurrence admission
and declared BOC table sizes checked before native allocation. C++ and Rust read
each other's incompressible objects through the 32 MiB boundary. Historical
native codecs are unchanged.

The native state verifier independently checks the full pinned anchor, network,
masterchain state, Config8 capability, mandatory/critical Config9/10 membership,
Config16 ceiling, Config46 version/domain/fingerprint and selected C0 policy.
It recomputes the requested profile/policy/key or complete registry page from
proved dictionaries, rejects detached physical cells and unrelated revealed
values, and compares the complete canonical result. Queue/account roots and
native auxiliary headers are admitted while unrelated descendants remain pruned.

`Client::call_verified` shares framing, correlation and one attachment reader with
an output-specific verifier. The default semantic output remains explicitly
untrusted. `NativeStateVerifier` returns a privately constructed verified type;
it receives an independently established anchor/network, not a peer's new trust
claim. A referenced proof is fetched once, within that same operation budget.
No second semantic decoder re-fetches or double-charges it.

Current native evidence contains 64 cross-checks, including 21 C++-produced native
proof cases and 32 cross-language pack/unpack cases. The 58 Rust HTTP client cases
include those 21 native positive/negative proofs over actual Unix connections.
The real local API test verifies all four native state methods and a referenced
128-identity page in Rust, checks exactly one chunk call, and also exercises the
persistent C++ signer services. Six additional C++ proof mutations and seventeen
Rust native mutations require compiled, named assertion failures. Exported fixture
sets carry completion markers so a missing/partial export cannot silently pass.

Rust linting covers both modified authentication crates with warnings denied;
`--no-deps` excludes unrelated pre-existing lints in the native block dependency.
That dependency is still compiled and executed by the native tests. Rust global
registry governance apply, owner execution proofs and production node and CLI
wiring remain separate implementation work.


## Native Keyring designation and concurrency

`Keyring::create` installs the isolation layer used by the existing node callers.
The trusted local `protect_validator_auth_key` method blocks new private operations,
drains already-issued raw operations, durably records the public-key hash and then
acknowledges protection. All raw signing forms, decryption, single/bulk secret
export, permanent/temporary import and deletion check that layer. Public metadata
remains available. Retire, cancel, branch rollback and reimport have no removal API.
A bulk export fails explicitly instead of silently returning an incomplete backup.

Legacy instances hold shared directory locks. Designation requires an exclusive
upgrade after local raw operations drain; a competing legacy instance prevents
acknowledgment. A failed upgrade stops that already-drained instance because OS
lock conversion can release its shared lock. A pending designation also blocks
new exports and admissions, including unrelated keys, until the finite drain ends.
Unrelated network keys remain usable by the owning instance afterwards.

The `validator-auth-guard` directory is a durable initialization marker. Its ledger
uses the existing durable-log framing, checksums, exclusive writer lock and sync
rules. Designation requires a same-owner Keyring directory that is not writable
by group or others. Missing/corrupt records, wrong ownership/permissions, links, detached or
replaced open ledger paths and uncertain writes fail closed. The deny archive has
an operational bound of 1,048,576 public-key hashes and a 128 MiB log; exhaustion
stops new designations without dropping history. Empty-directory temporary keyrings
cannot acknowledge persistent protection. This is local storage, not a new wire type.

`test-p0-keyring` uses real native keys and the actual factory, including a separate
process that holds a legacy keyring open. Its actor probe places raw signing and
protection in the same turn, proving that the protection callback follows the raw
result and that private exports are blocked during the wait. The historical
`test-keyring-temp-key` still passes. `keyring_mutations.py` requires exact assertion
failures after compiling the removed guards; unrelated errors and crashes do not
count. AddressSanitizer and UndefinedBehaviorSanitizer also cover the new Keyring,
isolation and durable-log sources through the same complete process test. Local
macOS testing disables leak detection; Ubuntu CI enables it.
Provider inventory reconciliation before native session admission remains
required: a local deny file alone cannot detect restoration of an entire host to
an earlier state without any designation. No hardware rollback claim is made.

The design-era whole-file boundary was evolved deliberately for native integration.
`doc/validator-auth-p0-native-insertions.json` lists the exact added bytes and their
original offsets; `check_production.py` reconstructs and hashes the original files.
The freeze record also covers this insertion inventory and updated evidence scripts.
Historical verifier bodies and historical encodings are unchanged.


## Native VM entry and whole-transaction rehearsal

[The native execution contract](validator-auth-p0-native-vm.md) defines VAUTH_CHKSIGN
at `0xf917`. It preserves raw frozen C0 statement bytes and the existing CHKSIGNU /
CHKSIGNS behavior. Both runtimes require VM version 16 and capability 1024, read
only canonical AuthBytes, meter every invocation and inherit immutable capability
metadata in child execution. The capability is registered in the native inventories;
no configuration enables it on a network.

C++ and Rust compare 168 executions, including 98 real/falsified frozen-signature
inputs, valid identity R, canonical carriers, malformed operands, version gates,
exact gas exhaustion and historical disabled-instruction charging. Five compiled
adapter removals separately falsify constructor, RUNVM, getter, config-load and
transaction-compute capability propagation. The independent C0 primitive is shared
within each language without making the VM depend on signer or protocol state.

The public FunC binding is compiled into a local test probe and executed in the
actual native emulator and Rust transaction executor. Eight transactions agree on
compute exit, action result, out-message hashes, balance and stored data. Positive
transactions relay; bad signatures are refused; insufficient send funds roll back
the probe's attempted data change; disabled capability refuses execution. These are
real transaction/action-phase tests with controlled local configuration, not an
owner authorization proof or a native multinode rehearsal.


## Native election binding and committee selection

[The native committee contract](validator-auth-p0-native-committee.md) defines the
additive 0xb3 descriptor and anchored native adapter. It preserves historical
constructors and the independent 0x93 sequence-number extension. C++ and Rust
preserve explicit identity/stake bindings through total-set export, main-chain
shuffle and shard selection; no public-key search allocates an identity.

The native corpus compares 40 independently derived VAM1 objects/admissions and
transport orders, including a full 400-member committee. It covers native Config35
precedence, complete elected-set binding, Config16 limits, exact activation gates,
selector bounds and the shard weight of one. Shared entry-view budgets refuse
partial reads without enumerating unrelated archive history. Retiring a required key makes a new snapshot fail while old owned
snapshots retain their original keys and denominator.

The new Rust registry reader independently checks native dictionaries, retained
policies, immutable key hashes/epochs, identity references and pending/control
records. This completes native snapshot reading, not Rust global mutation apply.
Elector/config execution, native session/consensus routing,
node RPC adapters and P0-enabled local multi-node acceptance remain open. Legacy JSON tooling preserves native
bindings but remains a metadata interface, not authenticated P0 update authority.


Native proof and committee fixtures also run with full address/undefined-behavior
instrumentation and leak detection. This exposed temporary-hash slices in the
shared anchor helper and proof-substitution fixture; both now retain the owning
hash through the copy. Two compiled ownership removals fail a named lifetime
assertion before a poisoned-memory read, and release/sanitized exports must match.
The committee boundary has 23 C++ and 25 Rust compiled guard removals, including
unselected duplicate members, descriptor propagation and equality, native selector
bounds, native zero-network admission and whole-registry resource budgets. Those
48 guards and the two lifetime checks are included in the total above.


The authenticated entry view adds 21 C++/Rust cases and 30 compiled guard removals.
They distinguish whole-registry validation from snapshot lookup, compare exact
remaining budgets, test 10000 archived keys and reject missing required proof nodes.
The kind-5 native committee proof producer/verifiers add 25 cross-language cases
and 16 compiled guard removals for anchor/object binding, minimal revealed nodes,
detached physical cells, header reads and publication before returning a manifest.
These paths run under full native ASan/UBSan/leak instrumentation with byte-identical
release and sanitized fixture exports. They provide committee proof authority;
production session/consensus call sites and node RPC adapters remain open.


## Native config tools and voting input

Configuration JSON preserves the native identity/stake binding through Config32
through Config37, the control client and the actual voting-provider method. A
shared typed binding representation rejects incomplete, noncanonical and zero IDs.
P0 binding/ADNL/sequence-extension conflicts, declared-count mismatches, integers
outside native widths and P0 lists above 400 return errors. The raw control-client
parser also rejects recursive and escaped duplicate keys, oversized/value-heavy
JSON and trailing documents; it is reused by the voting provider.

The 47-test native JSON suite includes 24 exact cell round trips across six
parameters and four descriptor formats, plus malformed binding and count bounds.
Four focused control-client tests and one real voting-provider test cover metadata
preservation, native numeric widths, strict raw JSON and shared dispatch. The 24
compiled guard removals are included in the total above. A separate focused CI job
builds these real packages on Ubuntu x86_64 and ARM. This metadata does not grant
owner, identity, possession or governance authority.
