# Treasury Vault V1

## Status

Implementation proposal. Do not deploy with real funds before the native transaction tests, sensitivity controls, independent review and deployment ceremony have passed on the exact reviewed commit. Existing wallets and consensus rules are unchanged.

## Objective and threat model

Protect a treasury when a business host, its deployment credentials and its online signing capability are compromised. An online business signer must not authorize payment alone, change security roles, increase budgets, install code or disable protection. This is a contract-enforced authorization boundary, not a malware detector.

The guardian must obtain withdrawal intent independently and decode the exact on-chain request. Separate keys on hosts controlled by the same administrator, or approvers that trust the same compromised input, are not independent protection. Compromise of the final cold governance quorum, a supported token's implementation, consensus, or all required approvers is outside the prevention claim. Budgets provide bounded exposure, not zero loss after all payment approvers are compromised. The guardian and pauser are online or semi-online roles and are expected to be compromised eventually; the design therefore guarantees that the cold administrator can always replace them given time, not that a compromised hot role cannot interrupt service. Storage fees and service availability remain operational responsibilities.

## Architecture

Deploy a new, immutable `crypto/smartcont/treasury-vault-code.fc` contract. Do not modify the semantics of the general multisig or Agent Account. Existing authenticated wallet accounts send internal messages; the vault checks the VM-provided sender. They can use existing classic or post-quantum account authentication. The vault neither introduces a signature algorithm nor claims that a key is independent merely because its address differs.

Four distinct canonical workchain-0 addresses are configured: business, guardian, cold administrator and emergency pauser. None may equal the vault. The cold administrator should be an existing, independently controlled multisig account. It is the calling account's responsibility to meet that multisig threshold; the vault does not infer a threshold from an address. The cold administrator address is fixed for the vault's lifetime: no governance request can replace it, and cold key rotation happens inside the cold multisig account. An immutable address does not make that multisig's own code or quorum rules immutable; they remain part of the trusted cold boundary and must be verified separately.

V1 has one pending payment, one pending management request, and at most 16 registered assets. It deliberately favors a small auditable state machine over exchange-scale parallel throughput. This is not a highload-wallet replacement.

## Required security properties

1. **Two independent payment roles.** Business proposes one exact payment. Guardian must approve that same request before any outgoing value message is created. Neither role alone can pay or change policy.
2. **Domain and replay binding.** Requests bind a versioned domain, network global ID, exact vault address, policy epoch, sequential request nonce, expiry and complete typed payload. Payment and management domains and counters are separate. Stale, malformed, trailing or mismatched data fails closed.
3. **Typed payment only.** Native TOS transfer or the explicitly supported Token transfer wire format. The vault builds the outgoing message. No caller-supplied action lists, arbitrary call bodies, send modes, StateInit, delegate installation, code replacement or account destruction.
4. **Per-asset accounting.** Each registered asset has a per-payment ceiling, a fixed 24-hour accounting-window ceiling and a cumulative ceiling. The cumulative spent counter never resets on configuration changes. Window limits are not advertised as strict rolling-24-hour limits: adjacent windows may permit a burst across their boundary.
5. **Asset identity.** Native TOS uses asset ID zero. A Token uses its canonical workchain-0 master address hash as its nonzero ID and a cold-approved, immutable source Token-wallet address. Registration requires independent verification that this wallet belongs to this vault and that its code/master implements the supported standard. This is a trusted asset registry, not an on-chain proof of a token implementation's correctness. V1 does not support rebinding a registered source wallet.
6. **Separate cold management.** Only the cold administrator can schedule role changes, asset registration/limit changes or unpause. Every change waits an immutable 48 hours; applications cannot shorten this delay. Execution revalidates the request and its epoch. No administrator entry point directly sends assets. The cold administrator address, the delay and the code are immutable: a role change rotates business, guardian and pauser only, and a request that names a different cold administrator is rejected at scheduling and again at application.
7. **Emergency action only tightens.** Guardian, pauser or cold administrator can pause immediately and invalidate pending authorizations. Unpause requires delayed cold administration. A dedicated pauser cannot pay, raise limits or install new roles. Pending management can be vetoed by the guardian, pauser or cold administrator, with one exception: a guardian or pauser cannot veto the role change that replaces its own address, so a compromised hot role cannot block its own removal. The cold administrator's veto is unrestricted. Pausing clears a pending role change, but a paused vault refuses a second pause, so a compromised hot role can delay its replacement by at most one further 48-hour round. Recovery restores trusted roles; it does not guarantee uninterrupted availability, because a newly installed role that is in turn compromised can pause again.
8. **No approval resurrection.** Successful policy changes advance the epoch and invalidate the pending payment. Cancellation and expiry consume the respective sequence. Counters reject exhaustion before mutation.
9. **Conservative asynchronous accounting.** Debit budgets when dispatch is committed. Never automatically credit budgets on a bounce, notification or excess message. A local action-phase failure must revert the dispatch and its accounting together; a downstream token failure consumes budget until a separately authorized increase. This avoids fake receipt/retry amplification at the cost of conservative availability.
10. **Principal is not a fee subsidy.** Only funded internal control messages are accepted. Guardian funds dispatch fees and Token gas attachments. Outgoing actions preserve pre-message principal except for the explicitly approved native amount and keep a minimum storage reserve. The contract never accepts an unauthenticated external message or uses carry-all/destroy modes.
11. **Bounded storage.** Pending slots are constant size; supported payloads have fixed schemas; asset registration stops at 16 entries. Unknown notifications cannot create state. No unbounded per-order history or receipt map is stored.

## Payment lifecycle

`empty -> business proposal -> guardian approval -> dispatch -> empty`.

Approval must carry the identical request hash, epoch, nonce and unexpired typed payload. Business or guardian may cancel a pending payment; anyone may expire it after its deadline. Cancellation does not move assets. Pausing invalidates pending payment and management authorizations. A submitted proposal is not a completed payment: clients must inspect the resulting outgoing message and downstream Token transaction.

Payment payload fields are asset ID, asset units, canonical recipient and a bounded Token gas attachment. Native payments require a zero Token attachment. Token payments use zero forwarded application value, no custom payload and the vault itself as the excess-return destination. Arbitrary recipient hooks are not available through the native payment body.

## Management lifecycle

`empty -> cold proposal -> 48-hour delay -> apply -> empty`.

Only one proposal may be pending. Its deadline is bounded and must leave time after the delay. Applying a change is permissionless after the delay but requires the exact queued request. Cancellation/veto consumes its nonce. Asset changes preserve existing accounting and cannot replace the source wallet. Role changes enforce pairwise separation and must keep the current cold administrator. Unpause is its own delayed change. No generic upgrade, recovery sweep or bypass is provided. Recovery consists of delayed replacement of the hot roles; loss of the final cold authority permanently impairs recovery, so operators must rehearse the cold multisig procedure. Any path that could move the cold authority would be equivalent to replacing the vault's code, and one deceived cold signature would then be unrecoverable; with a fixed cold address the honest quorum retains ultimate authority after any single bad signature.

## Deviations from the original requirements

The following points differ from the original requirement draft on purpose and are accepted for V1. They are design revisions, not omissions.

| Item | Original draft | V1 | Note |
|---|---|---|---|
| Periodic budget | UTC calendar day | Fixed 24-hour window counted from its first debit | Not a sliding 24-hour limit; adjacent windows can permit a burst across their boundary. |
| Token transfer gas | Debited from the vault's native budget | Supplied by the guardian with the approval message | The vault reserves its pre-message principal; the guardian's own operating balance and signing costs are not protected by vault budgets and need their own limits. |
| Registered assets | 32 | 16 | Smaller V1 scope; the bound is enforced on chain. |
| Pending payments | 1 | 1 | Unchanged; the vault is not a high-throughput withdrawal system. |

## Integration and deployment

**Post-quantum deployment requirement.** The vault contains no signature check and no public key; it authenticates roles by the sender address of an internal message and compares requests by cell hash. Its resistance to a quantum adversary is therefore exactly that of the four role accounts. A production deployment must use post-quantum authenticated accounts for all four roles, and the cold administrator must be a post-quantum multisig account: the cold address is immutable, so a classical multisig in that role could only be replaced by redeploying the vault and migrating its assets. Post-quantum accounts require TVM global version 16 or later. The post-quantum multisig account for the cold role is `crypto/smartcont/pq-multisig-code.fc` (`doc/pq-multisig.md`); its cold leg against the vault is executed by `test/treasury-vault/test_pq_cold.py` (issue #378).

Provide deterministic request/state builders and getters for configuration, pending requests and budgets. Derive a fresh address from the new StateInit; do not suggest existing deployed wallets are upgraded by a source-code change. Verify the deployed code hash, all role addresses, chain ID, empty initial registry and counters before funding. Register supported assets through the cold delay, rehearse a small payment and a pause/recovery drill, then migrate bounded balances.

V1's initial registry is empty. The first asset registration uses the same delayed governance path as subsequent ones. Operations must maintain storage reserves on the vault and its authorizing accounts. No production deployment or asset migration is performed by this implementation PR.

The cold administrator leg is executed end to end by `test/treasury-vault/test_pq_cold.py` with the post-quantum multisig account: a below-threshold set of signers produces no governance proposal, a threshold set produces exactly one, the vault still enforces its own 48-hour delay afterwards, a multisig veto and pause are accepted, and the multisig has no payment path. Before any funding, the same scenarios must be re-run against the exact production candidate (code hashes, member set and quorum) and the result recorded; issue #378 tracks that acceptance.

## Acceptance tests

Tests must compile the current source and execute full transactions on the native action-phase emulator. A Python model or successful FunC compilation alone is not execution evidence. The business and guardian roles must additionally be exercised through real signing wallets, both classical and post-quantum: an Ed25519 key signs an external message to a wallet-v5 account, and an ML-DSA-44 key signs a relayed request to a post-quantum high-volume wallet; in each case the wallet executes on the emulator and its actual emitted internal message is delivered to the vault unchanged. Required scenarios:

- business-only, guardian-only, forged sender, wrong request and repeated approval rejection;
- through real wallets: a signed business proposal and signed guardian approval pay out, the business wallet cannot approve, a guardian approval for other content is refused, an emitted approval cannot be delivered twice, and a message signed with the wrong key is refused by the wallet before it reaches the vault;
- the same scenarios through post-quantum wallets, with the VM log showing that an ML-DSA-44 verification actually executed for every accepted request;
- the cold leg through the post-quantum multisig: below-threshold, non-member and over-count signatures refused before verification, threshold produces exactly one governance message, the vault's delay still applies, veto and pause accepted, no administrator payment path, and a full post-quantum lifecycle;
- correct native payout and exact Token outgoing wire/body/destination;
- per-payment, window and cumulative ceilings, split payments and independent assets;
- wrong chain/account/domain/epoch/nonce, expiry and malformed/trailing input;
- no Token amount bypass via a small native gas attachment;
- Token-side rejections in their own right: window and cumulative ceilings, disabled or unregistered Token IDs, a paused vault, a guardian message that does not fund the attachment plus the control fee, and raw payloads the developer codec would refuse (zero or oversized Token attachment, native payment with an attachment, zero amount) so the contract's own guards are the ones that fire;
- management cannot execute early, hot roles cannot schedule it, veto and expiry work;
- role changes invalidate old approvals; budget changes never reset cumulative spending;
- the cold administrator cannot schedule its own replacement, even through a valid delayed request;
- a replaced guardian or pauser cannot veto its own replacement, retained roles and the cold administrator keep their veto, an expired pending request stays vetoable, and a pause can clear a pending replacement only once;
- pause, delayed unpause, role recovery and lack of a direct administrator payment path;
- unknown/bounced messages cannot release budget or mutate policy;
- local action failure has no outgoing payment and no committed budget debit;
- asset-count limit, pending-slot limit, overflow and state-size bounds;
- mutation controls: remove a guardian, budget, timelock or replay guard and observe its targeted native regression fail.

Record exact commands, source hashes and results. Missing native tools must fail the native runner, not silently skip tests. Do not mark tests as passing until they have actually run.
