# EVM chain-ID domain separation for coin-bridge vote digests

Status: **Implemented and locally verified; not approved for deployment.** This
change alters all three EVM signed payloads, test signers, golden vectors,
repository verification, and the reviewed-delta record. The production oracle
signer is outside this repository and must adopt the pinned wire format before
deployment. The deployment and independent-audit gates in §6 remain open.

Scope: the EVM part covers the `coin-bridge` EVM/Solidity plane **only**. The
newer `token-bridge` is **not** affected there — its
`evm/contracts/SignatureChecker.sol` already binds `block.chainid` in all four
of its digests (`abi.encode(<magic>, address(this), block.chainid, …)`),
inherited from its own, newer upstream. token-bridge is therefore the in-repo
reference for the layout this implementation adopts, not a second thing to fix.
This matches `SECURITY.md`'s wording that the affected plane is "the historical
Solidity plane [that] predates the token bridge."

The TVM part (§3) is wider: the symmetric network binding described there
applies to **all three** TVM multisigs — coin-bridge's
`tvm/{ethereum,bsc}/multisig-code.fc` *and* token-bridge's
`tvm/contracts/multisig.fc` — because all three inherited the same query
layout, which separated deployments but not networks.

## 1. The problem

Before this change, the oracle vote digests on the EVM side used the bridge
contract address as their only domain separator. They did **not** bind the EVM
chain ID.

The inherited `evm/contracts/SignatureChecker.sol` produced three digests, all
of the form
`keccak256(abi.encode(<magic>, address(this), <fields...>))`:

| Function | Magic | Purpose |
|---|---|---|
| `getSwapDataId` | `0xDA7A` | authorize a TOS→EVM mint/release |
| `getNewSetId` | `0x5E7` | rotate the oracle set |
| `getNewBurnStatusId` | `0xB012` | toggle the burn (EVM→TOS) path |

An oracle signs `"\x19Ethereum Signed Message:\n32" || digest` (see
`checkSignature`). The digest commits to `address(this)` but to nothing that
distinguishes one EVM network from another.

### Why this is a replay surface

`address(this)` works as a domain separator **only for as long as the same
bridge address never exists on a second EVM chain whose current oracle set shares
enough signers with the signatures an attacker already holds.** State the
condition precisely — a replay from chain A onto chain B succeeds when both hold:

1. **Same contract address on A and B.** With `CREATE2` this needs the same
   deployer, salt, and init code; with plain `CREATE`, the same deployer and the
   same nonce. Operators frequently *want* one address on every chain for
   discoverability, so this is a realistic, often deliberate, configuration.
2. **Quorum-carrying signer overlap.** The signatures gathered on A must contain,
   among signers that are members of B's *current* oracle set, at least B's
   quorum:

   ```text
   | signers(A signatures) ∩ current_oracle_set(B) | >= ceil(2 * |oracle_set(B)| / 3)
   ```

When both hold, the chain-A signatures verify byte-for-byte on B — same address,
magic, fields, digest, `ecrecover` — and an attacker replays them to drive a mint,
an oracle-set rotation, or a burn-status flip that no chain-B oracle intended.
Mere set overlap is not sufficient; the overlap must reach B's quorum.

### This is inherited from upstream, verbatim

`NOTICE.md` records the coin-bridge Solidity provenance (the pinned upstream
`bridge-solidity` commit). That older upstream uses exactly this
`abi.encode(magic, address(this), …)` scheme with no chain ID, which coin-bridge
inherited before this intentional reviewed delta. The newer token-bridge derives
from a different, later upstream (see its own `NOTICE.md`) that already carries
`block.chainid`; token-bridge's reviewed-delta list does not add it, so chain-ID
binding came from that newer upstream, not from TOS. This is therefore a
generational gap in the upstream lineage, not a TOS regression: coin-bridge is the
older plane and its upstream never added the separator.

**Do not assume the older scheme is safe in practice because "addresses and
oracle sets differ."** The pinned upstream does *not* enforce that: its own
`migrations/1_initial_migration.js` wires the **same** oracle set across chains
(the same operator keys for the two mainnet EVM targets, and again for the two
testnet targets), and nothing in the upstream repo forces distinct deployment
addresses. So the operational separation that would make `address(this)`-only
sufficient is an assumption about how a specific deployment is run, not a property
the code or upstream tooling guarantees. Whether any real TOS deployment would
avoid the replay condition can only be established with independent on-chain
evidence — it cannot be inferred from the source. TOS's `SECURITY.md` was right to
flag this rather than inherit the assumption silently.

## 2. Implemented fix

The implementation binds the EVM chain ID into every EVM vote digest, so a signature is
cryptographically valid in exactly one configured chain-ID domain regardless of
deployment address. (Binding the chain ID cannot stop replay between two networks
that *share* a chain ID — see the signer requirement in §3 that every target
network's chain ID be distinct.)

The chain ID is an explicit field in each `abi.encode`:

The code adopts the **exact field ordering token-bridge already uses** —
`<magic>, address(this), chainId, <fields…>` — so the two bridges share one
layout and token-bridge's working tests are a template.

coin-bridge is on `pragma solidity ^0.7.0`, where the Solidity global
`block.chainid` does **not** exist (it is a later-Solidity member). Under 0.7.x
the chain ID is read with the Yul `chainid()` opcode via a tiny helper, and the
digests use that helper:

```solidity
// Solidity 0.7.x: `block.chainid` is unavailable; read the opcode via assembly.
function getChainId() internal pure returns (uint256 id) {
    assembly { id := chainid() }
}

// getSwapDataId
keccak256(abi.encode(0xDA7A, address(this), getChainId(),
                     data.receiver, data.amount,
                     data.tx.address_.workchain, data.tx.address_.address_hash,
                     data.tx.tx_hash, data.tx.lt));

// getNewSetId
keccak256(abi.encode(0x5E7, address(this), getChainId(), oracleSetHash, set));

// getNewBurnStatusId
keccak256(abi.encode(0xB012, address(this), getChainId(), newBurnStatus, nonce));
```

(On a 0.8.x bump the helper body becomes `id = block.chainid;`; the abi.encode
layout — and therefore the digest and the golden vectors — is identical either
way. This exact layout is what the golden vectors in §5 pin.)

Notes and alternatives considered:

- **Keep `address(this)` as well.** Chain ID separates chains; the contract
  address still separates two independent bridge instances on the *same* chain.
  Both belong in the preimage (defense in depth), so this is additive.
- **Pragma decision (concrete).** coin-bridge pins `pragma solidity ^0.7.0`,
  where the `block.chainid` member does **not** exist; it would need the
  `chainid()` opcode via inline assembly (EIP-1344, Istanbul). token-bridge, by
  contrast, is on `pragma solidity ^0.8.9` and uses the `block.chainid` member
  directly. This change stays on `0.7.x` and reads `chainid()` via the assembly
  helper (the smaller diff); a `0.8.x` bump would have created a wider
  recompile/audit surface. The value is read live per call (not cached at
  construction), so a chain-ID change invalidates signatures from the old domain.
- **EIP-712 typed-data domain** (`{name, version, chainId, verifyingContract}`)
  is the canonical, tooling-friendly form and subsumes both `chainId` and
  `verifyingContract`. It is the recommended target if the oracle/relayer signer
  is being rewritten anyway; the minimal `abi.encode` addition above is the
  smaller change if signer churn must be minimized. This implementation uses the
  minimal addition and flags EIP-712 as a possible future protocol revision.

### Tron: a known-unverified chain-ID surface

Binding `chainid()` presumes the EVM the contract runs on returns a stable,
network-unique chain ID. On Tron this is not settled. token-bridge already
targets Tron (`tvm/params/tron.fc`, ConfigParam 83) and its `NOTICE.md` records
that slot and its Tron chain ID "have no upstream counterpart at all" and that
"deployment to a public Tron network, and the chain id of that network
specifically, remain unverified." coin-bridge has no Tron target today, so adding
`chainid()` does not introduce a Tron dependency by itself — but if coin-bridge
is ever extended to Tron, the same unverified-chain-ID caveat applies, and the
golden-vector test (§5, item 5) must be run against Tron's actual `chainid()` return
before any Tron deployment. Flagging it here so the two bridges' Tron stories stay
consistent.

## 3. Cross-plane coordination (why this cannot be a one-file change)

The digest is reproduced by **every** party that signs or verifies it. All must
change atomically or the bridge stops verifying its own oracles:

1. **On-chain EVM** — `SignatureChecker.sol` (the three functions above).
2. **The off-chain oracle/relayer signer** — the watcher that observes a TOS
   event and signs the EVM digest must include the chain ID in byte-identical
   order. Critically, the signer must not read the chain ID from an arbitrary RPC
   per call: it MUST pin an `expected_chain_id` in its audited deployment config,
   verify at startup that its target RPC actually returns that value, refuse to
   run on a mismatch, and treat any chain-ID change as a governance/deployment
   event — never a silent runtime input. The set of `expected_chain_id`s across
   all target networks MUST be pairwise distinct (a shared chain ID re-opens the
   replay the digest is meant to close). (The relayer implementation lives outside
   this repo — `~/relayer` is still spec-only — so this is a forward constraint
   recorded here, plus a golden vector, see §5.)
3. **The test signer** — `evm/test/utils/utils.js` (`encodeSwapData`,
   `encodeSet`, `encodeBurnStatus`) mirrors the contract's `abi.encode` and now
   requires the same explicit `chainId` field in the same position.

### TVM symmetric analysis

The EVM→TOS direction has oracles signing messages consumed by the TOS-side
multisig (`tvm/{ethereum,bsc}/multisig-code.fc`, and the token bridge's
`tvm/contracts/multisig.fc`). All copies compute `hash = slice_hash(in_msg)`
before consuming any query field. The hash therefore commits to the 32-bit
`wallet_id` and the complete destination message, including its destination.
The contract then independently enforces `query_wallet_id == wallet_id`;
pending-query continuations also require the stored message hash to equal the
submitted message hash.

An earlier revision of this document concluded that no symmetric TVM change was
needed because the query binds `wallet_id` and the destination. That reasoning
holds between two multisigs *deployed differently*, and no further. `wallet_id`
and the destination address are both **address-scoped, not network-scoped**
values: two TOS networks bootstrapped from the same StateInit (a testnet and
mainnet, or a rehearsal chain) carry the same `wallet_id`, the same multisig
address, and the same bridge addresses on both networks. If the oracle set also
reuses its signing keys across those networks — the same operational reality §1
documents for the EVM side — a query signed on one network (for example a
release of TOS after a burn on a test EVM bridge) verifies **verbatim** on the
other and releases real funds there.

The TVM side therefore now binds each signed query to the network itself. The
signed body carries a 32-bit signed `global_id` immediately after `wallet_id`,
and every multisig compares it against the network's own identity — the value
of `ConfigParam 19`, read with the `GLOBALID` instruction, exactly as the
repository's wallet contracts do — rejecting a mismatch with **exit code 44**:

```
int query_global_id = in_msg~load_int(32);
throw_unless(44, query_global_id == get_global_id());
```

Both `slice_hash` computations (the root-signature hash and the co-signature
hash) are taken before any field is parsed, so every oracle signature already
covers the new field; no re-serialisation path (pending-query storage,
`unpack_query_data`, the get methods) depends on field offsets and none needed
adjustment beyond the body carrying 32 more bits. The message-size bound is
computed on the referenced message after the fixed header and is unchanged.

Every builder of signed queries must insert the target network's `global_id`
after `wallet_id`, and the value must come from pinned deployment
configuration verified against the target network — never from an arbitrary
RPC at signing time. Deployment manifests must still assign pairwise-distinct
`wallet_id` values and StateInit/address identities to the Ethereum and BSC
multisigs; the network binding is defense in depth for the deployments where
those identities coincide by construction.

## 4. Upstream-parity impact

This is a **deliberate divergence** from the pinned upstream `bridge-solidity`
commit recorded in `NOTICE.md`:

- `NOTICE.md` records the signed-payload change as reviewed delta 8 and points
  to the committed wire vectors.
- `scripts/verify-coin-bridge.py` is a repository source-invariant check, not a
  byte-for-byte upstream diff. It now requires the exact three-field-prefix
  ordering, the dual-chain test and golden vector, the NOTICE delta, and the TVM
  wallet/message-binding invariants. Any future upstream comparison must treat
  this one signed-payload change as an intentional difference.

## 5. Implemented tests

All of the following are committed and pass locally.

**EVM unit (core replay property):**
1. `evm/test/chainid-domain-separation.js` runs two Ganache instances with
   chain IDs 7001 and 7002, the same deployer and nonce, the same oracle keys,
   and therefore the same `Bridge` address. A quorum signs on chain A; chain B
   rejects the identical mint call.
2. The same test rejects the chain-A signatures for oracle-set rotation and
   burn-status switching on chain B, then proves B's supply and governance
   state remain unchanged.
3. It separately creates valid legacy-format signatures (digest without chain
   ID) and proves the new deployment rejects all three vote types. The contract
   is not upgradeable; this is a property of the new build, not an in-place
   change.

**EVM regression (no behavior lost):** token-bridge's own EVM test suite —
which already signs `block.chainid`-bound digests — is the working template for
these updates.
4. The existing `1_test_token.js`, `2_test_signatureChecker.js`, and
   `3_test_votings.js` suites pass with an explicit chain ID in `utils.js`.
   Threshold, strict-signer-ordering, low-`s`/canonical-`v`, `finishedVotings`
   replay protection, and oracle-set validation remain green.

**Cross-implementation (signer ↔ contract agreement):**
5. `evm/test/vectors/chain-id-domain-separation.json` pins fixed inputs,
   chain ID, verifying contract, and all three digest outputs. The test
   recomputes those outputs through the JavaScript signer helper and also checks
   the deployed contract against the helper. This is the wire contract the
   future production relayer must satisfy.

**TVM plane:**
6. The signed multisig query now carries the network's 32-bit signed
   `global_id` (ConfigParam 19, read with `GLOBALID`) directly after
   `wallet_id`, and all three TVM multisigs reject a mismatch with exit
   code 44. `tvm/tests/replay-wrong-global-id.js` (one copy per bridge, run
   by `scripts/test-coin-bridge-tvm.sh` and `scripts/test-token-bridge-tvm.sh`
   for every configured network) signs a real query with the wrong network id
   and asserts exit 44, then proves the identical query signed for the staged
   network executes and cannot be executed twice. The verifier pins the source
   invariants, and the protocol model asserts that changing `wallet_id`, the
   network id, or the destination changes the signed domain.

**Parity:**
7. `scripts/verify-coin-bridge.py` requires the exact EVM digest prefix order,
   golden vector, replay/legacy test cases, NOTICE delta, and TVM binding
   invariants, then runs the protocol model.

## 6. Deployment status and rollout

**Deployment status is a precondition to confirm, not a fact this document
establishes.** Repository evidence does not establish current deployment status:
this document does **not** prove the on-chain state, and does not rely on any
claim that `SECURITY.md` or another in-repo document proves the bridge is
undeployed. Before the "no live migration" reasoning below is relied upon,
confirm and attach evidence (traceable to a document/commit, network, and block
height):

- an independent node read of masterchain `ConfigParam` 71 and 72 (the ETH/BSC
  bridge multisig slots) — network, block seqno, and the values (or their
  absence);
- the EVM side: for each target chain, whether a `Bridge`/`SignatureChecker` is
  deployed at the intended address, with the on-chain bytecode hash.

If that evidence shows the bridge is genuinely undeployed, there is **no live
migration**: the coordinated change (contracts + signer + tests + parity +
NOTICE) simply must land, be audited, and be verified before the *first*
deployment.

**If any instance is already deployed, this implementation's simple rollout is blocked
and there is NO safe in-place or short migration.** The obstacle is structural,
not just the absence of a proxy:

- the EVM `Bridge` *is itself* the wrapped-TOS ERC-20 (`Bridge is SignatureChecker,
  BridgeInterface, WrappedTOS`). A new address is a **new token identity**; holder
  balances cannot simply be "migrated";
- the contract exposes no wrapped-supply migration interface, no admin power to
  move holder balances, no global mint pause, no freeze/retire entry, and no proxy
  upgrade path;
- switching the TOS-side `ConfigParam` does **not** disable a deployed EVM
  contract — the old oracle quorum can still execute mints on the old `Bridge`.

Therefore: **if any existing deployment or balance is found, it immediately blocks
this implementation's rollout.** A separate, independently audited plan must be written
and reviewed before any action — covering legacy-token redemption/swap,
dual-contract supply reconciliation, revocation of the old oracle quorum's
authority, and final sealing of the old bridge. This change does not attempt to
specify that plan, and no four-step summary should be read as one. This is exactly
the live token-and-key problem a pre-deployment fix avoids, which is why the fix
must land before first value flows.

## 7. Implemented decisions

The implementation follows the owner-reviewed decisions below.

| Decision | Recommendation |
|---|---|
| Add chain ID to coin-bridge digests | **Implemented** — required before first deployment. |
| Solidity version | Keep `0.7.x`; read the chain ID with an inline-assembly `chainid()` (EIP-1344) rather than bump the whole compiler for one field. Reading the member under a `0.8.x` bump is the alternative, at a wider recompile/audit surface. |
| Field order | `magic, address(this), chainId, fields…` — align with token-bridge. |
| Move to EIP-712 now | **Defer** — it changes the signing envelope too and widens the audit surface; adopt later if the signer is rewritten. |
| Change token-bridge | **Reject** — it already binds the chain ID. |
| Change TVM code now | **Implemented**: `wallet_id` and the destination are address-scoped and do not separate two networks sharing a StateInit and oracle keys, so every signed query now also carries the network's `global_id` (ConfigParam 19, `GLOBALID`, exit code 44 on mismatch) in all three multisigs. Query builders must insert it after `wallet_id`; distinct deployments must still use unique `wallet_id`/StateInit. |
| Merge this PR | Merge only after code review and CI pass. It intentionally contains the implementation, tests, vectors, and reviewed-delta record together. |
| First value-bearing deployment | **Blocked** until the external signer adopts and verifies the golden vectors, independent audits pass, live on-chain pre-deployment evidence is attached, and every other `SECURITY.md` gate is satisfied. |
