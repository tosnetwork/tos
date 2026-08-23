# Proposal: bind the EVM chain ID into coin-bridge vote digests

Status: **Proposal — for review, not yet implemented.** No code in this change
alters a signed payload. This document scopes the problem, the fix, the
cross-plane coordination it forces, its deliberate divergence from upstream,
and the test plan that must accompany the eventual implementation.

Scope: the `coin-bridge` EVM/Solidity plane **only**. The newer `token-bridge`
is **not** affected — its `evm/contracts/SignatureChecker.sol` already binds
`block.chainid` in all four of its digests (`abi.encode(<magic>, address(this),
block.chainid, …)`), inherited from its own, newer upstream. token-bridge is
therefore the in-repo reference for the layout this proposal adopts, not a
second thing to fix. This matches `SECURITY.md`'s wording that the affected
plane is "the historical Solidity plane [that] predates the token bridge."

## 1. The problem

The oracle vote digests on the EVM side use the bridge contract address as their
only domain separator. They do **not** bind the EVM chain ID.

`evm/contracts/SignatureChecker.sol` produces three digests, all of the form
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
`bridge-solidity` commit) and that "signed payload structures are unchanged." That
older upstream uses exactly this `abi.encode(magic, address(this), …)` scheme with
no chain ID, and coin-bridge inherits it verbatim. The newer token-bridge derives
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

## 2. Proposed fix

Bind the EVM chain ID into every EVM vote digest, so a signature is
cryptographically valid in exactly one configured chain-ID domain regardless of
deployment address. (Binding the chain ID cannot stop replay between two networks
that *share* a chain ID — see the signer requirement in §3 that every target
network's chain ID be distinct.)

Add the chain ID as an explicit field in each `abi.encode`:

Adopt the **exact field ordering token-bridge already uses** —
`<magic>, address(this), chainId, <fields…>` — so the two bridges share one
layout and token-bridge's working tests are a template.

coin-bridge is on `pragma solidity ^0.7.0`, where the Solidity global
`block.chainid` does **not** exist (it is a later-Solidity member). Under 0.7.x
the chain ID is read with the Yul `chainid()` opcode via a tiny helper, and the
digests use that helper:

```solidity
// Solidity 0.7.x: `block.chainid` is unavailable; read the opcode via assembly.
function getChainId() internal view returns (uint256 id) {
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
way. This exact layout is what the golden vectors in the test plan pin.)

Notes and alternatives considered:

- **Keep `address(this)` as well.** Chain ID separates chains; the contract
  address still separates two independent bridge instances on the *same* chain.
  Both belong in the preimage (defense in depth), so this is additive.
- **Pragma decision (concrete).** coin-bridge pins `pragma solidity ^0.7.0`,
  where the `block.chainid` member does **not** exist; it would need the
  `chainid()` opcode via inline assembly (EIP-1344, Istanbul). token-bridge, by
  contrast, is on `pragma solidity ^0.8.9` and uses the `block.chainid` member
  directly. §7 recommends staying on `0.7.x` and reading `chainid()` via the
  assembly helper (the smaller diff); a `0.8.x` bump is the alternative at a wider
  recompile/audit surface. Either way read the value live per call (do not cache at
  construction) so the bridge is correct across a chain hard-fork that changes the
  ID.
- **EIP-712 typed-data domain** (`{name, version, chainId, verifyingContract}`)
  is the canonical, tooling-friendly form and subsumes both `chainId` and
  `verifyingContract`. It is the recommended target if the oracle/relayer signer
  is being rewritten anyway; the minimal `abi.encode` addition above is the
  smaller change if signer churn must be minimized. This document recommends the
  minimal addition now and flags EIP-712 as the preferred end state.

### Tron: a known-unverified chain-ID surface

Binding `block.chainid` presumes the EVM the contract runs on returns a stable,
network-unique chain ID. On Tron this is not settled. token-bridge already
targets Tron (`tvm/params/tron.fc`, ConfigParam 83) and its `NOTICE.md` records
that slot and its Tron chain ID "have no upstream counterpart at all" and that
"deployment to a public Tron network, and the chain id of that network
specifically, remain unverified." coin-bridge has no Tron target today, so adding
`block.chainid` does not introduce a Tron dependency by itself — but if coin-bridge
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
   recorded here, plus a golden vector, see the test plan.)
3. **The test signer** — `evm/test/utils/utils.js` (`encodeSwapData`,
   `encodeSet`, `encodeBurnStatus`) mirrors the contract's `abi.encode` and must
   gain the same `chainId` field in the same position.

### The TVM plane must be analyzed, not assumed safe

The EVM→TOS direction has oracles signing messages consumed by the TOS-side
multisig (`tvm/{ethereum,bsc}/multisig-code.fc`). That multisig signs over the
message hash (`check_signatures` over the query), and the ETH and BSC bridges are
distinct TOS contracts (config params 71/72). Whether a signature can replay
between them depends on whether the signed hash already binds the destination
bridge and on oracle-set overlap. This proposal does **not** claim the TVM plane
is unaffected; a symmetric analysis (and, if a gap exists, a symmetric fix
binding a TOS-side network/bridge identifier) is required before deployment and
is tracked as part of the same work item.

## 4. Upstream-parity impact

This is a **deliberate divergence** from the pinned upstream `bridge-solidity`
commit recorded in `NOTICE.md`. When implemented:

- `NOTICE.md` must record it as a reviewed delta (the next numbered item under
  "Reviewed deltas against the pinned upstream"), stating that the signed payload
  now additionally binds `block.chainid` and is therefore **not** byte-identical
  to upstream by design.
- `scripts/verify-coin-bridge.py` (the byte-parity check against the pinned
  commit) must be updated so the intentional digest change is an expected,
  reviewed difference rather than a parity failure.

## 5. Test plan

The implementation is incomplete until all of the following exist and pass.

**EVM unit (core replay property):**
1. A quorum of signatures produced for `getSwapDataId` under `chainId = A` is
   **rejected** when the identical call is verified under `chainId = B`, at the
   same contract address. This is the property the whole change exists to create;
   drive it with the repo's actual toolchain — Truffle/Ganache, **not** Hardhat:
   run two Ganache instances with distinct `chainId`s, deploy to the **same
   address** on both (same deployer + nonce, or same CREATE2 salt/init code), sign
   on instance A, and assert the vote is rejected on instance B.
2. The same rejection test for `getNewSetId` and `getNewBurnStatusId`.
3. A **negative/regression** test: a legacy-format signature (digest without the
   chain ID) is rejected by the new deployment — proves the preimage actually
   moved. (The contract is not upgradeable; this is a property of the new build,
   not an in-place change.)

**EVM regression (no behavior lost):** token-bridge's own EVM test suite —
which already signs `block.chainid`-bound digests — is the working template for
these updates.
4. The existing `1_test_token.js`, `2_test_signatureChecker.js`, and
   `3_test_votings.js` suites pass after `utils.js` is updated to include
   `chainId`. Threshold, strict-signer-ordering, low-`s`/canonical-`v`,
   `finishedVotings` replay protection, and oracle-set validation must all remain
   green.

**Cross-implementation (signer ↔ contract agreement):**
5. A golden-vector test: for fixed inputs and a fixed `chainId`, the contract's
   `getSwapDataId`/`getNewSetId`/`getNewBurnStatusId` return a hash byte-identical
   to the value the off-chain signer computes. This vector becomes the contract
   the future relayer implementation must satisfy, and guards against the two
   sides drifting.

**TVM plane:**
6. The symmetric analysis from §3; if it finds a replay path, an equivalent
   rejection test on the TVM multisig (a signature valid for the ETH bridge is
   rejected by the BSC bridge, and vice versa).

**Parity:**
7. `scripts/verify-coin-bridge.py` passes with the digest change recorded as an
   expected delta, and fails if any *other* unreviewed change appears.

## 6. Deployment status and rollout

**Deployment status is a precondition to confirm, not a fact this document
establishes.** Repository evidence does not establish current deployment status:
this proposal does **not** prove the on-chain state, and does not rely on any
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

**If any instance is already deployed, this proposal's simple rollout is blocked
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
this proposal's rollout.** A separate, independently audited plan must be written
and reviewed before any action — covering legacy-token redemption/swap,
dual-contract supply reconciliation, revocation of the old oracle quorum's
authority, and final sealing of the old bridge. This proposal does not attempt to
specify that plan, and no four-step summary should be read as one. This is exactly
the live token-and-key problem a pre-deployment fix avoids, which is why the fix
must land before first value flows.

## 7. Recommended decisions (for owner ratification)

A review of the pinned upstream and both bridges suggests these answers; the
owner ratifies.

| Decision | Recommendation |
|---|---|
| Add chain ID to coin-bridge digests | **Accept** — required before first deployment. |
| Solidity version | Keep `0.7.x`; read the chain ID with an inline-assembly `chainid()` (EIP-1344) rather than bump the whole compiler for one field. Reading the member under a `0.8.x` bump is the alternative, at a wider recompile/audit surface. |
| Field order | `magic, address(this), chainId, fields…` — align with token-bridge. |
| Move to EIP-712 now | **Defer** — it changes the signing envelope too and widens the audit surface; adopt later if the signer is rewritten. |
| Change token-bridge | **Reject** — it already binds the chain ID. |
| Change TVM code now | **No code change yet on evidence available**: the TVM multisig already signs over `wallet_id` and the full destination message. Still required before deployment: an ETH↔BSC replay-rejection test on the TVM side, and an operational rule that distinct deployments use unique `wallet_id`/StateInit. |
| Merge this PR | It is a **proposal doc only**; it does not implement the fix. Land it to record the decision, then implement in a separate reviewed+audited PR with the tests in §5. |
| First value-bearing deployment | **Blocked** until the implementation PR, golden vectors, an independent audit, and live on-chain proof of the pre-deployment state all pass. |
