# Proposal: bind the EVM chain ID into coin-bridge vote digests

Status: **Proposal — for review, not yet implemented.** No code in this change
alters a signed payload. This document scopes the problem, the fix, the
cross-plane coordination it forces, its deliberate divergence from upstream,
and the test plan that must accompany the eventual implementation.

Scope: the `coin-bridge` EVM/Solidity plane. The `token-bridge` shares the same
digest construction and inherits the same gap; the analysis and fix below apply
to it verbatim and it must be changed in the same coordinated step.

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
bridge address never exists on two EVM chains whose oracle sets overlap.** The
moment those two conditions hold, a signature gathered for chain A is a valid
signature for the identical call on chain B: same contract address, same magic,
same fields, same signer set, same digest, same `ecrecover`. An attacker replays
a quorum of chain-A signatures against chain B and drives a mint, an oracle-set
rotation, or a burn-status flip there that no chain-B oracle ever intended.

The two conditions are not exotic:

- **Same address on two chains** is the *default* outcome of `CREATE2`
  deterministic deployment, and is also reachable with plain `CREATE` when a
  deployer reuses an address/nonce across chains. Operators frequently *want*
  the same address on every chain for discoverability.
- **Overlapping oracle sets** is the natural operational choice — the same
  trusted operators running the same keys for a multi-chain bridge.

### This is inherited from upstream, verbatim

`NOTICE.md` records that the Solidity plane derives from
`ton-blockchain/bridge-solidity@f78adaf8` and that "signed payload structures are
unchanged." Upstream TON uses exactly this `abi.encode(magic, address(this), …)`
scheme with no chain ID. TON does not defend this cryptographically; it defends
it **operationally**: each EVM chain gets a separate deployment at a distinct
address, and the ETH and BSC bridges are separate codebases (upstream's
`bridge-func` `master` vs `bsc` branches; here `tvm/ethereum` vs `tvm/bsc`, config
params 71 vs 72) with their own oracle wiring. The gap is therefore not a TOS
regression — it is an upstream design assumption that TOS's `SECURITY.md` chose
to make explicit rather than inherit silently.

## 2. Proposed fix

Bind `block.chainid` into every EVM vote digest, so a signature is
cryptographically valid on exactly one chain regardless of deployment address.

Add the chain ID as an explicit field in each `abi.encode`:

```solidity
// getSwapDataId
keccak256(abi.encode(0xDA7A, block.chainid, address(this),
                     data.receiver, data.amount,
                     data.tx.address_.workchain, data.tx.address_.address_hash,
                     data.tx.tx_hash, data.tx.lt));

// getNewSetId
keccak256(abi.encode(0x5E7, block.chainid, address(this), oracleSetHash, set));

// getNewBurnStatusId
keccak256(abi.encode(0xB012, block.chainid, address(this), newBurnStatus, nonce));
```

Notes and alternatives considered:

- **Keep `address(this)` as well.** Chain ID separates chains; the contract
  address still separates two independent bridge instances on the *same* chain.
  Both belong in the preimage (defense in depth), so this is additive.
- **`block.chainid` requires Solidity ≥ 0.8.0 / the `CHAINID` opcode (EIP-1344,
  Istanbul).** The contracts pin `pragma solidity ^0.7.0`, which supports the
  `chainid()` builtin via inline assembly on an Istanbul-or-later EVM; a bump to
  a pragma with the `block.chainid` member is cleaner. Deciding the pragma/EVM
  target is part of this review. Cache the value read at construction only if the
  contract must survive a chain hard-fork that changes the ID — for a bridge,
  reading it live per call is the safer default.
- **EIP-712 typed-data domain** (`{name, version, chainId, verifyingContract}`)
  is the canonical, tooling-friendly form and subsumes both `chainId` and
  `verifyingContract`. It is the recommended target if the oracle/relayer signer
  is being rewritten anyway; the minimal `abi.encode` addition above is the
  smaller change if signer churn must be minimized. This document recommends the
  minimal addition now and flags EIP-712 as the preferred end state.

## 3. Cross-plane coordination (why this cannot be a one-file change)

The digest is reproduced by **every** party that signs or verifies it. All must
change atomically or the bridge stops verifying its own oracles:

1. **On-chain EVM** — `SignatureChecker.sol` (the three functions above).
2. **The off-chain oracle/relayer signer** — the watcher that observes a TOS
   event and signs the EVM digest must add `block.chainid` in byte-identical
   order. (The relayer implementation lives outside this repo — `~/relayer` is
   still spec-only — so this is a forward constraint recorded here, plus a golden
   vector, see the test plan.)
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

This is a **deliberate divergence** from `ton-blockchain/bridge-solidity`. When
implemented:

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
   drive it by deploying/verifying under two distinct chain IDs (Hardhat network
   `chainId` override, or a harness that mocks the `chainid()` return).
2. The same rejection test for `getNewSetId` and `getNewBurnStatusId`.
3. A **negative/regression** test: a pre-upgrade signature (digest without
   `chainId`) is rejected after the upgrade — proves the preimage actually moved.

**EVM regression (no behavior lost):**
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

## 6. Rollout

The bridge is currently dark: no `ConfigParam`, not deployed, no production
oracle set (`SECURITY.md`). There is therefore **no live migration** — the
coordinated change (contracts + signer + tests + parity + NOTICE) simply must
land, be audited, and be verified before the *first* deployment. If the bridge
were ever deployed before this lands, closing the gap afterward would require a
contract upgrade plus an oracle-set rotation, which is exactly the kind of live
key ceremony a pre-deployment fix avoids.
