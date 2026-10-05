# Experimental version-17 rescue-fee admission

This branch adds an experimental executor/VM interface. Development genesis remains
version 16. Neither this interface nor the contextual vault is production activated.
The existing suite-4 instruction and its price are unchanged.

## Authenticated import context

For global version >=17, transaction execution appends `c7[18]`:

```
null | [1, incoming_message_hash:uint256, cells:uint64, bits:uint64]
```

The tuple is supplied only for an ordinary, non-special external transaction after
successful import-size and Merkle-depth checks. Counts cover the complete original
incoming message DAG, **including the root**, optional StateInit, and inline body.
Identical cells are counted once by representation hash. The hash is the original
incoming root's representation hash, not a normalized reserialization. Import fees
continue to exclude the root as before. The existing traversal supplies the counts;
no VM cell traversal is subsidized or bypassed.

Internal messages, tick/tock, getters, and compute-only contexts have null here.
Version <=16 does not append the field. Low-level callers that explicitly construct
a custom c7 are responsible for its contents; they do not establish transaction
admission evidence. Contracts cannot treat a simulated custom c7 as proof of import.

## `LMSCHECKFEEHASH` (`F93103`)

```
(hash:uint256 leaf:uint20 signature:Cell public_key:Cell -- valid:Bool)
```

Version >=17 only. This fixes the existing suite-4 profile to one-level HSS,
LMS_SHA256_M32_H20 / LMOTS_SHA256_N32_W4, a 32-byte big-endian message, and empty
context. It accepts the same canonical ordinary byte chains as the generic verifier.
It additionally requires the verified HSS signature's q to equal `leaf`.

The key is parsed first. The full worst-case compression charge is deducted before
reading/verifying the signature: `500 + 3 * 1067 = 3701` gas. All ordinary new/repeated
cell-load charges remain payable. Caller-created message/context cells and duplicate
q parsing are eliminated; cryptographic work and credit are not discounted.

A well-formed cryptographic mismatch, including leaf mismatch, returns false.
Malformed/unsupported profile or byte chain throws cell underflow (9). Bad operand
type throws 7; invalid finite hash/leaf range throws 5; stack underflow throws 2.
Non-finite integers retain ordinary VM integer-overflow handling. Before version 17
the instruction throws invalid opcode (6). Ordinary gas exhaustion remains -14.

## Contextual vault wire format

`crypto/smartcont/rescue-fee-vault-context.fc` is a new experimental layout, not an
in-place upgrade of an existing deployed vault:

- Body: `intent:^Cell signature:^Cell`, no trailing bits/refs.
- Intent: `FEE3:uint32 class:uint8 (=1) vault:MsgAddressInt leaf:uint32
  deadline:uint32 value:Coins payload:^Cell header:^Cell`, no trailing data.
- Immutable header commits to domain, global id, network tag, suite/profile, fee
  public-key digest, wallet, and module. Its hash is stored in the vault state.
- State: `next_leaf:uint32 measured_gas:uint32 epoch0:uint32 fixed_value:Coins
  header_hash:uint256 target:MsgAddressInt key:^Cell auth_prefix:^Cell`.
- The exact 851-bit AUTH prefix includes AU2R, global id, network tag, standard
  wallet address, module hash, and RESCUE role. SUB1 has exactly two refs. AUTH
  kinds 0/1/3/4 are eligible; the inner module still verifies SLH and full policy.

The signed intent commits to the actual vault, full payload DAG, pinned header,
leaf, deadline, class, and exact outgoing value. Send policy is fixed by vault code;
no outgoing StateInit is allowed. An external wrapper's StateInit is import-checked
against the destination and counted, but is never forwarded to the module.

Before ACCEPT, the vault checks the executor-owned cell count <=128. A contract
entry's input is the executor's original message, so no caller-selected graph can
be substituted for that context. The field is fixed-shape/versioned by the executor;
null/missing context fails closed. At <=128 cells, total bits are <=128*1023.
The single outgoing wrapper plus its payload also fits <=128 cells: its payload is
a proper subgraph of the counted input. This replaces the earlier experimental
independent **72-cell payload cap**, not silently preserves it.

Before ACCEPT it also checks signature/q, monotonic q, current or previous one-hour
slot (four leaves per slot), deadline in `(now, now+3600]`, exact configured value,
and balance against current compute, forwarding and storage prices. Conservative
reserves cover 65536 gas, twice a 128-cell/131072-bit forwarding bound and
33554432 seconds of 32-cell/32768-bit storage. The configured value is fixed so a
fee-authorized caller cannot select a smaller payment. Production downstream
minimum-funding calibration is still required.

After ACCEPT, the vault stores q+1, COMMITs, and attempts one mode-3 send to the
pinned module. This does not establish successful inner execution. Receipt tests
must inspect actual emitted messages and the final account state. Fee authorization
never replaces SLH authorization.

## Evidence and remaining gates

See `test/rescue-fee-gate/README.md` for commands and the compact result index.
Tests cover exact two-VM opcode gas/results, full transactions including SLH/account
lock, original-message context fields, aliasing/inline/StateInit, cell limits,
negative paths, and mutations that must succeed incorrectly when protection is
removed. All are local test fixtures; no real funds or production activation.

The fixed tariff still needs release x86-64/AArch64 reference-hardware calibration.
A deployable product additionally needs canonical factory/witness enforcement,
paired successor module/vault proof-of-possession and funding handoff, complete V5
message/action integration, durable anti-rollback signer state, independent review,
and relevant CI. Existing prototype/module tests do not discharge these gates.
