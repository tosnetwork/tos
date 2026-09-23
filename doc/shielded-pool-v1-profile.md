# TOS Shielded Pool — V1 Implementation Profile

**Frozen for coding:** 2026-09-20  
**Bytes:** normative changes since that freeze move this document's bytes, and its bytes are the
`profile_hash` of §13.1 -- which is in the config store, which is in the genesis state, which is half the
deployment address. That coupling is deliberate: the document cannot drift away from the deployment
quietly. What the bytes currently hash to is in `doc/shielded-pool/genesis-manifest.json`, which is
generated. The date above is when the profile was frozen, not when it was last changed.  
**Status:** **FROZEN FOR CODING**. This profile is the normative implementation target for Claude Code.  
**Activation status:** **NOT APPROVED FOR MAINNET/TESTNET ACTIVATION** until **all acceptance gates in §19 pass**.

> This file intentionally removes design freedom. If another privacy document conflicts with this
> profile for V1 wire/state/circuit behavior, **this profile wins** and the other document must be
> corrected. Design alternatives belong in the other documents, not in the implementation.

---

## 0. V1 scope

V1 implements exactly:

- basechain workchain **0** system contract;
- **native TOS only**. Extra currencies / TIP-2 assets are deferred;
- fixed **2 input / 3 output** private transaction shape;
- Groth16 over **BLS12-381**;
- Poseidon2 over BLS12-381 scalar field, **t=8**, 7-ary trees;
- chain-delivered **ML-KEM-768 + XChaCha20-Poly1305** note data;
- **one-time ML-DSA-44 key per note**;
- funded internal submission; normal deposit/transact paths **MUST NOT call ACCEPT**;
- bounded nullifier state as an **indexed Merkle tree (IMT)** root;
- no admin, no SETCODE path, upgrades only through the network hard-fork/global-version process.

Deferred from V1:

- multi-asset notes;
- bonded external relay;
- reusable/auth-policy ML-DSA keys;
- arbitrary variable input/output counts;
- memo/free-form application payload;
- STARK/PQ-soundness migration implementation (format hooks remain);
- sharded/multi-account pool.

---

## 1. Frozen cryptographic profile

### 1.1 Scalar field

All circuit/Poseidon field elements use BLS12-381 `Fr`:

```text
r =
0x73eda753299d7d483339d80809a1d805
53bda402fffe5bfeffffffff00000001
```

Field elements on the wire are **exactly 32-byte big-endian unsigned integers < r**.
No implicit reduction is accepted for user-supplied field elements.

### 1.2 Poseidon2 instance — corrected parameter decision

V1 pins the authors' reference implementation:

```text
repository  HorizenLabs/poseidon2
commit      055bde3f4782731ba5f5ce5888a440a94327eaf3
file        plain_implementations/src/poseidon2/poseidon2_instance_bls12.rs

field       BLS12-381 Fr
width t     8
S-box       x^5
RF          8
RP          57
matrix      MAT_DIAG8_M_1 / MAT_INTERNAL8 from the pinned file
constants   RC8 from the pinned file
```

The previous D1 text claiming that the authors' t=8 instance used `RP=22` was wrong.
The pinned source defines:

```text
POSEIDON2_BLS_8_PARAMS =
  Poseidon2Params::new(8, 5, 8, 57, MAT_DIAG8_M_1, MAT_INTERNAL8, RC8)
```

No parameter generation is performed for V1. **Copying/generated constants from another width,
another field, gnark-crypto, or Poseidon1 is forbidden.**

The exact upstream source file SHA / generated constant-table hash MUST be frozen in the TOS
implementation and test manifest.

### 1.3 TVM opcodes

V1 reserves codepage-0 24-bit opcodes:

```text
0xF93200  POSEIDON2_PERM8
0xF93201  POSEIDON2_HASH7
minimum global version: 17
```

`POSEIDON2_PERM8`:

```text
(a0 a1 a2 a3 a4 a5 a6 a7 -- b0 b1 b2 b3 b4 b5 b6 b7)
```

`POSEIDON2_HASH7`:

```text
(domain x0 x1 x2 x3 x4 x5 x6 -- h)
```

Semantics of `HASH7` are exactly:

```text
state = [domain, x0, x1, x2, x3, x4, x5, x6]
state = POSEIDON2_PERM8(state)
h = state[0]
```

Both instructions reject any non-integer, negative integer, or value `>= r` before permutation.
No silent modular reduction.

The implementation MUST re-check at build time that `0xF93200/01` do not collide with another
registered opcode. A collision is a hard failure; Claude Code MUST NOT silently choose another opcode.

### 1.4 Domain constants and H7

`domain_fr(label)` is:

```text
uint256_be(
  SHA256(
    ASCII("TOS-SHIELDED-DOMAIN-v1:") || ASCII(label)
  )
) mod r
```

The modulo operation is only part of **constant generation**; user field inputs remain canonical.

Define:

```text
H7(label, a0..a6) =
  POSEIDON2_HASH7(domain_fr(label), a0..a6)
```

Frozen labels:

```text
DUMMY-OWNER-NF
OWNER-NF-HASH
OWNER-COMMITMENT
NOTE-BODY
NOTE-COMMITMENT
NULLIFIER
PHANTOM-NULLIFIER
RECOVERY-TEMPLATE
COMMIT-NODE
IMT-LEAF
IMT-NODE
INTENT-CORE
INTENT-OUTPUTS
INTENT-FINAL
```

A build script MUST generate the numeric domain constants and a manifest digest; no hand-written
numeric domain table.

`DUMMY_OWNER_NF_HASH = domain_fr("DUMMY-OWNER-NF")` and is therefore non-zero by construction check.
The generator MUST fail if any reserved domain constant reduces to zero.

---

## 2. V1 wallet key hierarchy

The existing TOS mnemonic algorithm remains the root. Use the existing 32-byte TOS
`private_seed()` / equivalent SDK result as `tos_seed`.

Derive the mnemonic-global base first:

```text
pool_master =
  SHAKE256(
    ASCII("TOS-SHIELDED-POOL-MASTER-v1") || tos_seed,
    64 bytes
  )
```

Then, for each exact V1 pool/network execution domain (§8), derive:

```text
pool_instance_master =
  SHAKE256(
    ASCII("TOS-SHIELDED-POOL-INSTANCE-v1") ||
    pool_master ||
    fr_be32(execution_domain),
    64 bytes
  )
```

All owner-NF, ML-DSA and ML-KEM derivations below use **pool_instance_master**, not the mnemonic-global
`pool_master`. This prevents the same mnemonic + note index from exposing the same PQ/owner key across
mainnet/testnet or two pool instances while preserving mnemonic-only recovery.

Wallet counters/used-index sets are scoped by `execution_domain`.

### 2.1 One-time owner-nullifier key per note

V1 does **not** reuse one owner-nullifier key across notes.

For note descriptor index `i:uint64`:

```text
owner_nf_key_i =
  uint512_be(
    SHAKE256(
      ASCII("TOS-SHIELDED-OWNER-NF-v1") ||
      pool_instance_master ||
      uint64_be(i),
      64
    )
  ) mod r
```

Attempt 0 is exactly the bytes above. If it reduces to zero, retry with
`... || uint64_be(i) || uint8(retry)` for `retry=1..255`; return the first non-zero result.
Exhausting all 256 attempts is a hard wallet error.

```text
owner_nf_key_hash_i =
  H7("OWNER-NF-HASH", owner_nf_key_i, 0,0,0,0,0,0)
```

The same `note_key_index=i` derives both the owner-nullifier key and the one-time ML-DSA key.
This removes a stable owner-nullifier hash from recipient descriptors.

### 2.2 Long-lived ML-KEM-768 key from the mnemonic

FIPS 203 permits storing/re-expanding the 64-byte `(d,z)` seed.

```text
d = SHAKE256("TOS-SHIELDED-MLKEM-D-v1" || pool_instance_master, 32)
z = SHAKE256("TOS-SHIELDED-MLKEM-Z-v1" || pool_instance_master, 32)

(mlkem_ek, mlkem_dk) = ML-KEM-768.KeyGen_internal(d, z)
```

Frozen ML-KEM-768 sizes:

```text
encapsulation/public key  1184 bytes
decapsulation key          2400 bytes (or 64-byte d||z seed form)
ciphertext                 1088 bytes
shared secret                32 bytes
```

The encapsulation key is off-chain recipient data. It is not emitted as a pool transaction field.

### 2.3 One-time ML-DSA-44 key per note

Every spendable note has a **different ML-DSA-44 key pair**, using the same `note_key_index=i`.

```text
xi_i =
  SHAKE256(
    ASCII("TOS-SHIELDED-MLDSA44-KEY-v1") ||
    pool_instance_master ||
    uint64_be(i),
    32
  )

(pk_i, sk_i) = ML-DSA-44.KeyGen_internal(xi_i)
```

FIPS 204 seed-form private keys are allowed; V1 stores only mnemonic + index when possible.

Frozen sizes:

```text
ML-DSA-44 public key  1312 bytes
signature             2420 bytes
```

### 2.4 Recipient descriptor V1

Off-chain binary object:

```text
magic                     uint32 = 0x53484431   // "SHD1"
version                    uint8  = 1
execution_domain           bytes32 canonical Fr
note_key_index             uint64 big-endian
owner_nf_key_hash          bytes32 canonical Fr
pq_auth_public_key         bytes1312
mlkem768_encapsulation_key bytes1184
```

A descriptor is valid only for the exact `execution_domain` of the target pool/network.

A recipient descriptor is **single use**. Wallet recovery scans/decrypts chain note data, finds every
used `note_key_index` and sets `next_note_key_index = max_seen + 1` before creating a new descriptor.

The ML-KEM encapsulation key is deliberately long-lived **within one execution_domain** in V1 to permit mnemonic-only chain scanning.
It is **not published on chain**, but two off-chain payers for the same pool/domain who exchange recipient descriptors can recognize
the same ML-KEM key. Different execution domains derive different ML-KEM keys. V1's privacy target is third-party/on-chain unlinkability; sender-collusion-resistant per-payment viewing keys within one pool are deferred.

### 2.5 Descriptor single-use and forced-reuse semantics

“Single use” is a **wallet issuance rule**, not a consensus rule. A sender that already learned a descriptor
can deliberately reuse it, so V1 MUST define deterministic wallet behavior instead of assuming reuse never happens.

Wallet rules:

1. local wallet code MUST never issue the same `note_key_index` twice;
2. after mnemonic recovery for one `execution_domain`, `next_note_key_index = max(all successfully decrypted indices in that domain) + 1`;
3. if chain scanning finds **multiple valid owned notes with the same `note_key_index`**, import **all** of them;
   never discard the later note merely because the descriptor was already used;
4. mark that index `descriptor_reused` / privacy-degraded and never issue it again;
5. a reused descriptor may expose the same one-time ML-DSA public key in multiple later spends, so wallets SHOULD
   consolidate such notes into fresh descriptors promptly, subject to normal privacy/timing policy;
6. descriptor reuse is not a minting or spend-authority failure: every resulting note still has its own
   `note_secret` and semantic note body. It is a **counterparty-induced linkability degradation**.

Acceptance tests MUST include two different valid notes sent to the same descriptor and prove mnemonic-only recovery
imports both, derives the same note-specific PQ key correctly for both, and never reissues that index.


## 3. Note delivery bytes — exact V1 format

V1 uses ML-KEM-768 plus XChaCha20-Poly1305-IETF.

For each output slot `slot ∈ {0,1,2}` (deposit uses slot 0):

1. encapsulate to recipient `mlkem768_encapsulation_key`;
2. get `shared_secret[32]` and `kem_ct[1088]`;
3. derive 56 bytes:

```text
key_nonce =
  SHAKE256(
    ASCII("TOS-SHIELDED-DELIVERY-KDF-v1") ||
    shared_secret ||
    fr_be32(execution_domain) ||
    uint8(slot),
    56
  )

aead_key   = key_nonce[0..32]
aead_nonce = key_nonce[32..56]   // 24 bytes
```

4. AAD is exactly:

```text
fr_be32(execution_domain) || uint8(slot)
```

5. encrypt the fixed 128-byte plaintext:

```text
magic                  uint32 = 0x53484E31   // "SHN1"
version                 uint8  = 1
slot                    uint8
flags                   uint16              // bit0=dummy, bit1=recovery_template
amount                  uint128 big-endian  // V1 TOS: < 2^120
note_secret             bytes32 canonical Fr
owner_nf_key_hash       bytes32 canonical Fr
note_key_index          uint64 big-endian
pq_auth_key_hash        bytes32 canonical Fr
```

Size check: `4+1+1+2+16+32+32+8+32 = 128`.

XChaCha20-Poly1305 combined ciphertext is `128 + 16 = 144` bytes.

The on-chain opaque output payload is exactly:

```text
output_data_v1 =
  version:uint8 (=1) ||
  mlkem768_ciphertext[1088] ||
  xchacha20poly1305_ciphertext[144]
```

**Total: 1233 bytes, fixed for all real and dummy outputs.**

The 1233 bytes are encoded as the same canonical ordinary level-zero byte chain used by the PQ
verifier style: every non-final cell contains exactly 127 bytes and exactly one reference; the final
cell contains the remaining bytes and zero references; no trailing empty cell. Decoder rejects
special cells, non-byte-aligned cells, short non-final cells, extra references or trailing data.

Dummy outputs MUST also contain a real ML-KEM encapsulation and AEAD ciphertext of the same length.

The **exact dummy plaintext semantics** are:

```text
flags                = 0x0001              // dummy only
amount               = 0
note_secret          = fresh non-zero Fr
owner_nf_key_hash    = DUMMY_OWNER_NF_HASH
note_key_index       = fresh locally consumed index
pq_auth_key_hash     = hash(fresh throwaway ML-DSA public key derived from that index)
```

The ML-KEM recipient is a fresh self-issued descriptor so the wallet can decrypt/recognize its own dummy payload,
but the plaintext `owner_nf_key_hash` is **the fixed dummy constant**, not the normal descriptor-derived owner hash.
The descriptor index is consumed and MUST NOT later be issued as a payment descriptor.

A pre-authorized withdrawal recovery payload uses **only** flag bit1 (`0x0002`), plaintext amount=0,
a fresh normal owner-nullifier key/hash and a fresh one-time ML-DSA key/hash. Dummy and recovery flags MUST NOT both
be set. Its eventual recovery-note amount comes from the actual accepted bounced `msg_value`; see §15.

Define:

```text
output_data_hash =
  uint256_be(
    SHA256(
      ASCII("TOS-SHIELDED-OUTPUT-DATA-v1") ||
      exact_1233_bytes
    )
  ) mod r
```

The contract independently hashes the actual bytes before constructing the Groth16 public-input vector.

### 3.1 Wallet post-decryption validation — normative

Ciphertext hash binding prevents a relay from replacing bytes. It does **not** make the encrypted plaintext
self-authenticating against the on-chain semantic note. Wallet import MUST therefore run all checks below after
successful ML-KEM + XChaCha decryption.

Common checks:

1. exact 128-byte plaintext, magic/version/slot canonical;
2. reserved flag bits are zero; only `flags ∈ {0,1,2}` are valid;
3. `note_secret` is canonical Fr and non-zero;
4. derive `owner_nf_key` and one-time ML-DSA key from mnemonic + `note_key_index`;
5. recompute the derived ML-DSA full public key and `pq_auth_key_hash`.

For an **ordinary real output** (`flags=0`):

- require `0 < amount < 2^120`;
- require plaintext `owner_nf_key_hash == H7("OWNER-NF-HASH", derived_owner_nf_key, ...)`;
- require plaintext `pq_auth_key_hash` equals the derived one-time ML-DSA key hash;
- recompute `owner_commitment` and `note_body_commitment` using the **chain-observed output_data_hash**;
- require the recomputed note body equals the transaction's public `note_body_slot` before importing balance.

For a **dummy output** (`flags=1`):

- require `amount=0`;
- require `owner_nf_key_hash == DUMMY_OWNER_NF_HASH`;
- require `pq_auth_key_hash` equals the throwaway key derived from `note_key_index`;
- recompute the dummy owner/note body and require equality with the public slot;
- mark the index consumed but import **zero balance**.

For a **recovery template** (`flags=2`):

- require `amount=0`;
- require the derived normal owner-NF hash and derived PQ-key hash match plaintext;
- recompute `recovery_owner_commitment` and `recovery_template_hash` and require equality with the signed
  withdrawal recovery record;
- do **not** import it as a spendable note until a genuine bounce creates a recovery note with an actual amount.

Any mismatch means “payload belongs to no valid local spendable note”. Wallet MUST NOT silently import it as balance.
It SHOULD retain diagnostic metadata so malformed/malicious delivery can be surfaced to the user/test harness.

This validation algorithm is part of WP-D and mnemonic-recovery acceptance, not an SDK preference.

---

## 4. Note commitments and nullifiers

### 4.1 Owner commitment

`note_secret` is a fresh non-zero random Fr element per note.

```text
owner_commitment =
  H7(
    "OWNER-COMMITMENT",
    owner_nf_key_hash,
    pq_auth_key_hash,
    note_secret,
    0, 0, 0, 0
  )
```

`pq_auth_key_hash` is computed from the exact canonical 1312-byte key:

```text
pq_auth_key_hash =
  uint256_be(
    SHA256(
      ASCII("TOS-SHIELDED-MLDSA44-PK-v1") ||
      pk_bytes
    )
  ) mod r
```

### 4.2 Semantic note body

V1 is native-TOS-only, so no asset field exists in the V1 circuit:

```text
note_body_commitment =
  H7(
    "NOTE-BODY",
    owner_commitment,
    amount,
    output_data_hash,
    0, 0, 0, 0
  )
```

### 4.3 Final tree note

```text
note_commitment =
  H7(
    "NOTE-COMMITMENT",
    note_body_commitment,
    leaf_index,
    0, 0, 0, 0, 0
  )
```

`leaf_index` is assigned by the contract after proof verification.

### 4.4 Nullifier

Nullifier deliberately binds the **semantic note body**, not the final leaf index:

```text
nullifier =
  H7(
    "NULLIFIER",
    note_body_commitment,
    owner_nf_key,
    0, 0, 0, 0, 0
  )
```

This makes an accidentally/recovery-duplicated semantic note single-spend even if it appears at two
different leaf indices.

Real nullifiers MUST be non-zero.

### 4.5 Phantom nullifier

For a phantom input slot:

```text
phantom_nullifier =
  H7(
    "PHANTOM-NULLIFIER",
    intent_nonce,
    input_slot,            // 0 or 1
    pq_auth_key_hash,
    0, 0, 0, 0
  )
```

It MUST also be non-zero.

---

## 5. Commitment tree

Frozen shape:

```text
arity       7
depth       12
logical max 2^32 leaves
```

Although `7^12 > 2^32`, actual leaf indices remain uint32 (`0 .. 2^32-1`). Persistent `commitment_next_index` is **uint64** so the exhausted sentinel value `2^32` is representable. The contract MUST reject append when `commitment_next_index >= 2^32`.

Empty leaf is field zero.

```text
EMPTY_ROOT[0] = 0
EMPTY_ROOT[level+1] =
  H7("COMMIT-NODE",
     EMPTY_ROOT[level] repeated 7 times)
```

A node is:

```text
H7("COMMIT-NODE", child0, child1, ... child6)
```

### 5.1 Frontier

Persistent frontier is a logical array `frontier[12][7]` and **MUST use the canonical `frontier_store` level-chain encoding from §13.1**. There is no alternate encoding in V1.

Append leaf at index `i`:

```text
carry = leaf

for level in 0..11:
    d = floor(i / 7^level) mod 7

    children[j] =
       frontier[level][j]  if j < d
       carry               if j == d
       EMPTY_ROOT[level]   if j > d

    frontier[level][j] = children[j]   for every j in 0..6

    carry = H7("COMMIT-NODE", children[0..6])

commitment_root = carry
commitment_next_index += 1
```

Slots `j>d` hold whatever an earlier append left there and their contents are never read, but they are **rewritten to `EMPTY_ROOT[level]` on every append**: the store is a fixed-shape chain, so what is persisted is part of the state hash and is fixed here rather than left to the implementation.

Three transact outputs append sequentially at indices `next, next+1, next+2`.

---

## 6. Anchor policy — current + recent-root ring + one-day checkpoints

A pure “one root per 30-second epoch” ring is not sufficient by itself: under load, a proof made against a
mid-epoch root would become invalid as soon as the next transaction changed the tree.

V1 therefore accepts three anchor kinds:

```text
ANCHOR_CURRENT = 0
ANCHOR_RECENT  = 1
ANCHOR_EPOCH   = 2

RECENT_ROOT_SLOTS    = 4096
ANCHOR_EPOCH_SECONDS = 30
ANCHOR_EPOCH_SLOTS   = 2880     // 24 hours
```

The transact message carries:

```text
anchor_kind:uint8
anchor_id:uint32
anchor_root:Fr
```

Only `anchor_root` is a Groth16 public input.

### 6.1 Recent-root preservation

Before every successful **transaction/handler that will append one or more commitment leaves**, preserve the single pre-transaction current root **once**:

```text
require commitment_next_index < 2^32
root_version = uint32(commitment_next_index)
recent_roots[root_version % 4096] = (root_version, commitment_root)
```

Then perform that transaction's append(s) sequentially. Intermediate roots created while appending multiple leaves inside the same transaction are not externally visible anchors and are not inserted into the recent ring.

A recent anchor is accepted iff the slot contains exactly the supplied
`(anchor_id=root_version, anchor_root)`.

Retention is defined by **leaf-version slot overwrite**, not by a fixed number of transactions. A recent root remains valid until a later pre-mutation `root_version` with the same `root_version % 4096` overwrites that slot. Because V1 deposit appends 1 leaf and transact appends 3, the number of intervening transactions depends on traffic mix. Tests MUST use exact version arithmetic rather than assume `4096 transactions`.

### 6.2 One-day checkpoint ring

Also before the first successful commitment-tree mutation in a new 30-second epoch:

```text
epoch = floor(now / 30)
epoch_roots[epoch % 2880] = (epoch, pre_mutation_commitment_root)
last_anchor_epoch = epoch
```

An epoch anchor is accepted iff:

```text
slot contains exactly (anchor_id, anchor_root)
current_epoch - anchor_id < 2880
```

Recent notes may need to wait until the next epoch checkpoint before they can use the long-lived one-day path.

### 6.3 Current root

For `ANCHOR_CURRENT`:

```text
anchor_id == 0
anchor_root == commitment_root at transaction start
```

No other anchor kind/value is valid.

Wallet default:

1. prove against current root;
2. if it changed before submission, use the matching recent-root entry;
3. use epoch checkpoints for delayed/offline proving.

## 7. Nullifier indexed Merkle tree — exact V1 semantics

V1 does **not** leave IMT-vs-SMT to the implementation.

Shape:

```text
arity             7
depth             12
logical max leaves 2^32
next index starts  1
leaf index 0       head sentinel
```

Leaf tuple:

```text
(value:Fr, next_index:uint32, next_value:Fr)
```

Hash:

```text
imt_leaf_hash =
  H7("IMT-LEAF", value, next_index, next_value, 0,0,0,0)

imt_node =
  H7("IMT-NODE", child0..child6)
```

Initial leaf 0:

```text
(value=0, next_index=0, next_value=0)
```

Real/phantom nullifiers are required non-zero, so zero is reserved by the head sentinel.

### 7.0 Empty-tree and sentinel semantics

Unallocated IMT leaves have hash **field zero**.

Define empty internal roots:

```text
IMT_EMPTY[0] = 0
IMT_EMPTY[level+1] =
  H7("IMT-NODE",
     IMT_EMPTY[level],
     IMT_EMPTY[level],
     IMT_EMPTY[level],
     IMT_EMPTY[level],
     IMT_EMPTY[level],
     IMT_EMPTY[level],
     IMT_EMPTY[level])
```

Allocated leaf hash:

```text
H7("IMT-LEAF", value, next_index, next_value, 0,0,0,0)
```

MUST be non-zero.

Genesis IMT root is obtained by inserting the head sentinel tuple
`(value=0,next_index=0,next_value=0)` at leaf index 0 into the otherwise empty tree.
This root is part of the zerostate manifest.

For every allocated low leaf:

- `low_value < Fr`;
- if `low_next_index == 0`, then `low_next_value == 0`;
- if `low_next_index != 0`, then:
  - `low_next_index == 0 || uint64(low_next_index) < nullifier_next_index`;
  - `low_value < low_next_value < Fr`.

Real/phantom nullifiers are non-zero, therefore the sentinel value zero can never be spent/inserted as a
normal nullifier.

### 7.1 Non-membership + insertion witness

For each nullifier, caller supplies:

```text
low_index:uint32
low_value:Fr
low_next_index:uint32
low_next_value:Fr
low_path[12][6]
append_path[12][6]
```

Contract MUST:

1. prove the low leaf is in current `nullifier_root`;
2. require `low_value < nf`;
3. require `(low_next_index == 0 && low_next_value == 0) || (low_next_index != 0 && nf < low_next_value)`;
4. set `new_index = uint32(nullifier_next_index)` after first requiring `nullifier_next_index < 2^32` and require `new_index < 2^32`;
5. replace low leaf with `(low_value, new_index, nf)`, producing `root1`;
6. using `append_path` against `root1`, prove leaf `new_index` has the exact unallocated leaf hash `0`;
7. insert `(nf, low_next_index, low_next_value)`, producing `root2`;
8. set `nullifier_root=root2` and increment next index.

For a 2-input transaction, process `nf0` then `nf1` **sequentially**.
The second witness is relative to the root after `nf0` insertion.

The circuit also enforces `nf0 != nf1`.

---

## 7.2 Canonical IMT witness cell encoding

The logical witness in §7.1 has one and only one V1 cell encoding.

Witness root:

```text
low_index       uint32
low_value       uint256   // canonical Fr
low_next_index  uint32
low_next_value  uint256   // canonical Fr
^low_path
^append_path
```

Root payload is exactly **576 bits + 2 refs**. No trailing bits or refs.

Each path contains exactly **72 Fr elements**:

```text
12 levels × 6 siblings = 72 fields
```

Sibling order is frozen:

1. levels from leaf to root: `level = 0..11`;
2. at each level compute the path digit
   `d = floor(index / 7^level) mod 7`;
3. serialize the six sibling positions in ascending child-position order, skipping `d`.

`low_path` uses `low_index`.
`append_path` uses the V1 `new_index = uint32(nullifier_next_index)` after the `< 2^32` capacity check and is interpreted against the
intermediate root **after** the low leaf update.

Each path is encoded as a canonical linked chain of **24 ordinary level-zero cells**:

```text
cell 0: field[0]  field[1]  field[2]  ^cell1
cell 1: field[3]  field[4]  field[5]  ^cell2
...
cell23: field[69] field[70] field[71]
```

Every non-final path cell contains exactly **768 data bits + 1 ref**.
The final cell contains exactly **768 data bits + 0 refs**.

Decoder rejects:

- fewer or more than 24 path cells;
- any field `>= Fr`;
- extra/trailing bits or refs;
- special cells;
- wrong sibling count/order;
- `uint64(low_index) >= nullifier_next_index`;
- `low_next_index != 0 && uint64(low_next_index) >= nullifier_next_index`;
- append path not proving the V1 append slot empty.

This encoding is part of the signed/profile wire contract. It is not an SDK preference.

---

## 8. Execution domain and address hashing

V1 withdrawal recipients are **non-anycast addr_std on workchain 0**.

`execution_domain`:

```text
uint256_be(
  SHA256(
    ASCII("TOS-SHIELDED-EXEC-v1") ||
    int32_be(GLOBALID) ||
    uint8(0) ||
    pool_account_id_bytes32 ||
    uint16_be(1)
  )
) mod r
```

The contract recomputes it from `GLOBALID` and `MYADDR`.

Withdrawal recipient hash:

```text
public_recipient_hash =
  uint256_be(
    SHA256(
      ASCII("TOS-SHIELDED-RECIPIENT-v1") ||
      recipient_account_id_bytes32
    )
  ) mod r
```

Transfer mode uses `public_amount_out=0`, `public_recipient_hash=0` and `addr_none`.
Withdrawal mode requires `public_amount_out>0` and a workchain-0 std address.

---

## 9. Transaction intent and ML-DSA authorization

### 9.1 Two signatures always

Every `transact` carries exactly:

- 2 × canonical 1312-byte ML-DSA-44 public keys;
- 2 × canonical 2420-byte signatures.

For a real input, the circuit binds the corresponding public-key hash into that input note.
For a phantom input, wallet generates a fresh throwaway one-time key and valid signature.

Therefore public wire shape does not reveal which input is phantom.

### 9.2 Recovery template

A withdrawal pre-authorizes only the **recovery secret material**, not a future amount.

```text
recovery_data_hash =
  hash_exact_output_data(recovery_output_data)

recovery_template_hash =
  H7(
    "RECOVERY-TEMPLATE",
    recovery_owner_commitment,
    recovery_data_hash,
    0,0,0,0,0
  )
```

The recovery payload has `recovery_template` flag set and encrypted amount=0.
If a bounce occurs, the actual recovery amount is the bounce message's actual credited `msg_value`;
the contract then computes the final semantic recovery note body.

Transfer requires `recovery_template_hash=0`.

### 9.3 Intent digest

Circuit private witness includes fresh non-zero `intent_nonce:Fr`.

```text
intent_core =
  H7(
    "INTENT-CORE",
    execution_domain,
    nf0,
    nf1,
    public_amount_out,
    withdrawal_fee,
    public_recipient_hash,
    recovery_template_hash
  )

intent_outputs =
  H7(
    "INTENT-OUTPUTS",
    note_body_0,
    note_body_1,
    note_body_2,
    pq_auth_key_hash_0,
    pq_auth_key_hash_1,
    intent_nonce,
    valid_until
  )

transaction_intent_digest =
  H7(
    "INTENT-FINAL",
    intent_core,
    intent_outputs,
    0,0,0,0,0
  )
```

The digest is a public input.

`valid_until` is a public uint32 field. Contract requires:

```text
now <= valid_until <= now + 3600
```

### 9.4 Exact signed bytes

Both ML-DSA signatures use:

```text
message = 32 raw big-endian bytes of transaction_intent_digest
context = ASCII("TOS-SHIELDED-POOL-MLDSA44-v1")
          // exactly 28 bytes
```

Use FIPS 204 Pure ML-DSA-44 exactly as `PQCHECKSIG_MLDSA44` expects.

The contract hashes each supplied full public key with the `pq_auth_key_hash` rule and supplies those
hashes to the Groth16 public-input vector.

## 10. Groth16 V1 public input vector

The verifier public input order is frozen to **18 Fr elements**:

```text
 0  anchor_root
 1  nullifier_0
 2  nullifier_1
 3  note_body_0
 4  note_body_1
 5  note_body_2
 6  output_data_hash_0
 7  output_data_hash_1
 8  output_data_hash_2
 9  pq_auth_key_hash_0
10  pq_auth_key_hash_1
11  public_amount_out
12  withdrawal_fee
13  public_recipient_hash
14  valid_until
15  execution_domain
16  recovery_template_hash
17  transaction_intent_digest
```

Any change to this ordering is a new circuit/profile version and requires a new Phase 2.

## 10.1 Groth16 proof and VK encoding

**Point encoding (ruled 2026-09-20, see `TOS_SHIELDED_POOL_V1_OPEN_RULINGS.md` A1).**
This section previously fixed only the lengths. V1 canonical bytes are the
**blst/IETF BLS12-381 compressed encoding**, defined as exactly what this chain's own
BLS primitives accept and produce:

```text
G1  48 bytes   encoder blst_p1_affine_compress   decoder blst_p1_uncompress
G2  96 bytes   encoder blst_p2_affine_compress   decoder blst_p2_uncompress
```

x is big-endian; the compression, infinity and sort flags occupy the top bits of the **first**
byte. `A`, `C`, `alpha` and every `IC[i]` are G1; `B`, `beta`, `gamma` and `delta` are G2.

The bytes are defined by a round trip rather than by a description of the layout: decode with
blst, re-compress, and the same bytes must come back. A proving library is free to be the curve
implementation, but its own serializer is **not** the wire format. The contract consumes these
bytes directly; there must be no second endian or flag conversion on chain.

> Recorded because it would otherwise be mistaken for a migration: arkworks 0.5 already emitted
> exactly these bytes, so pinning the convention changed no proof or VK byte and no VK hash. What
> changed is that the agreement is now produced and checked by blst at encoding time instead of
> being an accident of one library version.

V1 proof is standard BLS12-381 Groth16:

```text
A : G1 compressed 48 bytes
B : G2 compressed 96 bytes
C : G1 compressed 48 bytes
total = 192 bytes
```

Canonical proof cell:

```text
proof_root:
  A[48]
  C[48]
  ^proof_b

proof_b:
  B[96]
```

No extra bits/refs are allowed.

Contract MUST require A/B/C to deserialize canonically, be in the correct subgroup and be non-zero.

With 18 public inputs the verifying key contains exactly 19 IC G1 points:

```text
alpha_g1  48
beta_g2   96
gamma_g2  96
delta_g2  96
IC[19]    19 * 48
```

The generated VK manifest records byte-for-byte compressed points and SHA-256 of the complete canonical
VK encoding.

Verifier computes:

```text
vk_x = IC[0] + Σ(public_input[i] * IC[i+1]), i=0..17
```

using TVM BLS G1 multi-exponentiation/addition and checks the standard four-pair Groth16 pairing equation.
The exact sign/order used by the prover library MUST be cross-checked with one valid and at least four
mutated proofs before it is frozen; Claude Code must not infer equation signs from memory.

The development fixture MUST contain:
- one valid proof;
- one proof with A mutated;
- one with B mutated;
- one with C mutated;
- one public input changed;
and only the valid vector may verify.

---

## 11. Circuit relations

### 11.1 Inputs

For each input `i∈{0,1}`, witness `is_phantom_i` is boolean.

If real:

- `amount_i > 0` and `amount_i < 2^120`;
- compute `owner_nf_key_hash_i` from private `owner_nf_key_i`;
- compute owner commitment from `owner_nf_key_hash_i, pq_auth_key_hash_i, note_secret_i`;
- recompute semantic note body from owner commitment, amount and original input-output-data hash;
- compute final note commitment using private `leaf_index_i < 2^32`;
- verify 7-ary depth-12 membership under public `anchor_root`;
- compute public nullifier from **note_body_commitment + owner_nf_key**.

If phantom:

- amount is zero;
- no membership relation is enabled;
- public nullifier equals the phantom-nullifier formula using `intent_nonce`, slot and public PQ-key hash.

The selector that removes a phantom amount from conservation MUST be the same boolean that selects
the phantom branch; there is no independent “skip balance” flag.

Require at least one real input, `nf0 != nf1` and both nullifiers non-zero.

### 11.2 Outputs

For each of 3 outputs:

- `is_dummy_i` boolean;
- if real: `0 < amount_i < 2^120`;
- if dummy: `amount_i=0` and `owner_nf_key_hash_i=DUMMY_OWNER_NF_HASH`;
- owner commitment includes output `pq_auth_key_hash_i` and `note_secret_i`;
- circuit MUST constrain `note_secret_i != 0` for every real and dummy output; cryptographic freshness is a wallet RNG requirement;
- semantic note body includes **public `output_data_hash_i`**;
- computed semantic note body equals public `note_body_i`.

All three output-data payloads have the same 1233-byte shape, including dummy slots.

### 11.3 Conservation and mode

```text
sum(real_input_amounts)
  =
sum(three_output_amounts)
  + public_amount_out
  + withdrawal_fee
```

All arithmetic is range-checked before conservation.

Transfer:

```text
public_amount_out = 0
withdrawal_fee = 0
public_recipient_hash = 0
recovery_template_hash = 0
```

Withdrawal:

```text
0 < public_amount_out < 2^120
0 < withdrawal_fee < 2^120
public_recipient_hash != 0
recovery_template_hash != 0
```

**Fee width (ruled 2026-09-20, see `TOS_SHIELDED_POOL_V1_OPEN_RULINGS.md` A2).** The fee carries
the same 120-bit width as every other amount, and the circuit range-checks it as its own relation.
Conservation is field arithmetic: a fee left unbounded could be chosen as `r - X`, wrapping the
equation back into balance while `X` walks out. The contract's equality against the immutable
config fee is a second line of defence and is not a reason to leave the first one open.

The circuit range-checks both public amounts. The **contract additionally MUST require**
`public_amount_out` to be exactly one entry in the immutable sorted V1 denomination list.
This boundary-denomination check is deliberately outside the circuit because the list is deployment config,
not circuit state.

Contract also requires `withdrawal_fee == config.withdrawal_fee`.

The withdrawal fee is not a private note. It is value removed from shielded liability and retained by the
pool as operational reserve to fund outbound and possible bounce-recovery work.

### 11.4 Intent

Circuit recomputes `transaction_intent_digest` exactly as §9.3.
The two public PQ-key hashes, all three output note bodies, withdrawal fee and recovery template are
therefore authorization-bound.

This is what prevents fee-slot theft: slot 2 is just an output, but changing its amount/recipient/payload
changes `note_body_2` and invalidates both signatures.

## 12. Wire messages

Frozen opcodes:

```text
OP_DEPOSIT     = 0x53485001
OP_TRANSACT    = 0x53485002
OP_RESERVE_TOPUP = 0x53485003
```

### 12.1 Deposit

Deposit is a **direct public boundary operation**, not relayed in V1.

Logical body:

```text
deposit_v1:
  op:uint32
  query_id:uint64
  deposit_amount:Coins
  owner_commitment:Fr
  output_data:^Cell      // canonical 1233-byte chain
```

Contract:

1. requires standard denomination;
2. requires `deposit_amount < 2^120`;
3. requires local inbound funding per §14.1;
4. hashes actual output data;
5. computes note body from owner commitment + deposit amount + output-data hash;
6. checkpoints the pre-mutation root into recent/epoch rings as required;
7. appends final note at contract-assigned leaf index;
8. increments `native_liability` by exactly `deposit_amount`.

User cannot supply final note commitment.

### 12.2 Transact

Root cell logical fields:

```text
op:uint32
query_id:uint64
anchor_kind:uint8
anchor_id:uint32
valid_until:uint32
public_amount_out:Coins
withdrawal_fee:Coins
public_recipient:MsgAddressInt
transaction_intent_digest:Fr

^proof_bundle
^output_bundle
^auth_bundle
^nullifier_witness_bundle
```

Exactly four root references.

`query_id` MUST equal the low 64 bits of `transaction_intent_digest`.

Proof bundle:

```text
anchor_root:Fr
nullifier_0:Fr
nullifier_1:Fr
^note_bodies      // exactly 3 canonical Fr values
^groth16_proof
```

Output bundle:

```text
recovery_owner_commitment:Fr
^output_data_0
^output_data_1
^output_data_2
^recovery_output_data
```

For transfer, `recovery_owner_commitment=0` and recovery data is the canonical empty cell.
For withdrawal, recovery output data is another canonical 1233-byte payload with
`recovery_template` flag set and encrypted amount=0.

Auth bundle:

```text
^public_key_0
^signature_0
^public_key_1
^signature_1
```

Public keys/signatures use the same canonical ordinary byte-chain rules as
`PQCHECKSIG_MLDSA44`.

Nullifier witness bundle:

```text
^witness_nf0
^witness_nf1
```

Each witness encodes the exact §7.1/§7.2 structure.

### 12.3 Reserve top-up

Anyone may replenish operational reserve without minting a note:

```text
reserve_topup_v1:
  op:uint32
  query_id:uint64
```

No refs/trailing bits.

The path MUST NOT call `ACCEPT`, MUST NOT change `native_liability`, and MUST NOT emit a message.
After its bounded compute cost, the remaining inbound value simply increases unencumbered pool balance.

## 13. Contract state

Logical persistent state:

```text
magic                 uint32 = 0x53505631  // "SPV1"
version               uint16 = 1

commitment_root       Fr
commitment_next_index uint64

nullifier_root        Fr
nullifier_next_index  uint64

last_anchor_epoch     uint32
native_liability      Coins
reserve_floor         Coins

^frontier_store
^anchors_store
^config_store
^vk_store
```

No admin key exists.

### 13.1 Canonical persistent-cell layout

The state root contains exactly the fields above and **4 refs**, with no trailing bits or refs.

Both `*_next_index` counters are uint64 **only to represent the exhausted sentinel `2^32`**. Every actual commitment/IMT leaf index remains uint32. Any state with a next-index greater than `2^32` is invalid.

#### frontier_store

A chain of twelve level nodes, level 0 first, each holding that level's seven
slots as canonical `Fr` values. A cell holds 1023 bits and a field element
needs 256, so a level is three cells:

```text
level node   v0 v1 v2  (768 bits)   ^second   ^next
second       v3 v4 v5  (768 bits)   ^third
third        v6        (256 bits)
```

`^next` points at the node for level + 1 and is **absent at level 11**, which
is the only level whose node has one reference rather than two. Every node
has exactly 768 data bits, every `second` exactly 768 and one reference, every
`third` exactly 256 and none. A store whose shape differs anywhere is invalid
and MUST be refused rather than read.

Every slot is always present. There is no encoding for an absent slot and no
canonicalisation rule about zero: a zero slot is 256 zero bits like any other
value. At genesis every one of the eighty-four slots is zero (§13.2), and none
of them is read before it is written, because at index zero every digit is
zero and §5.1 takes `EMPTY_ROOT[level]` for every slot above the digit.

This replaced a `HashmapE 7` keyed by `level * 7 + child_position` on
2026-09-21. The access pattern is a sequential walk over a dense, contiguous,
compile-time-known key space, which is not what a sparse dictionary is for,
but the reason for the change is the cost *shape*: a dictionary append ran
from 108,544 gas at genesis up to 172,192 at the worst reachable leaf index,
while the chain runs from 127,412 down to 123,544. A sender pre-pays the
ceiling of §14 and a ceiling has to cover the worst age the pool can reach, so
under the dictionary every sender paid for a maturity most pools will never
have.

#### anchors_store

The anchors store root has **0 data bits and exactly 2 refs**:

```text
^recent_roots_dict
^epoch_roots_dict
```

`recent_roots_dict` is `HashmapE 12`:

```text
key   = root_version % 4096
value = root_version:uint32 || root:Fr
```

`epoch_roots_dict` is `HashmapE 12`:

```text
key   = epoch % 2880
value = epoch:uint32 || root:Fr
```

Exact key/value comparison is required; slot collision alone never authenticates a root.

#### profile_hash — exact document anchor

Before building zerostate, copy this normative profile into the TOS repository as:

```text
doc/shielded-pool-v1-profile.md
```

The copy MUST be byte-for-byte the reviewed profile except for line-ending normalization to **LF**.
Encoding is UTF-8, no BOM, no trailing-space rewriting and no generated header/footer.

```text
profile_hash =
  SHA256(
    ASCII("TOS-SHIELDED-PROFILE-DOC-v1\0") ||
    exact_LF_normalized_UTF8_profile_bytes
  )
```

Build/test tooling MUST emit the source memo commit/blob identifier, the copied file SHA-256 and
`profile_hash`. A changed normative profile therefore changes deployment StateInit and cannot silently drift.

#### config_store

Root:

```text
profile_hash            bits256
poseidon_manifest_hash  bits256
groth16_vk_hash         bits256
withdrawal_fee          Coins
denomination_count      uint8
^denomination_chain
```

Exactly one ref.

`withdrawal_fee` is immutable for a V1 deployment and MUST be positive.
Contract requires the transaction public `withdrawal_fee` to equal this value.

The denomination list contains at most 16 sorted unique positive native-TOS amounts.
The chain contains exactly `denomination_count` nodes:

```text
amount:Coins
^next                  // omitted only on final node
```

No duplicate or unsorted amount is valid.

#### vk_store

The canonical VK byte stream is exactly **1248 bytes**, in this order:

```text
alpha_g1[48] ||
beta_g2[96] ||
gamma_g2[96] ||
delta_g2[96] ||
IC[0][48] || ... || IC[18][48]
```

It is stored as the canonical ordinary level-zero byte chain used elsewhere in V1:

```text
9 non-final cells × 127 bytes
1 final cell         × 105 bytes
total                  1248 bytes / 10 cells
```

Every non-final cell has exactly one ref; the final cell has zero refs; no special cells, short non-final cells,
trailing empty cell, extra bits or refs.

`groth16_vk_hash = SHA256(exact_1248_byte_stream)`.

`vk_store` **MUST always contain** the canonical 1248-byte VK chain in persistent state, so zerostate/state BOC is unique.
The contract implementation MAY additionally compile/cache the same VK in code as a performance optimization, but
that does not remove or alter `vk_store`; build/zerostate tests MUST prove byte/hash equality.
Runtime VK replacement is forbidden.

### 13.2 Initialization

Zerostate generator MUST initialize:

- commitment root = 7-ary depth-12 empty root;
- `commitment_next_index:uint64 = 0`;
- nullifier root = the IMT genesis root containing only the head sentinel;
- `nullifier_next_index:uint64 = 1`;
- `last_anchor_epoch = 0xffffffff`;
- a frontier store of twelve levels in the §13.1 shape, every one of the
  eighty-four slots zero;
- empty recent-root and epoch-root dictionaries;
- `native_liability = 0`;
- configured positive reserve floor;
- configured positive withdrawal fee;
- immutable sorted denomination list;
- exact profile / parameter / VK hashes.

A deployment fixture whose initial state hash differs from the frozen generated manifest MUST fail.

### 13.3 Canonical message-bundle size table

The V1 parser MUST enforce exact root/ref shape before expensive crypto.

| Cell/bundle | Data | Refs |
|---|---:|---:|
| transact root | fixed fields; must fit one ordinary cell | **4 exactly** |
| proof bundle root | **768 bits** (`anchor_root,nf0,nf1`) | **2 exactly** |
| note-bodies cell | **768 bits** (3 Fr) | **0 exactly** |
| Groth16 proof root | **768 bits** (`A48 + C48`) | **1 exactly** |
| Groth16 B cell | **768 bits** (`B96`) | 0 |
| output bundle root | **256 bits** recovery owner commitment | **4 exactly** |
| auth bundle root | **0 bits** | **4 exactly** |
| nullifier-witness bundle root | **0 bits** | **2 exactly** |
| IMT witness root | **576 bits** | **2 exactly** |
| IMT path cell 0..22 | **768 bits** | 1 |
| IMT path final | **768 bits** | 0 |
| output-data chain | **1233 bytes = 10 cells**: 9×127 B + final 90 B | canonical linked refs |
| ML-DSA public-key chain | **1312 bytes = 11 cells**: 10×127 B + final 42 B | canonical linked refs |
| ML-DSA signature chain | **2420 bytes = 20 cells**: 19×127 B + final 7 B | canonical linked refs |
| recovery record root | **768 bits** | **1 exactly** |
| recovery record tail | **256 bits** | **1 exactly** |
| VK byte chain | **1248 bytes = 10 cells**: 9×127 B + final 105 B | canonical linked refs |

The contract MUST run shape/length checks before ML-DSA, Groth16, IMT hashing or state mutation.

## 14. Backing and gas rules

### 14.1 Normal deposit/transact: never ACCEPT

Normal `deposit`, `transact` and `reserve_topup` paths **MUST NOT call ACCEPT**.

Gas/fee constants:

```text
DEPOSIT_GAS_CEILING    = 230_000
TRANSACT_GAS_CEILING   = 1_510_000
BOUNCE_GAS_CEILING     = 240_000
TOPUP_GAS_CEILING      = 10_000
RECOVERY_FEE_MARGIN    = 0
```

Each ceiling is set by one rule, so that nobody picks a margin:

```text
B = an upper bound on the gas of the worst legal successful path for that
    operation, under the Poseidon2 tariff and denomination list this profile
    freezes
C = max(10_000, round_up_10_000(ceil(B * 5 / 4)))
```

**`B` is a bound and not a measurement.** A transact ranges over a leaf index with 2^32 values, two anchor-ring
occupancies, three anchor kinds, every configured denomination and two nullifier insertion orders; nothing built by
hand visits enough of that product to establish a maximum over it, and a maximum over a sample is a sample. The
bound is derived instead, from the structure of the handlers: each is a straight line whose variable calls read only
their own arguments, so its cost is a constant plus one term per call, and

```text
cost(any legal path) <= cost(one measured transaction)
                        + sum over calls of (that call's worst - its best)
```

where each span is one function over one domain small enough to walk end to end -- every configured denomination,
all three anchor kinds, every slot of both rings at every occupancy either passes through, every base-seven digit at
every tree level, both nullifier orders, and both ends of the `Coins` range the state cell stores. The corner that
sum describes need not be reachable; an upper bound is not required to be attained.

These four values were derived that way on 2026-09-23, against bounds of 176,694 / 1,205,003 / 186,991 / 2,480 for
deposit / transact / bounce / top-up. An implementation MUST re-derive them, not re-measure them, whenever the
Poseidon2 tariff, the denomination list, the handler code or the basechain gas schedule moves. The rule is stated as
an equality and MUST be read as one: below it a legal path can be cut off inside a contract whose code hash is its
address, and above it every sender on that path is charged `get_compute_fee(ceiling)` for compute nobody spends.

`RECOVERY_FEE_MARGIN=0` is the frozen **coding-profile** value. Safety margin for a deployment is primarily
provided by choosing `config.withdrawal_fee` above the measured minimum. If activation measurements require a
non-zero protocol margin constant, change this profile/deployment before activation; Claude Code must not invent one.

These ceilings are fail-closed: they bound what a bug can burn, and they are the sender's cost cap. They are stated
for the tariff and configuration this profile freezes, and they are not a claim about any other.

The critical rule is **message-local funding**. Global pool surplus may not substitute for required inbound
funding.

For this profile, `msg_value` means the **credited/remaining inbound TOS value passed to `recv_internal` and used by
ordinary internal-message gas admission**, not an untrusted body field or the sender's pre-forward-fee nominal value.

After the cheap parse needed to identify the operation and after its funding inequality is established, every normal
handler MUST immediately execute:

```text
deposit:       set_gas_limit(DEPOSIT_GAS_CEILING)
transact:      set_gas_limit(TRANSACT_GAS_CEILING)
reserve_topup: set_gas_limit(TOPUP_GAS_CEILING)
```

and MUST NOT call `ACCEPT`.

The funding inequality by itself is **not sufficient**: without `SETGASLIMIT`, a large deposit principal also buys a
large initial internal-message gas limit, so a bug could burn principal as compute. The explicit ceiling makes the
maximum compute loss independent of principal size.

Deposit requires:

```text
msg_value
  >= deposit_amount
   + get_compute_fee(wc0, DEPOSIT_GAS_CEILING)
```

and, independently at end state:

```text
actual_balance >= new_native_liability + reserve_floor
```

Therefore an attacker cannot declare a deposit larger than its inbound principal and convert pre-existing
operational reserve into a private note.

Transfer transact requires:

```text
msg_value >= get_compute_fee(wc0, TRANSACT_GAS_CEILING)
```

Withdrawal transact requires the same compute funding. The public `withdrawal_fee` is paid from shielded
value via circuit conservation and retained by the pool as operational reserve; it is not taken from
`msg_value`.

Reserve top-up requires:

```text
msg_value >= get_compute_fee(wc0, TOPUP_GAS_CEILING)
```

then `set_gas_limit(TOPUP_GAS_CEILING)`. Whatever remains after bounded compute increases operational reserve.

### 14.2 Withdrawal fee solvency check

Before accepting a withdrawal proof, compute the forward/action fee for the exact outbound message.

Require:

```text
withdrawal_fee == config.withdrawal_fee

withdrawal_fee
  >= exact_outbound_forward_fee
   + RECOVERY_FEE_MARGIN
```

The floor covers what the pool spends **before any bounce can exist**: sending the payout, as its sender.
It does not cover the recovery's compute, which section 15.4 charges to the money being recovered.

That term used to be here, and it was the dangerous one. `config.withdrawal_fee` is immutable while this
check reads live prices, so a fee that had to stay ahead of a governed **compute** price could be overtaken
permanently -- bricking every withdrawal at this exit while deposits and transfers carried on, with no way
to change the fee. What remains prices bytes rather than work.

It is also fairer: the old floor made every withdrawal pre-pay for a recovery, and almost no withdrawal
bounces.

`RECOVERY_FEE_MARGIN` is exactly `0` in this coding profile. Production activation must measure the real
path and choose `config.withdrawal_fee` with explicit headroom; changing the margin constant itself requires
an explicit profile/deployment revision.

If current config pricing makes the inequality false, withdrawals fail closed until the deployment/profile
is updated. Deposit/private transfer remain available.

### 14.3 Liability transition

For transfer:

```text
new_liability = old_liability
```

For withdrawal:

```text
new_liability =
  old_liability
  - public_amount_out
  - withdrawal_fee
```

The `withdrawal_fee` value stays in the contract balance and therefore becomes unencumbered reserve.

Before creating the outbound withdrawal:

```text
raw_reserve(new_liability + reserve_floor, 0)
```

Send exactly `public_amount_out` as message value with sender-side forward/action fees paid separately
(mode `1 + 16 = 17`).

The recipient may spend some of that message value on its own compute. V1 defines
`public_amount_out` as the **gross outbound message value before recipient compute**, which is the public
boundary amount observers see.

## 15. Withdrawal body and recovery

### 15.1 Recovery template is pre-authorized, amount is not

For withdrawal, wallet prepares:

- fresh `recovery_owner_commitment`;
- fixed 1233-byte `recovery_output_data` encrypted to itself;
- recovery payload flag bit1=1;
- encrypted plaintext amount = 0.

Contract computes:

```text
recovery_data_hash =
  hash_exact_output_data(recovery_output_data)

recovery_template_hash =
  H7(
    "RECOVERY-TEMPLATE",
    recovery_owner_commitment,
    recovery_data_hash,
    0,0,0,0,0
  )
```

This is Groth16 public input #16 and is signed via the intent digest.

The future recovery amount is deliberately absent because it is not known until an actual bounce returns.

### 15.2 Outbound recipient body

The recipient-facing message root is intentionally short:

```text
op:uint32 = 0
query_id:uint64
^recovery_record
```

`recovery_record` is split into two ordinary cells because four Fr values would require 1024 data bits.

```text
recovery_record_root:             // exactly 768 bits + 1 ref
  transaction_intent_digest:Fr
  recovery_template_hash:Fr
  public_recipient_hash:Fr
  ^recovery_record_tail

recovery_record_tail:             // exactly 256 bits + 1 ref
  recovery_owner_commitment:Fr
  ^recovery_output_data
```

No trailing bits/refs are allowed. The full original body is requested through rich-bounce extra flags `3`.

### 15.3 What counts as a genuine bounce

A production-chain contract cannot create an ordinary outbound message with `bounced=1`; normal action
serialization/canonicalization produces non-bounced outbound messages, while the protocol bounce phase creates
the bounced message.

The pool bounce handler MUST still validate **before ACCEPT**:

1. inbound header has `bounced=1`;
2. rich-bounce body is the V12+ full-original-body form, not a legacy/truncated body;
3. original body has exact §15.2 shape;
4. `query_id == low64(transaction_intent_digest)`;
5. parse `INMSG_SRC_ADDR` as canonical non-anycast wc0 `addr_std`, extract its 32-byte account id, recompute the exact §8 `public_recipient_hash` formula, and require equality;
6. recomputed recovery-template hash equals the record value;
7. recovery output-data has the exact canonical **outer** 1233-byte form and its exact bytes recompute the record's `recovery_template_hash`. **The contract does not and cannot inspect the encrypted plaintext recovery flag; that flag is enforced only by wallet post-decryption validation (§3.1).**

Only after these cheap checks may the bounce handler call `ACCEPT`, immediately followed by:

```text
set_gas_limit(BOUNCE_GAS_CEILING)
```

This bounded accepted gas is charged to the value being recovered, at the prices live when the bounce arrives:
section 15.4's `recovery_charge`. It is **not** pre-paid out of `config.withdrawal_fee`, and section 14.2's floor
does not carry a term for it. It did until 2026-09-22, and that term was the dangerous one: an immutable fee had to
stay ahead of a compute price the chain can govern upwards, so a large enough rise would have bricked every
withdrawal permanently while deposits and transfers carried on.

Tests MUST use a **real outbound -> failure -> protocol-generated bounce round trip**.
A sandbox helper that merely fabricates `bounced=true` is not sufficient evidence.

### 15.4 Recovery amount and note construction

Let `msg_value` be the value actually credited by the bounced message before recovery compute.

A bounced internal message still needs enough inbound value to execute the **pre-ACCEPT authenticity checks**.
V1 therefore does **not** promise recovery for arbitrarily small/dust bounced values.

Activation testing MUST measure and freeze a `min_recoverable_bounce_value` for the active fee schedule:
the smallest real protocol-generated bounce that reaches the authenticated `ACCEPT` point. Below that threshold,
the handler MUST never mint a note; any credited remainder that cannot execute recovery is treated as user loss /
unencumbered reserve according to actual transaction semantics.

The recovery is work, and the money being recovered pays for it:

```text
recovery_charge = get_compute_fee(wc0, BOUNCE_GAS_CEILING)
```

read at the prices live when the bounce arrives. It is the ceiling rather than what the transaction actually
spends, because the note commitment must be built before the transaction's own cost is known and building it
costs gas -- an exact charge is circular. The ceiling is declared, derived by the section 14.1 rule, and
computable by a wallet before it withdraws.

If authenticated recovery reaches the post-ACCEPT phase and `msg_value <= recovery_charge`, **no recovery
note is minted**. This is the `msg_value == 0` rule with its threshold moved off zero: below it, minting
would hand the user a note the rest of the pool had paid for. The credited remainder stays in the balance as
unencumbered reserve, which is where this transaction's gas comes from.

Otherwise:

```text
recovered_amount = msg_value - recovery_charge

recovery_note_body =
  H7(
    "NOTE-BODY",
    recovery_owner_commitment,
    recovered_amount,
    recovery_data_hash,
    0,0,0,0
  )
```

Then:

1. `native_liability += recovered_amount`;
2. checkpoint current root into recent/epoch anchor structures if needed;
3. append the recovery note body at a fresh leaf index;
4. save state once;
5. assert backing invariant.

**The pool never restores more principal than actually returned by the bounce, less the cost of
restoring it.**
Any amount consumed by recipient compute, forwarding, bounce transport or the pool's own recovery compute is
the withdrawing user's loss, not a subsidy from other users' reserve.

The fixed `withdrawal_fee` funds pool-side sender fees only; it does not fund recovery compute and it does
not reimburse lost principal.

### 15.5 Replay model

V1 does not keep an unbounded pending-withdrawal map.

The chain's message model consumes an internal message once and protocol-generates at most one bounce for a
failed outbound. Ordinary contracts cannot manufacture a valid `bounced=1` message through SENDRAWMSG.

Therefore the V1 replay boundary is:

- real chain round trip exactly once;
- duplicate synthetic bounced messages in a unit harness are **not** treated as valid consensus traces;
- tests MUST verify normal outbound action rewrites/serializes `bounced=0` and only the protocol failure path
  creates the accepted bounce.

If future consensus changes make user-forgeable/replayable bounced messages possible, V1 recovery must be
version-gated off until a bounded replay structure is added.

## 16. Contract execution order

### 16.1 Deposit

1. parse exact deposit body/ref shape;
2. reject nonstandard denomination / amount range;
3. enforce `msg_value >= deposit_amount + compute_fee(DEPOSIT_GAS_CEILING)`;
4. immediately `set_gas_limit(DEPOSIT_GAS_CEILING)` (**still no ACCEPT**);
5. canonical-hash exact output-data bytes;
6. derive note body;
7. ensure end-state backing invariant can hold;
8. checkpoint pre-mutation commitment root into recent/epoch rings;
9. append contract-assigned final note;
10. increment liability by deposit amount;
11. `set_data` once.

No `ACCEPT`, no `COMMIT`, no outbound action.

### 16.2 Transact

Exact order:

1. parse canonical body/ref counts/sizes;
2. message-local compute funding check (**no ACCEPT**), then immediately `set_gas_limit(TRANSACT_GAS_CEILING)`;
3. derive execution domain;
4. parse/canonical-check all Fr, Coins, addresses and anchor metadata;
5. validate transfer/withdraw mode, `withdrawal_fee`, recipient and `valid_until`; for withdrawal also require `public_amount_out` is exactly in the immutable denomination list;
6. hash 3 actual output-data payloads;
7. hash 2 full ML-DSA public keys;
8. compute recovery-template hash or require transfer recovery fields zero;
9. validate anchor using current/recent/epoch policy;
10. validate both nullifier witnesses against temporary IMT roots **without saving state**;
11. verify both ML-DSA signatures over exact intent digest;
12. verify Groth16 with the exact 18-element public vector;
13. checkpoint pre-mutation commitment root into recent/epoch rings;
14. apply temporary nullifier IMT roots sequentially;
15. append 3 final note commitments sequentially;
16. if withdrawal:
    - compute exact outbound fee;
    - verify §14.2 fee solvency;
    - set `new_liability = old - public_amount_out - withdrawal_fee`;
    - `raw_reserve(new_liability + reserve_floor, 0)`;
    - enqueue exactly one mode-17 payout with rich-bounce flags 3;
17. save all persistent state once.

No `COMMIT` opcode is allowed before or after step 17 in V1.
The successful return from the handler is the commit boundary.

Implementation MUST keep temporary roots/frontier/liability in stack/local cells until the final `set_data`.

### 16.3 Bounce recovery

Pre-ACCEPT:

1. check `INMSG_BOUNCED`;
2. parse rich-bounce full-original-body envelope;
3. verify exact recovery record/query/source/template/payload shape.

Then:

4. `ACCEPT`;
5. immediately `set_gas_limit(BOUNCE_GAS_CEILING)`;
6. compute `recovered_amount = msg_value`;
7. if zero, return without minting;
8. compute semantic recovery note body from **actual recovered amount**;
9. checkpoint pre-mutation commitment root;
10. append one final recovery note at fresh leaf index;
11. increase liability by `recovered_amount`;
12. save state once and assert backing invariant.

### 16.4 Reserve top-up

1. exact op/query body only;
2. require `msg_value >= get_compute_fee(wc0, TOPUP_GAS_CEILING)`;
3. immediately `set_gas_limit(TOPUP_GAS_CEILING)`;
4. no `ACCEPT`;
5. no liability/state mutation required;
6. no outbound messages.

The credited inbound remainder after bounded compute becomes unencumbered reserve.

## 17. Groth16 / ceremony boundary

The circuit implementation must output:

- deterministic R1CS/constraint-system digest;
- exact ordered public input manifest;
- proving/verifying key hash;
- circuit source commit.

Phase 1 may reuse a BLS12-381 Powers-of-Tau artifact only after its provenance/hash is independently
recorded.

**Phase 2 is not a coding prerequisite.** Claude Code should implement the circuit/prover/verifier integration
using deterministic development keys/fixtures first. Production Phase 2 occurs only after circuit freeze.

Any relation/public-input change after Phase 2 creates profile V2 or a new V1 circuit revision and requires a
new Phase 2.

---

## 18. Code layout / work packages

Normative existing-tree targets:

### WP-A — Poseidon2 VM ISA

Normative details are in `TOS_POSEIDON2_OPCODE_WORK_ORDER.md`.

```text
crypto/vm/poseidon2ops.{h,cpp}        new
crypto/vm/cp0.cpp                     register ops
crypto/vm/vm.h                        gas constants
crypto/fift/lib/Asm.fif               mnemonics
common/global-version.h               advertise SUPPORTED_VERSION=17
doc/GlobalVersions.md                 V17 ISA record
test/pq-readiness/test_release_profile.py

tosctl/src/vm/src/executor/...         Rust VM parity
tosctl/src/assembler/src/simple.rs     assembler parity
```

Use global version 17; ML-DSA remains min-version 16. The executed V15/V16/V17 matrix from the opcode work order
is part of WP-A, not an activation-time afterthought.

### WP-B — Pool contract

```text
crypto/smartcont/tos-shielded-pool-v1.fc
test/shielded-pool/                    build + sandbox + mutation suite
```

FunC is normative V1 contract implementation. A Tol port may follow after byte/behavioral profile is frozen.

### WP-C — Circuit/prover tool

Create a standalone Rust tool module:

```text
tools/shielded-pool-circuit/
```

It may use a maintained BLS12-381 Groth16/R1CS library, but its output format and relations are fixed by
this profile, not by the library. The module MUST export development proof/VK fixtures consumable by
`test/shielded-pool/`.

Moving this non-consensus tool directory to fit build-system conventions is allowed; changing its circuit is not.

### WP-D — Wallet crypto

```text
sdk/js/packages/crypto/src/shielded/
```

Implement:

- mnemonic-derived owner-nullifier key;
- ML-KEM-768 key derivation;
- one-time ML-DSA descriptors;
- output-data encrypt/decrypt;
- note scanning/recovery;
- the exact §3.1 plaintext-to-chain-note validation algorithm, including dummy/recovery handling and descriptor reuse;
- proof request / intent signing serialization.

If ML-KEM is added as a native vendored dependency, pin exact upstream commit/version and add independent
known-answer/interoperability vectors.

---

## 19. Acceptance gates — coding may start, activation may not

Claude Code may start WP-A..D immediately from this profile.

Mainnet/testnet activation is blocked until all are true:

1. **Poseidon2 pin parity:** C++/Rust/reference t=8 RF=8 RP=57 vectors match; mutate any constant -> tests fail.
2. **Opcode collision/version:** 0xF93200/01 unique; binary advertises `SUPPORTED_VERSION=17`; executed matrix proves V15 rejects ML-DSA/Poseidon2, V16 accepts ML-DSA but rejects Poseidon2, V17 accepts both.
3. **Circuit negative tests:** remove every relation one at a time; the targeted exploit vector becomes accepted
   before removal is reverted.
4. **Deposit inflation:** deposit amount 1 can never create a note body for amount 100, even when the pool has a
   large pre-existing operational reserve.
5. **Message-local funding:** deposit/transact with inbound value below their local §msg_value§ requirement fail
   before expensive work and never consume pre-existing shielded backing.
6. **PQ substitution:** swap either public key/signature to attacker-controlled valid pair -> reject.
7. **PQ one-time recovery:** mnemonic-only restore derives every used note-specific owner-NF/ML-DSA key by
   §note_key_index§ and never reissues an already-used descriptor index.
8. **Phantom indistinguishability:** wire has exactly 2 full keys + 2 signatures in both 1-real and 2-real cases.
9. **Payload substitution:** flip one bit in any 1233-byte output payload -> proof/public inputs mismatch.
10. **IMT:** full predecessor/non-membership/update/append semantics run in real TVM; two sequential nullifiers pass;
    bad successor tuple, nonempty append leaf, duplicate or reordered witnesses fail.
11. **Atomicity:** compute throw, OOG, action failure and state-limit failure never leave only nullifier, only notes
    or a changed liability.
12. **Backing:** after every deposit/transfer/withdraw-success/withdraw-bounce path:
    §actual_balance >= native_liability + reserve_floor§.
13. **Withdrawal boundary/fee:** a withdrawal with `public_amount_out` not in the immutable denomination list is rejected; configured fee must cover the current exact outbound forward fee + margin, and **must be measured against a forwarding price the chain could return to, not only today's** -- the fee is immutable while the check reads live prices; changing fee public input away from config fails. The bounded bounce-recovery compute was part of this floor until 2026-09-22 and is now charged to the recovered amount (§15.4), so a gate that still required it here would be requiring the thing that change removed.
14. **Real rich bounce:** execute an actual pool outbound -> destination failure -> protocol-generated rich bounce.
    Recovery liability/note amount equals the **actual bounced msg_value less §15.4's recovery charge**, never the original principal when value was lost, and never the gross bounced value -- minting the gross would pay for the recovery out of other users' reserve.
15. **No bounce subsidy:** a destination deliberately burning part of the withdrawal before failure cannot make the
    pool mint/restore the burned difference from other users' reserve.
16. **Bounce authenticity:** ordinary SENDRAWMSG cannot create the accepted bounced path; synthetic §bounced=true§
    injection alone is not counted as E2E evidence.
17. **Anchor concurrency:** every externally visible pre-transaction root is inserted once before its transaction's append batch; recent-root validity lasts until exact `(root_version % 4096)` slot overwrite. Tests cover pure deposit, pure transact and mixed 1/3-leaf traffic at the overwrite boundary; epoch checkpoints remain valid 24h.
18. **Mnemonic recovery:** fresh wallet from only mnemonic + chain data recovers ML-KEM key, used note-key indices,
    note-specific owner-NF/ML-DSA keys and every unspent note.
19. **Wire exactness:** malformed extra refs, trailing bits, wrong byte-chain lengths, non-canonical fields,
    bad anchor kind/id and wrong IMT path length/order all fail closed.
20. **Gas ceilings:** each §14.1 ceiling is exactly what the rule there gives for a **derived** bound, and the
    derivation walks every variable call's whole domain -- every configured denomination, all three anchor kinds,
    every slot of both rings at every occupancy, every base-seven digit at every tree level, both nullifier orders.
    A sampled maximum does not close this gate; neither does a bound whose per-level composition is not itself held
    against real multi-digit appends. Moving a ceiling in either direction must be killed.
21. **Groth16 exactness:** proof/VK canonical encodings, 18-element input ordering and IC[19] are cross-checked
    against the selected prover library; one-field/public-input mutations fail.
22. **State manifest:** zerostate initial roots, four state refs, dual anchor dictionaries, fee/denomination config,
    profile hash, parameter hash and VK hash match a frozen generated manifest.
23. **Consistency:** `measurements/consistency-check.py` plus explicit profile checks report no current-vs-historical drift.
24. **Normal-path gas cap:** after funding validation, deposit/transact/topup execute their exact `SETGASLIMIT` ceiling.
    Attach a very large deposit principal and prove compute cannot exceed the ceiling; removing the cap must be killed.
25. **Wallet plaintext validation:** ordinary/dummy/recovery payloads are accepted only by the exact §3.1 rules;
    wrong owner hash, PQ-key hash, note body, flags, slot, amount or secret never becomes spendable balance.
26. **Descriptor forced reuse:** two valid notes sent to one descriptor are both recovered/imported, the index is
    marked reused and never reissued; privacy-degraded state is surfaced.
27. **Bounce dust boundary:** a real round trip measures the minimum bounced value that can complete pre-ACCEPT
    authentication **and the §15.4 charge, asserting which of the two binds** -- since 2026-09-22 the charge is about twenty times the authentication, so it is the charge. Sub-threshold bounces never mint; above-threshold recovery mints exactly the authenticated `msg_value` less that charge.
28. **Circuit scalar hygiene:** `intent_nonce=0` and any real/dummy output `note_secret=0` fail the circuit; removing either non-zero constraint is killed by a targeted mutation.
29. **Withdrawal denomination:** every configured denomination succeeds in the boundary check; one-less/one-more and arbitrary non-list values fail before payout even with an otherwise valid proof.
30. **Cross-domain key separation:** with the same mnemonic and same `note_key_index`, two distinct execution domains derive different owner-NF keys, ML-DSA public keys and ML-KEM encapsulation keys; using a descriptor under the wrong domain fails.

## 20. Explicit non-blockers for coding

The following remain activation/product decisions but **do not permit Claude Code to invent protocol behavior**:

- exact mainnet denomination list — implement immutable genesis list, fixtures use test values;
- exact mainnet `reserve_floor` — implement genesis field, fixtures use a conservative test value;
- exact mainnet `withdrawal_fee` — fixtures use a conservative positive value; coding-profile `RECOVERY_FEE_MARGIN` is exactly 0; activation must satisfy §14.2 under live fee config with explicit withdrawal-fee headroom;
- production Groth16 Phase-2 participants/artifact — development fixture first;
- final production Poseidon gas tariff — implement meter hook and conservative development constant, then calibrate;
- third-party submitter operator identity — protocol already uses funded internal messages;
- future PQ-soundness V2 migration — only V1 version/domain hooks are implemented now.

Everything else needed to serialize, prove, verify, execute and recover a V1 transaction is frozen in this file.
