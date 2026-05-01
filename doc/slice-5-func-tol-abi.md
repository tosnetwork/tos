# Slice 5 FunC<->Tol ABI Freeze

Status: Draft v1.1, 2026-04-30, post-Stage-0-security-review fixes.

This document defines what "FunC<->Tol ABI compatibility" means for
Slice 5. It is intentionally narrower than source compatibility. The
goal is that a legacy FunC contract and a new Tol contract can exchange
messages, expose getters, parse cells, and interpret errors without
guessing how the other language serialized data.

## 1. ABI surface

The frozen ABI surface is the TVM-visible boundary:

- internal message body cells;
- external message body cells where a pattern exposes external entry
  points;
- cells used as state-init data, payloads, proofs, signed states, or
  action lists;
- get-method ids, argument stack order, and result stack order;
- public throw/error codes and `OP_ERROR` reply bodies;
- opcode prefixes and `queryId` placement;
- manifest-declared wire-compatibility exceptions.

The ABI surface is not:

- Tol helper names that are not exported by a manifest;
- FunC local helper names;
- exact generated Fift text;
- source comments, whitespace, or local variable names;
- optimizer-internal stack temporaries.

## 2. Canonical message-body rule

Every Slice 5 message body that claims cross-language compatibility must
have one canonical encoding:

1. A 32-bit opcode prefix, unless the message is explicitly declared
   opcode-less in the ABI manifest.
2. A `queryId: uint64` field immediately after the opcode for request
   or reply messages that participate in request/reply correlation.
3. Remaining fields serialized in manifest order.
4. No implicit field insertion by helpers. If a helper adds a field, the
   field appears in the ABI manifest.
5. Manual raw-cell builders are allowed only when the manifest marks the
   body encoding as `manual_cell` and names the compatibility reason and
   fixture.

External wallet-style bodies are allowed to differ from the internal
request shape only when the manifest marks direction `external` and
documents the body encoding.

### 2.1 Signature material rule

Any Slice 5 body or cell that is signed across the FunC<->Tol boundary
must declare both `signature_algorithm` and `signing_input` in the ABI
manifest.

The only signature algorithm admitted in Slice 5 is `ed25519`, using
the TVM Ed25519 verification path. The canonical signed input for
payment-channel signed states is `cell_hash`: both FunC and Tol must
construct the same state cell, sign the 256-bit `cell.hash()`, and
verify that hash. Signing a language-specific serialized byte string is
not ABI-compatible unless a later policy revision explicitly adds a
`raw_bits` fixture and proves the FunC/Tol bit layout is identical.

`CHKSIGNU`-style verification over a 256-bit hash is the default
interop target. `CHKSIGNS`-style verification over a raw slice is
allowed only when the manifest uses `signing_input = "raw_bits"` and
the message or cell has a checked fixture. Payment-channel Stage 5 must
start with `cell_hash`.

### 2.2 Optional `queryId` rule

Messages with `query_id = "optional"` must declare a
`query_id_presence` value in the ABI manifest. The presence indicator is
part of the wire layout. FunC and Tol implementations must produce the
same flag bit, length prefix, or documented custom external indicator.

Messages with `query_id = "required_after_opcode"` use no presence
indicator: the 64-bit `queryId` immediately follows the opcode.
Messages with `query_id = "absent"` must not reserve hidden bits for a
future query id.

## 3. Getter ABI rule

Every public getter used by a Slice 5 package must declare:

- method name;
- numeric `method_id`;
- argument stack order;
- result stack order;
- each stack item's ABI type;
- whether the method id is explicit or auto-derived.

Method ids `0` and negative values are reserved for TVM entrypoint
semantics and are not valid public getters in Slice 5 ABI manifests.

The result stack order is the TVM order observed by callers, not the
source-code tuple spelling. If a Tol wrapper changes the apparent return
shape, the manifest must describe the TVM-visible result.

## 4. Cell and type mapping

The Stage 1 validator must support at least these ABI type names:

| ABI type | TVM/cell meaning |
|---|---|
| `int` | TVM integer with manifest-declared signedness/bit width when stored in a cell |
| `uintN` | unsigned integer stored in exactly `N` bits, where `1 <= N <= 1023` |
| `intN` | signed integer stored in exactly `N` bits, where `1 <= N <= 1023` |
| `bool` | one-bit boolean in cells, TVM integer on stack |
| `coins` | canonical Tol/FunC coin serialization for message cells |
| `address` | MsgAddress-compatible address serialization |
| `any_address` | address serialization that may include non-standard address forms |
| `cell` | TVM cell reference |
| `slice` | TVM slice |
| `builder` | TVM builder |
| `dict` | TVM dictionary cell/null representation |
| `uint256` | unsigned 256-bit integer, commonly used for hashes and public keys |
| `remaining_bits_and_refs` | raw suffix intentionally preserved as bits/refs |
| `custom:<Name>` | extension type that must correspond to a manifest `cell_types[].name` |

For any type not listed here, the ABI manifest must use the
`custom:<Name>` spelling and define a matching `cell_types[].name`, or
mark the field as a wire-compatibility exception. Ad hoc aliases such as
`u32` are not ABI type names.

Oracle median helpers sort accepted report values. For an odd accepted
report count, the median is the middle sorted value. For an even
accepted report count, the median is the integer-truncated average of
the two middle sorted values; the two-report case is
`(value1 + value2) / 2`. FunC reimplementations must use the same
round-toward-zero convention to match Tol-visible results.

Oracle outlier protection uses the running median of already accepted
reports as the anchor. This gives a majority-style anchor only after at
least two prior reports exist, so deployments that rely on
`maxDeviation` to resist a compromised first reporter must use quorum
`>= 3`. Quorum `2` is ABI-valid but the second report is necessarily
checked against the first report as the only available anchor.

Oracle round-start authorization is ABI-visible through
`Slice5OracleConfig.roundStarter`. Tol contracts pass the actual
`in.senderAddress` into `slice5OracleStartRound`; FunC implementations
must compare the same sender address against the stored starter before
mutating the active round.

## 5. Error ABI rule

Slice 5 packages use the Slice 1 error model:

- public Slice 5 stdlib error codes are integers in the
  `1024..65535` range;
- public stdlib errors are listed in the ABI manifest;
- application-level error replies use the existing `OP_ERROR` body;
- `ErrorClass.BackPressure` remains reserved until `actor.md` section
  5.7 is approved.

Codes `0..13` are TVM/system exception space and must not be used for
Slice 5 public stdlib errors. Lower legacy throw codes may appear only
as documented compatibility inputs that map to public Slice 5 errors.

Existing Slice 3/4 helpers that already expose BackPressure-class values
must record those as pre-section-5.7 compatibility exceptions. New Slice
5 helpers must not introduce active BackPressure semantics.

## 6. Manifest and hash rule

Each second-wave package ships a `slice-5-abi-manifest` JSON document.
The manifest is the canonical audit artifact for cross-language
compatibility.

Stage 1 defines a canonical JSON normalization for hashing. Until that
normalization is implemented, hashes in release notes are advisory.
After Stage 1 lands, any schema change requires a policy revision entry
and revalidation of all previously committed Slice 5 ABI manifests.
Once Stage 7 freezes the schema, changing any ABI-visible field requires
one of:

- a new manifest version;
- a compatibility exception with reason and replacement guidance;
- a documented breaking-change window outside Slice 5.

## 7. Interop fixture rule

The ABI validator is not accepted until it has at least one fixture that
compares a FunC-produced artifact with a Tol-produced artifact. The
first fixture should be small: a body cell with opcode, query id, an
address, and an amount is enough. Later pattern stages add package-
specific fixtures.

The fixture must fail if:

- field order changes;
- opcode width changes;
- a `queryId` is inserted, removed, or moved;
- a manual builder disagrees with Tol auto-serialization;
- a `manual_cell`, `raw_slice`, or `raw_suffix` fixture is missing;
- a signed-state fixture signs raw bytes in one implementation and a
  cell hash in the other;
- getter stack order changes.

Production contracts may reuse a stdlib golden fixture when their ABI
manifest intentionally reuses the exact same message wire body. The
fixture reference must include `wire_reuse_of: "<StdlibContract>"`; the
validator then accepts the referenced fixture's original `contract`
field only when it matches that stdlib contract and still validates the
message name, body encoding, canonical body hex, and SHA-256. This
prevents per-contract fixture copies that differ only by contract name
without weakening wire-identity checks.

## 8. Versioning rule

Slice 5 starts with ABI manifest `version = 1`. Within version 1:

- new optional manifest-only metadata may be added only by a schema
  revision before Stage 7 freeze;
- message fields, getter stack items, public error codes, and cell
  encodings are append-only only when the target wire format already
  supports that extension;
- deleting or reordering ABI-visible fields is a breaking change.

After Stage 7 freeze, schema changes require a new policy amendment and
cannot be bundled silently with a stdlib helper patch.

## 9. Security review checklist

Reviewers should reject a Slice 5 ABI manifest if:

- any opcode-bearing body lacks a 32-bit opcode;
- a request/reply body has ambiguous `queryId` semantics;
- a getter lists names but not stack order;
- a `manual_cell`, `raw_slice`, or `raw_suffix` body/cell has no fixture;
- an error code collides with an existing public error in the package;
- a BackPressure class appears without a pre-section-5.7 exception;
- a signed state does not declare Ed25519 and `cell_hash`/`raw_bits`;
- a field type is too vague to reproduce in both FunC and Tol.
