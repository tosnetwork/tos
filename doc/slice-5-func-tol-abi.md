# Slice 5 FunC<->Tol ABI Freeze

Status: Draft v1, 2026-04-30.

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
   body encoding as `manual_cell` and names the compatibility reason.

External wallet-style bodies are allowed to differ from the internal
request shape only when the manifest marks direction `external` and
documents the body encoding.

## 3. Getter ABI rule

Every public getter used by a Slice 5 package must declare:

- method name;
- numeric `method_id`;
- argument stack order;
- result stack order;
- each stack item's ABI type;
- whether the method id is explicit or auto-derived.

The result stack order is the TVM order observed by callers, not the
source-code tuple spelling. If a Tol wrapper changes the apparent return
shape, the manifest must describe the TVM-visible result.

## 4. Cell and type mapping

The Stage 1 validator must support at least these ABI type names:

| ABI type | TVM/cell meaning |
|---|---|
| `int` | TVM integer with manifest-declared signedness/bit width when stored in a cell |
| `uintN` | unsigned integer stored in exactly `N` bits |
| `intN` | signed integer stored in exactly `N` bits |
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

For any type not listed here, the ABI manifest must either define a
`cell_type` entry or mark the field as a wire-compatibility exception.

## 5. Error ABI rule

Slice 5 packages use the Slice 1 error model:

- throw codes are integers in the `0..65535` range;
- public stdlib errors are listed in the ABI manifest;
- application-level error replies use the existing `OP_ERROR` body;
- `ErrorClass.BackPressure` remains reserved until `actor.md` section
  5.7 is approved.

Existing Slice 3/4 helpers that already expose BackPressure-class values
must record those as pre-section-5.7 compatibility exceptions. New Slice
5 helpers must not introduce active BackPressure semantics.

## 6. Manifest and hash rule

Each second-wave package ships a `slice-5-abi-manifest` JSON document.
The manifest is the canonical audit artifact for cross-language
compatibility.

Stage 1 defines a canonical JSON normalization for hashing. Until that
normalization is implemented, hashes in release notes are advisory. Once
Stage 7 freezes the schema, changing any ABI-visible field requires one
of:

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
- getter stack order changes.

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
- a `manual_cell` body has no fixture;
- an error code collides with an existing public error in the package;
- a BackPressure class appears without a pre-section-5.7 exception;
- a field type is too vague to reproduce in both FunC and Tol.
