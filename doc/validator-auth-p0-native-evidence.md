# Native transaction evidence container

This additive native ingress preserves the frozen VAA1/VAF1, object manifests,
authorization families and profile fingerprint. `NativeEvidence` admits bounded
transaction-contained data. Admission does not itself confer owner, possession,
identity or governance authority.

## Native cell representation

```
native_evidence#76616531 version:uint16
  authorizations:^AuthBytes mc_header:^Cell
  attachments:(HashmapE 264 ^AuthBytes) = NativeEvidence;
```

Version is exactly 1. The ordinary, unvirtualized, level-zero root contains 49 bits
and two or three references: VAA1 bytes, header witness, and the attachment dictionary
when nonempty. There are no trailing bits or references. Bit and reference streams
retain the field order above. The dictionary key is `object_id:bits256 || index:uint8`.
Values have zero inline bits and one AuthBytes reference. Native dictionary labels
must equal the canonical dictionary reconstructed from their admitted leaves.

Each of the four VAA1 lists retains its frozen maximum of one entry. The enclosing
AuthBytes limit is 266240 bytes: four 65536-byte variable fields plus 4096 bytes of
fixed fields and framing. This covers the largest canonical VAA1 representation;
a manifest is smaller than the inline field it replaces. Existing binary decoders
still enforce exact field/list/length/version rules and consume all input.

Owner evidence contributes one kind-5 proof object. Identity administration and
governance each contribute one kind-4 certificate object. Possession contributes
its existing bounded signature bytes. This container does not convert one family
into another. Each object retains exactly one canonical inline/manifest encoding.

All expected manifest keys are derived before reading chunk payloads. Unexpected
keys, missing keys, extra bits/references, inconsistent manifests for a shared
object ID and incorrect declared chunk sizes are rejected. Enumeration stops at
the first unrequested key, so at most the admitted keys plus one are inspected.
There are at most three manifests with at most 64 chunks each; every chunk is at
most 1048576 bytes. Each dictionary value uses the existing canonical AuthBytes tree,
including its length and hash. The reader also checks each domain-separated chunk
hash and the complete typed object ID. Shared objects may reuse the same exact
manifest and physical chunks; inconsistent aliases are rejected.

The sum of declared object lengths, including each use of a shared object and all
inline objects, must not exceed 67108864 bytes. This is the existing aggregate
ObjectReader bound. Header size is separately bounded by native header admission.
The enclosing native message/BOC and actual execution gas limits may impose smaller
limits; the parser's maximum is not a promise that every maximum-sized object fits
in a native transaction.

## Deterministic work and owner history

Admission requires a charge callback. Its first call covers the declared VAA1 byte
length, before AuthBytes decoding or hashing. Its second covers the admitted sum of
object lengths, before chunk decoding, reconstruction or object hashing. A refused
charge stops processing immediately. Structural inspection before these callbacks
is fixed or bounded by the admitted manifests; payload trees are not walked early.
The callback receives byte work bounds, not monetary amounts or a finalized gas
schedule. Concrete native VM pricing and registry/proof/signature work remain
separate integration requirements. No archive/network reader is invoked.

When owner evidence is absent, the header must be the canonical empty ordinary
cell. When present, `authenticate_owner` uses the independently authenticated native
history and fixed-surface header verifier. The returned coordinate, root, file and
resulting state must all equal the VAF1 anchor. That authenticates the anchor only;
the native owner-execution verifier must still check the actual successful wallet
transaction, owner/stake/update binding and finality-before-inclusion rule.

The shared 39-case corpus covers all four authorization lists at their inline
bounds, multiple chunks, shared manifests, shape/version/type substitution, unused
and missing attachments, nonminimal dictionary labels, chunk/object digests,
aggregate limits, refusal before decoding and full owner-anchor substitution.
Both implementations produce the same results and byte-charge sequence. Compiled
guard removals require named assertion failures; compiler/fixture failures are not
counted as kills. Full-dependency Ubuntu/ARM sanitizer exports are compared with
the ordinary native exports. This is ingress evidence, not an end-to-end native
transaction or enabled-network acceptance result.
