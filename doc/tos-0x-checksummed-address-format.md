# TOS 0x Checksummed Address Format

Version: v0.1

## 1. Purpose

This document defines an optional application-layer string format for TOS addresses that follows a familiar `0x...` presentation style while preserving the full TOS address payload:

- `workchain`
- `account_id` / `address hash` (32 bytes)

This format is intended for:

- wallets
- block explorers
- SDK helpers
- user interfaces
- copy/paste workflows

This format is not a protocol-level replacement for native TOS address formats such as:

- raw format: `workchain:hex_hash`
- friendly format with CRC16

It is a display and interchange format only.

## 2. Design Goals

The format is designed to satisfy the following goals:

- Preserve the complete native TOS address information.
- Use a `0x` prefix familiar to users of EVM ecosystems.
- Include a checksum signal in the rendered string.
- Be deterministic and reversible.
- Avoid ambiguity for negative workchains such as `-1`.
- Be easy to implement in SDKs across multiple languages.

## 3. Non-Goals

This format does not attempt to:

- mimic Ethereum address semantics
- reuse Ethereum's 20-byte address size
- replace native TOS address parsing rules
- carry bounceability or test-only flags from friendly addresses

If an implementation needs bounceability or test-only semantics, it should continue to use the native TOS friendly address format alongside this format.

## 4. Terminology

- `workchain`: the signed TOS workchain identifier
- `account_id`: the 32-byte account hash, derived from `StateInit` for contract addresses
- `canonical payload`: the fixed binary payload used by this format before checksum rendering
- `checksummed 0x address`: the final mixed-case hex string defined by this document

## 5. Canonical Binary Payload

The canonical binary payload is exactly 36 bytes:

- byte `0..3`: `workchain_i32_be`
- byte `4..35`: `account_id[32]`

The workchain is encoded as a signed 32-bit big-endian integer.

Examples:

- `0` -> `00 00 00 00`
- `-1` -> `ff ff ff ff`

This yields the following binary layout:

```text
+----------------------+----------------------------------+
| 4-byte workchain     | 32-byte account_id              |
+----------------------+----------------------------------+
| signed int32, BE     | raw 256-bit account hash        |
+----------------------+----------------------------------+
```

## 6. Hex Form

The lowercase hex form is:

```text
0x + hex(workchain_i32_be || account_id)
```

Because the payload is 36 bytes, the hex body is 72 hex characters long.

The full lowercase non-checksummed string is therefore always:

- prefix: `0x`
- body: 72 hex characters
- total length: 74 characters

This format never appends a separate checksum suffix after the hex body.
The checksum signal is encoded only through the letter casing of `a-f`
hex characters inside the 72-character body.

Example shape:

```text
0x00000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

## 7. Checksum Algorithm

This format uses a mixed-case checksum style inspired by EIP-55, but applied to the full 36-byte TOS payload instead of a 20-byte Ethereum address.

### 7.1 Input to the Checksum

Let:

- `payload_hex_lower` be the 72-character lowercase hex encoding of the 36-byte payload without the `0x` prefix

### 7.2 Hash Function

Compute:

```text
checksum_hash = SHA3-512( ASCII(payload_hex_lower) )
```

`SHA3-512` is used because the TOS 0x body is 72 hex characters long, and the
checksum algorithm requires at least 72 hash nibbles to drive the mixed-case
mapping across the whole body.

### 7.3 Case-Mapping Rule

For each hex character in `payload_hex_lower`:

- if the character is `0-9`, leave it unchanged
- if the character is `a-f`, inspect the corresponding nibble of `checksum_hash`
- uppercase the hex character if that nibble is `>= 8`
- otherwise keep it lowercase

The final encoded string is:

```text
0x + checksummed_hex_body
```

## 8. Canonical String Rules

The canonical string form defined by this document is:

- prefixed with lowercase `0x`
- exactly 74 characters long
- uses mixed-case checksum in the 72-character body
- does not append any trailing checksum characters

Canonical examples:

```text
0x00000000A1b2c3d4E5f6...
0xfFFFFFFf0123ABcd...
```

Non-canonical but parseable forms may include:

- all lowercase body
- all uppercase body

However:

- producers should emit the canonical checksummed form
- consumers should accept lowercase and uppercase as input
- consumers should be able to validate whether the input is correctly checksummed

## 9. Encoding Algorithm

Given a native TOS address:

1. Parse the native address into:
   - `workchain`
   - `account_id`
2. Encode `workchain` as signed 32-bit big-endian.
3. Concatenate:
   - `workchain_i32_be`
   - `account_id`
4. Hex-encode the 36-byte payload into lowercase hex.
5. Compute `SHA3-512(ASCII(payload_hex_lower))`.
6. Apply the mixed-case rule from Section 7.
7. Prefix with `0x`.

## 10. Decoding Algorithm

Given a candidate `0x` TOS address:

1. Require the string to start with `0x`.
2. Require exactly 72 hex characters after the prefix.
3. Decode the hex body into 36 bytes.
4. Split:
   - first 4 bytes -> signed big-endian `workchain`
   - next 32 bytes -> `account_id`
5. Optionally validate checksum:
   - recompute the canonical mixed-case form
   - compare to the provided string
6. Reconstruct the native raw TOS address:

```text
workchain:account_id_hex_lower
```

## 11. Validation Levels

Implementations should expose at least three validation levels:

- `syntax valid`
  - starts with `0x`
  - has 72 hex characters after the prefix
- `payload valid`
  - decodes into a 4-byte signed workchain and 32-byte account id
- `checksum valid`
  - matches the canonical mixed-case checksum rule

Recommended behavior:

- wallets and SDKs should reject strings that fail syntax or payload validation
- user interfaces may accept non-checksummed input but should normalize it immediately
- copy/export functions should always emit canonical checksummed output

## 12. Mapping to Native TOS Address Forms

This format maps directly to the native raw address:

```text
raw_tos_address = workchain:account_id_hex_lower
```

For example:

```text
0:012345...abcd
```

maps to:

```text
0x00000000012345...ABcd
```

The exact letter casing depends on the checksum result.

This format does not preserve friendly-address metadata such as:

- bounceable / non-bounceable
- test-only flag

Therefore:

- converting from friendly to `0x` loses those display-layer flags
- converting from `0x` back to friendly requires separate policy choices

## 13. Reference Pseudocode

### 13.1 Encode

```text
function encodeTos0x(workchain, account_id_32_bytes):
    wc = int32_big_endian(workchain)
    payload = wc || account_id_32_bytes
    lower = hex(payload).lower()
    h = sha3_512(ascii(lower))

    out = ""
    for i in range(len(lower)):
        ch = lower[i]
        if ch in "0123456789":
            out += ch
        else:
            nibble = hex_nibble(h, i)
            out += upper(ch) if nibble >= 8 else ch

    return "0x" + out
```

### 13.2 Decode

```text
function decodeTos0x(text):
    require text startsWith "0x"
    body = text[2:]
    require len(body) == 72
    require body is hex

    payload = hex_decode(body)
    workchain = parse_signed_i32_be(payload[0:4])
    account_id = payload[4:36]

    canonical = encodeTos0x(workchain, account_id)
    checksum_valid = (canonical == text)

    return {
        workchain,
        account_id,
        checksum_valid,
        raw_address: str(workchain) + ":" + hex(account_id).lower(),
    }
```

## 14. Worked Examples

The following examples are computed using the `SHA3-512` checksum rule
defined in this document.

### 14.1 Workchain 0

If:

- `workchain = 0`
- `account_id = 32-byte hash H`

then the payload begins with:

```text
00000000
```

and the full lowercase form is:

```text
0x00000000 + hex(H)
```

Concrete example:

```text
raw: 0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
0x : 0x000000000123456789abCDeF0123456789aBcDeF0123456789aBcdEF0123456789aBcDef
```

### 14.2 Workchain -1

If:

- `workchain = -1`

then the first 4 bytes are:

```text
ffffffff
```

so the lowercase form begins:

```text
0xffffffff...
```

The checksum step may then uppercase some letters in that body.

Concrete example:

```text
raw: -1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
0x : 0xFFffFFff0123456789ABcDEf0123456789ABcDEF0123456789abCdeF0123456789abCDEF
```

### 14.3 Additional Examples

```text
raw: 0:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
0x : 0x00000000fFffFffFFffFfffFfFfFFFffffffFfFFFFFFFffffFFfFFfFFfFFFfFfFffFFfff
```

```text
raw: 17:0000000000000000000000000000000000000000000000000000000000000001
0x : 0x000000110000000000000000000000000000000000000000000000000000000000000001
```

```text
raw: -3:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
0x : 0xFFFFFFfd1234567890aBCDeF1234567890AbCdef1234567890ABCDef1234567890aBCDEF
```

## 15. Compatibility Notes

### 15.1 Why 4 Bytes for Workchain

This document uses signed 32-bit workchain encoding because:

- the native address model treats workchain as a signed integer
- it avoids special-case encodings for negative workchains
- it is simple and language-neutral

### 15.2 Why Not `workchain:hex`

Raw TOS addresses are already available for that use case. The purpose of this format is specifically to provide:

- a `0x` presentation style
- a checksum-aware display format

### 15.3 Why Not Reuse Friendly Address CRC16

Friendly addresses already have their own structure and checksum rules. This document defines a separate format intended to be:

- hex-based
- reversible to raw form
- visually familiar to users who expect `0x`

### 15.4 Why Not Use Base58 or Bech32

Those are valid alternative display formats, but they are out of scope here. The specific goal of this document is a `0x`-prefixed format.

## 16. Security Considerations

- This checksum improves typo detection but is not a cryptographic authentication mechanism.
- Applications must still parse and compare decoded payloads, not rely on string equality alone.
- Mixed-case display should be preserved exactly in UI copy/export actions.
- User interfaces should consider highlighting checksum case changes to reduce phishing risk.

## 17. Recommendation

If this format is adopted, implementations should:

- keep native TOS raw and friendly formats fully supported
- expose explicit conversion helpers
- label this format clearly as `TOS 0x checksummed`
- avoid presenting it as an Ethereum-compatible address

## 18. Relationship to the Current Repository

The current TOS repository models an address as:

- `workchain`
- `256-bit hash`

For contract and wallet addresses, that hash is derived from `StateInit`.

Relevant implementation evidence:

- `sdk/js/packages/core/src/address/Address.ts`
- `sdk/js/packages/core/src/address/utils.ts`
- `sdk/js/packages/wallets/src/WalletV3R2.ts`
- `sdk/js/packages/wallets/src/WalletV4R2.ts`
- `sdk/js/packages/wallets/src/WalletV5R1.ts`

This document does not change those semantics. It only specifies an additional textual encoding.
