/*
    Uno Workchain — Bech32m address envelope codec (K-bech32m).

    Source: TOS-specific adapter; see doc/uno-workchain.md §2.6 (Address
    envelope — protocol-level MUST).

    The Uno address envelope carries `(version_tag, network_tag, payload)`
    plus a 6-byte BLAKE3 checksum bound to the avatar BLAKE3 adapter.
    Inside the envelope:

        version_tag : u8           // 0x01 for v1
        network_tag : u8           // 0x00 testnet, 0x01 mainnet
        payload     : bytes[1259]  // (d, compress(pk_d), ivk_commitment, pk_mlkem)
        checksum    : bytes[6]     // BLAKE3("uno-addr-checksum-v1" ||
                                   //        version_tag || network_tag || payload)[0..6]

    The envelope is then wrapped in a Bech32m string:

        HRP "1" Base32(version_tag || network_tag || payload || checksum)

    where HRP is "uno" for mainnet and "unot" for testnet (§2.6).

    Base32 encoding is Bech32m (BIP-350) — identical alphabet and layout to
    BIP-173 Bech32, but with the final constant `0x2bc830a3` instead of `1`
    for the polymod. That constant difference is the only wire-level
    distinction between Bech32 and Bech32m.

    Wallets and RPC endpoints MUST reject any envelope whose:
      - checksum does not verify
      - HRP does not match the configured network (mainnet vs testnet)
      - version_tag is unknown to the current implementation
      - length (1259 B payload) is wrong
      - characters are outside the alphabet
      - case is mixed (per BIP-173 §5)

    This header is intentionally self-contained: no avatar-specific types in
    the public API. The only cross-module dependency is the avatar BLAKE3
    adapter (`uno/crypto/internal/blake3_adapter.h`) used to derive the
    6-byte checksum.
*/
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace uno_workchain::crypto {

/// Uno address-envelope plaintext (1259 B per §2.6).
///
/// `payload` concatenates the raw address bytes in this order:
///   11 B diversifier `d`
///   32 B compressed Ristretto255 `pk_d`
///   32 B `ivk_commitment` = Poseidon2("uno-ivk-cm-v1", ivk, d)
///   1184 B ML-KEM-768 `pk_mlkem`
struct AddressEnvelope {
    std::uint8_t                     version_tag{0x01};   // v1
    std::uint8_t                     network_tag{0x00};   // 0x00 testnet, 0x01 mainnet
    std::array<std::uint8_t, 1259>   payload{};
};

/// Sentinel constants. Declared in the header so callers can reference the
/// spec-pinned values without including the implementation.
constexpr std::uint8_t kAddressEnvelopeVersionV1 = 0x01;
constexpr std::uint8_t kAddressNetworkTestnet    = 0x00;
constexpr std::uint8_t kAddressNetworkMainnet    = 0x01;
constexpr std::size_t  kAddressPayloadBytes      = 1259;
constexpr std::size_t  kAddressChecksumBytes     = 6;

/// Decoder / validation errors. Granular so the caller can surface a
/// specific reason (§2.6 enumerates the reject classes).
enum class EnvelopeError {
    kOk           = 0,
    kBadHrp       = 1,   // HRP not in {"uno", "unot"}, or HRP/network mismatch
    kBadChecksum  = 2,   // Bech32m polymod != 0x2bc830a3, OR 6-byte BLAKE3 tag mismatch
    kBadVersion   = 3,   // version_tag not in {0x01}
    kBadLength    = 4,   // data body length wrong after 8→5 bit unpack
    kBadCharset   = 5,   // character outside the Bech32 alphabet, or missing '1'
    kMixedCase    = 6,   // BIP-173 §5: input MUST be all-lower or all-upper
};

/// Encode an AddressEnvelope to the canonical Bech32m string.
///
/// Always lowercase. The returned string begins with "uno1" (mainnet) or
/// "unot1" (testnet) and is exactly kEncodedLength characters long:
///
///   len(HRP) + 1 separator + ceil((1 + 1 + 1259) * 8 / 5) data chars + 6 checksum
///     = 3 or 4 + 1 + 2018 + 6
///     = 2028 (mainnet) or 2029 (testnet) chars
std::string encode_address_envelope(const AddressEnvelope& env);

/// Decode and validate. On kOk, `out` is fully populated. On any other
/// return, `out` is left in an unspecified (but well-defined: trivially
/// copyable / zero-initialised) state.
///
/// Validation order (short-circuit):
///   1. kMixedCase    — any mix of upper- and lower-case letters
///   2. kBadHrp       — HRP not exactly "uno" or "unot" (case-normalised)
///   3. kBadCharset   — separator '1' not found, or data char outside alphabet
///   4. kBadLength    — data section not exactly the right encoded length
///   5. kBadChecksum  — Bech32m polymod check, OR tag-bound BLAKE3 mismatch
///   6. kBadVersion   — version_tag not 0x01
EnvelopeError decode_address_envelope(std::string_view encoded,
                                      AddressEnvelope& out);

/// Convenience: derive the expected 6-byte BLAKE3 checksum tag over
/// (version_tag || network_tag || payload). Exposed for test vectors and
/// for the genesis loader's cross-check path.
std::array<std::uint8_t, kAddressChecksumBytes>
derive_address_checksum_tag(const AddressEnvelope& env);

}  // namespace uno_workchain::crypto
