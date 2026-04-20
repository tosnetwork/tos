/*
    Uno Workchain — Bech32m address envelope codec (implementation).

    Follows BIP-350 ("Bech32m format for v1+ witness addresses") — this is
    the spec that distinguishes Bech32m from Bech32:

      * Bech32m polymod constant is 0x2bc830a3 instead of 1.
      * Everything else (alphabet, HRP-expand, 5-bit polymod update,
        separator '1', 6-symbol checksum) is identical to BIP-173.

    Specifically, the reference polymod from BIP-173 §Checksum reads:

        def bech32_polymod(values):
            GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            chk = 1
            for v in values:
                b = chk >> 25
                chk = ((chk & 0x1ffffff) << 5) ^ v
                for i in range(5):
                    if (b >> i) & 1:
                        chk ^= GEN[i]
            return chk

    and for Bech32m the `create_checksum` / `verify_checksum` functions
    replace the constant `1` with `0x2bc830a3` — that is the entire
    difference between the two encodings.

    This TU carries its own 5-bit polymod; it intentionally does NOT rely
    on the vendored avatar Bech32 (which targets TOS base addresses, not
    the Uno envelope). The avatar BLAKE3 adapter is used for the inner
    6-byte content-bound checksum tag only.
*/

#include "uno/crypto/bech32m.h"
#include "uno/crypto/internal/blake3_adapter.h"

#include <cctype>
#include <cstring>
#include <vector>

namespace uno_workchain::crypto {

namespace {

// BIP-173 / BIP-350 alphabet — index i corresponds to 5-bit value i.
constexpr char kBech32Alphabet[33] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Reverse map: ASCII → 5-bit value, or 0xFF for "not in alphabet".
// Built in code (rather than a compile-time constexpr array) so the
// source stays inspectable.
struct BechDecodeTable {
    std::uint8_t map[256];
    constexpr BechDecodeTable() : map{} {
        for (int i = 0; i < 256; ++i) map[i] = 0xFF;
        for (int i = 0; i < 32; ++i) {
            // Lowercase — canonical. Uppercase folded at the call site.
            map[static_cast<std::uint8_t>(kBech32Alphabet[i])] =
                static_cast<std::uint8_t>(i);
        }
    }
};
constexpr BechDecodeTable kBechDecode{};

// The Bech32m polymod generator constant (BIP-350 §Checksum). Classic
// Bech32 uses 1 here; BIP-350 changed it to 0x2bc830a3 to prevent
// length-extension insertion attacks that affect BIP-173.
constexpr std::uint32_t kBech32mConst = 0x2bc830a3;

// The 5 generator polynomials (BIP-173 §Checksum). Unchanged between
// Bech32 and Bech32m.
constexpr std::uint32_t kBechGen[5] = {
    0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3,
};

// 5-bit-per-entry polymod update; see BIP-173 reference code.
std::uint32_t bech32_polymod(const std::vector<std::uint8_t>& values) {
    std::uint32_t chk = 1;
    for (std::uint8_t v : values) {
        std::uint32_t b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ static_cast<std::uint32_t>(v);
        for (int i = 0; i < 5; ++i) {
            if ((b >> i) & 1) chk ^= kBechGen[i];
        }
    }
    return chk;
}

// HRP expansion for the polymod input (BIP-173 §Checksum).
// `hrp_expand(hrp) = [c >> 5 for c in hrp] + [0] + [c & 31 for c in hrp]`.
std::vector<std::uint8_t> hrp_expand(std::string_view hrp) {
    std::vector<std::uint8_t> out;
    out.reserve(hrp.size() * 2 + 1);
    for (char c : hrp) out.push_back(static_cast<std::uint8_t>(c) >> 5);
    out.push_back(0);
    for (char c : hrp) out.push_back(static_cast<std::uint8_t>(c) & 31);
    return out;
}

// Generate 6 checksum symbols for Bech32m.
std::array<std::uint8_t, 6> create_checksum_bech32m(
        std::string_view hrp,
        const std::vector<std::uint8_t>& data) {
    std::vector<std::uint8_t> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    for (int i = 0; i < 6; ++i) values.push_back(0);
    std::uint32_t mod = bech32_polymod(values) ^ kBech32mConst;
    std::array<std::uint8_t, 6> out{};
    for (int i = 0; i < 6; ++i) {
        out[i] = (mod >> (5 * (5 - i))) & 31;
    }
    return out;
}

// Verify: polymod(hrp_expand(hrp) + data) must equal kBech32mConst.
bool verify_checksum_bech32m(std::string_view hrp,
                             const std::vector<std::uint8_t>& data) {
    std::vector<std::uint8_t> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    return bech32_polymod(values) == kBech32mConst;
}

// Convert a byte stream to 5-bit groups (BIP-173 §Encoding). `pad=true`
// pads the final group with zero bits, as is customary for encoding.
bool convert_bits_8_to_5(const std::uint8_t* in, std::size_t in_len,
                        std::vector<std::uint8_t>& out, bool pad) {
    std::uint32_t acc = 0;
    int bits = 0;
    constexpr std::uint32_t maxv = 31;
    for (std::size_t i = 0; i < in_len; ++i) {
        std::uint32_t v = in[i];
        acc = (acc << 8) | v;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits > 0) out.push_back((acc << (5 - bits)) & maxv);
    } else {
        // Decode-direction check: no padding bits (BIP-173 "no non-zero
        // padding" rule). 5-bit-to-8-bit path handles this; unused here.
        if (bits >= 5) return false;
        if (((acc << (5 - bits)) & maxv) != 0) return false;
    }
    return true;
}

// Convert 5-bit groups back to bytes. Rejects non-zero padding bits.
bool convert_bits_5_to_8(const std::uint8_t* in, std::size_t in_len,
                        std::vector<std::uint8_t>& out) {
    std::uint32_t acc = 0;
    int bits = 0;
    for (std::size_t i = 0; i < in_len; ++i) {
        if (in[i] >> 5) return false;  // caller should have already screened
        acc = (acc << 5) | in[i];
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            out.push_back((acc >> bits) & 0xff);
        }
    }
    // Any trailing bits must be zero (no sloppy padding) AND be fewer than
    // 5 (otherwise we dropped a symbol).
    if (bits >= 5) return false;
    if (((acc << (8 - bits)) & 0xff) != 0) return false;
    return true;
}

// Derive the 6-byte content-bound checksum tag via BLAKE3.
std::array<std::uint8_t, 6> blake3_checksum_tag(const AddressEnvelope& env) {
    internal::Blake3Hasher h;
    static constexpr char kDomainTag[] = "uno-addr-checksum-v1";
    h.update(td::Slice(kDomainTag, sizeof(kDomainTag) - 1));
    h.update(td::Slice(reinterpret_cast<const char*>(&env.version_tag), 1));
    h.update(td::Slice(reinterpret_cast<const char*>(&env.network_tag), 1));
    h.update(td::Slice(reinterpret_cast<const char*>(env.payload.data()),
                       env.payload.size()));
    std::uint8_t full[32];
    h.finalize_32(full);
    std::array<std::uint8_t, 6> out{};
    std::memcpy(out.data(), full, 6);
    return out;
}

// Build the raw envelope byte sequence that goes into Base32 encoding.
//   version_tag (1 B) || network_tag (1 B) || payload (1259 B) || tag (6 B)
// Total = 1267 B.
std::vector<std::uint8_t> serialize_envelope_bytes(const AddressEnvelope& env) {
    std::vector<std::uint8_t> out;
    out.reserve(1 + 1 + kAddressPayloadBytes + kAddressChecksumBytes);
    out.push_back(env.version_tag);
    out.push_back(env.network_tag);
    out.insert(out.end(), env.payload.begin(), env.payload.end());
    auto tag = blake3_checksum_tag(env);
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

// HRP that MUST be paired with the given network_tag.
const char* hrp_for_network(std::uint8_t network_tag) {
    switch (network_tag) {
        case kAddressNetworkMainnet: return "uno";
        case kAddressNetworkTestnet: return "unot";
        default: return nullptr;
    }
}

// Reverse: HRP → network_tag. Returns 0xFF for unknown HRP.
std::uint8_t network_for_hrp(std::string_view hrp) {
    if (hrp == "uno")  return kAddressNetworkMainnet;
    if (hrp == "unot") return kAddressNetworkTestnet;
    return 0xFF;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::array<std::uint8_t, kAddressChecksumBytes>
derive_address_checksum_tag(const AddressEnvelope& env) {
    return blake3_checksum_tag(env);
}

std::string encode_address_envelope(const AddressEnvelope& env) {
    const char* hrp_c = hrp_for_network(env.network_tag);
    if (hrp_c == nullptr) {
        // Defensive: caller handed us a bogus network_tag. Return empty
        // string — encode is a pure function with no error channel, so the
        // contract is "caller already validated inputs". Tests exercise
        // only the two defined networks.
        return {};
    }
    std::string_view hrp{hrp_c};

    auto bytes = serialize_envelope_bytes(env);
    std::vector<std::uint8_t> data5;
    data5.reserve((bytes.size() * 8 + 4) / 5);
    convert_bits_8_to_5(bytes.data(), bytes.size(), data5, /*pad=*/true);

    auto checksum = create_checksum_bech32m(hrp, data5);

    std::string out;
    out.reserve(hrp.size() + 1 + data5.size() + 6);
    out.append(hrp.data(), hrp.size());
    out.push_back('1');
    for (std::uint8_t v : data5)    out.push_back(kBech32Alphabet[v]);
    for (std::uint8_t v : checksum) out.push_back(kBech32Alphabet[v]);
    return out;
}

EnvelopeError decode_address_envelope(std::string_view encoded,
                                      AddressEnvelope& out) {
    // --- Step 1: case check (BIP-173 §5). ---------------------------------
    bool has_lower = false, has_upper = false;
    for (char c : encoded) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        if (c >= 'A' && c <= 'Z') has_upper = true;
    }
    if (has_lower && has_upper) return EnvelopeError::kMixedCase;

    // Canonicalise to lowercase for all further processing.
    std::string lc(encoded);
    for (char& c : lc) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }

    // --- Step 2: find the last '1' — the HRP/data separator. --------------
    // Per BIP-173 the separator is the LAST '1' in the string (HRPs
    // themselves cannot contain '1' because '1' isn't in the alphabet and
    // HRPs are defined over us-ascii 33..126 excluding alphabet conflicts).
    auto sep_pos = lc.rfind('1');
    if (sep_pos == std::string::npos) return EnvelopeError::kBadCharset;
    if (sep_pos < 1)                  return EnvelopeError::kBadHrp;  // HRP empty
    if (sep_pos + 7 > lc.size())      return EnvelopeError::kBadLength;
    // (≥6 checksum chars after the '1' are mandatory.)

    std::string_view hrp(lc.data(), sep_pos);
    std::string_view body(lc.data() + sep_pos + 1, lc.size() - sep_pos - 1);

    // --- Step 3: HRP must be a known Uno HRP. -----------------------------
    std::uint8_t network = network_for_hrp(hrp);
    if (network == 0xFF) return EnvelopeError::kBadHrp;

    // --- Step 4: decode each data character. ------------------------------
    std::vector<std::uint8_t> data5;
    data5.reserve(body.size());
    for (char c : body) {
        std::uint8_t v = kBechDecode.map[static_cast<std::uint8_t>(c)];
        if (v == 0xFF) return EnvelopeError::kBadCharset;
        data5.push_back(v);
    }

    // --- Step 5: verify polymod. ------------------------------------------
    if (!verify_checksum_bech32m(hrp, data5)) return EnvelopeError::kBadChecksum;

    // --- Step 6: strip checksum, unpack 5→8. ------------------------------
    if (data5.size() < 6) return EnvelopeError::kBadLength;
    std::vector<std::uint8_t> payload5(data5.begin(),
                                       data5.end() - 6);
    std::vector<std::uint8_t> raw;
    // Expected: 1 + 1 + 1259 + 6 = 1267 bytes; (1267 * 8 + 4) / 5 = 2028 groups.
    raw.reserve(1267);
    if (!convert_bits_5_to_8(payload5.data(), payload5.size(), raw)) {
        return EnvelopeError::kBadCharset;  // sloppy padding = corrupted input
    }
    constexpr std::size_t kExpectedRaw =
        2 + kAddressPayloadBytes + kAddressChecksumBytes;
    if (raw.size() != kExpectedRaw) return EnvelopeError::kBadLength;

    // --- Step 7: unmarshal into AddressEnvelope and verify inner tag. -----
    AddressEnvelope candidate{};
    candidate.version_tag = raw[0];
    candidate.network_tag = raw[1];
    std::memcpy(candidate.payload.data(), raw.data() + 2, kAddressPayloadBytes);

    // HRP / network_tag cross-check: the inner network_tag MUST agree with
    // the HRP we read. Treat a mismatch as kBadHrp — wallets configured for
    // mainnet must reject an envelope that claims to be testnet, even if
    // the Bech32m checksum verifies (e.g. deliberate spoofing).
    if (candidate.network_tag != network) return EnvelopeError::kBadHrp;

    std::array<std::uint8_t, kAddressChecksumBytes> got_tag{};
    std::memcpy(got_tag.data(),
                raw.data() + 2 + kAddressPayloadBytes,
                kAddressChecksumBytes);
    auto want_tag = blake3_checksum_tag(candidate);
    if (got_tag != want_tag) return EnvelopeError::kBadChecksum;

    // --- Step 8: version_tag must be known to this implementation. --------
    if (candidate.version_tag != kAddressEnvelopeVersionV1) {
        return EnvelopeError::kBadVersion;
    }

    out = candidate;
    return EnvelopeError::kOk;
}

}  // namespace uno_workchain::crypto
