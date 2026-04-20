/*
    Uno Workchain — per-block compact filter implementation (§2.8, §9.1).
    Source: TOS-specific (not copied from upstream).
*/
#include "uno/core/block-filter.h"

#include <algorithm>

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Varint helpers (LEB128-style, matching BIP-158 and the rest of the TOS RPC
// surface for self-describing blobs).
// ---------------------------------------------------------------------------

namespace {

void varint_encode(std::uint64_t v, std::vector<std::uint8_t>& out) {
    while (v >= 0x80) {
        out.push_back(static_cast<std::uint8_t>(v | 0x80));
        v >>= 7;
    }
    out.push_back(static_cast<std::uint8_t>(v));
}

bool varint_decode(const std::uint8_t*& p, const std::uint8_t* end, std::uint64_t& out) {
    out = 0;
    std::uint32_t shift = 0;
    while (p < end) {
        std::uint8_t b = *p++;
        out |= std::uint64_t{static_cast<std::uint8_t>(b & 0x7f)} << shift;
        if ((b & 0x80) == 0) return true;
        shift += 7;
        if (shift >= 64) return false;  // overflow
    }
    return false;
}

// ---------------------------------------------------------------------------
// Bit writer / reader. MSB-first, BIP-158-compatible.
// ---------------------------------------------------------------------------

class BitWriter {
  public:
    explicit BitWriter(std::vector<std::uint8_t>& out) : out_(out) {}

    void write_bits(std::uint64_t value, std::uint32_t bits) {
        for (std::int32_t i = static_cast<std::int32_t>(bits) - 1; i >= 0; --i) {
            write_bit((value >> i) & 1);
        }
    }

    void write_unary(std::uint64_t q) {
        // q 1-bits followed by one 0-bit.
        for (std::uint64_t i = 0; i < q; ++i) write_bit(1);
        write_bit(0);
    }

    void finish() {
        if (bit_pos_ != 0) {
            // write_bit accumulates bits into the LOW positions of
            // cur_byte_ (`cur_byte_ = (cur_byte_ << 1) | bit`), so after
            // N < 8 writes the bits live in positions [0 .. N-1] counting
            // from the LSB. BitReader reads MSB-first (`(byte >> (7 - i)) & 1`),
            // so an unshifted partial-byte push reads back as zeros followed
            // by wrong bits. Shift the accumulated bits into the MSB
            // position before pushing so the reader sees them in order.
            cur_byte_ = static_cast<std::uint8_t>(cur_byte_ << (8 - bit_pos_));
            out_.push_back(cur_byte_);
            cur_byte_ = 0;
            bit_pos_ = 0;
        }
    }

  private:
    void write_bit(std::uint8_t bit) {
        cur_byte_ = static_cast<std::uint8_t>((cur_byte_ << 1) | (bit & 1));
        bit_pos_ += 1;
        if (bit_pos_ == 8) {
            out_.push_back(cur_byte_);
            cur_byte_ = 0;
            bit_pos_ = 0;
        }
    }

    std::vector<std::uint8_t>& out_;
    std::uint8_t cur_byte_{0};
    std::uint32_t bit_pos_{0};
};

class BitReader {
  public:
    BitReader(const std::uint8_t* data, std::size_t len) : data_(data), len_(len) {}

    bool read_bits(std::uint32_t bits, std::uint64_t& out) {
        out = 0;
        for (std::uint32_t i = 0; i < bits; ++i) {
            std::uint8_t b;
            if (!read_bit(b)) return false;
            out = (out << 1) | b;
        }
        return true;
    }

    bool read_unary(std::uint64_t& q) {
        q = 0;
        for (;;) {
            std::uint8_t b;
            if (!read_bit(b)) return false;
            if (b == 0) return true;
            q += 1;
            if (q > (std::uint64_t{1} << 40)) return false;  // sanity stop
        }
    }

    bool eof() const noexcept {
        return byte_pos_ >= len_ && bit_pos_ == 0;
    }

  private:
    bool read_bit(std::uint8_t& out) {
        if (byte_pos_ >= len_) return false;
        out = static_cast<std::uint8_t>((data_[byte_pos_] >> (7 - bit_pos_)) & 1);
        bit_pos_ += 1;
        if (bit_pos_ == 8) {
            bit_pos_ = 0;
            byte_pos_ += 1;
        }
        return true;
    }

    const std::uint8_t* data_;
    std::size_t len_;
    std::size_t byte_pos_{0};
    std::uint32_t bit_pos_{0};
};

}  // namespace

// ---------------------------------------------------------------------------
// Tag-to-range reduction.
//
// v1 choice: we map the 16-bit tag into [0, kGcsM) via a mixing multiplier,
// then take the high bits. Not a keyed hash — the filter is not
// consensus-critical and the tag is already the output of a cryptographic
// hash (Poseidon2 of k_aead, §2.8). We only need this mapping to be
// deterministic and to spread 16-bit inputs across the 19-bit range.
//
// TODO: swap for a keyed SipHash if the wallet SDK prefers BIP-158 parity.
// Any change must be coordinated with the wallet-side matcher bit-for-bit.
// ---------------------------------------------------------------------------

std::uint64_t gcs_hash_tag(std::uint16_t tag) noexcept {
    // Splitmix64 step. Deterministic, well-mixed for 16-bit inputs.
    std::uint64_t z = static_cast<std::uint64_t>(tag) * 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31);
    // Reduce into [0, kGcsM).
    return z & (kGcsM - 1);
}

// ---------------------------------------------------------------------------
// BlockFilterBuilder
// ---------------------------------------------------------------------------

BlockFilterBuilder::BlockFilterBuilder() = default;

void BlockFilterBuilder::add(std::uint16_t tag) {
    tags_.push_back(tag);
}

std::vector<std::uint8_t> BlockFilterBuilder::compile() const {
    // Hash each tag into [0, M), sort, dedup.
    std::vector<std::uint64_t> hashed;
    hashed.reserve(tags_.size());
    for (auto t : tags_) hashed.push_back(gcs_hash_tag(t));
    std::sort(hashed.begin(), hashed.end());
    hashed.erase(std::unique(hashed.begin(), hashed.end()), hashed.end());

    std::vector<std::uint8_t> out;
    varint_encode(hashed.size(), out);

    BitWriter bw(out);
    std::uint64_t prev = 0;
    for (auto h : hashed) {
        std::uint64_t delta = h - prev;
        prev = h;
        // Golomb-Rice: quotient unary, remainder in P bits.
        std::uint64_t q = delta >> kGcsP;
        std::uint64_t r = delta & ((std::uint64_t{1} << kGcsP) - 1);
        bw.write_unary(q);
        bw.write_bits(r, kGcsP);
    }
    bw.finish();
    return out;
}

bool BlockFilterBuilder::match(const std::vector<std::uint8_t>& compiled_blob, std::uint16_t tag) {
    if (compiled_blob.empty()) return false;

    const std::uint8_t* p = compiled_blob.data();
    const std::uint8_t* end = p + compiled_blob.size();

    std::uint64_t n = 0;
    if (!varint_decode(p, end, n)) return false;
    if (n == 0) return false;

    std::uint64_t target = gcs_hash_tag(tag);

    BitReader br(p, static_cast<std::size_t>(end - p));
    std::uint64_t running = 0;
    for (std::uint64_t i = 0; i < n; ++i) {
        std::uint64_t q = 0;
        if (!br.read_unary(q)) return false;
        std::uint64_t r = 0;
        if (!br.read_bits(kGcsP, r)) return false;
        std::uint64_t delta = (q << kGcsP) | r;
        running += delta;
        if (running == target) return true;
        if (running > target) return false;  // sorted — no later match possible
    }
    return false;
}

}  // namespace uno_workchain
