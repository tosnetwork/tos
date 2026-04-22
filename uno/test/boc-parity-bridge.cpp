/*
    Uno Workchain — V1-3c-beta cross-language BoC byte-parity bridge.

    This binary is the C++ half of a cross-language byte-parity harness.
    A Rust integration test (`tosctl/uno/tests/boc_parity.rs`) encodes a
    `Transfer` via `tosctl_uno::boc_encode::encode_transfer_boc`, pipes
    the resulting BoC bytes through this binary's stdin, reads a stable
    line-based dump of the decoded `Transfer` from stdout, and asserts
    every field matches the original.

    Pipeline:
        stdin  ──raw BoC bytes──▶  decode_transfer_bytes
                                     │
                                     ▼
        stdout ◀──text dump──  Transfer { ... }

    Output protocol (line-based, stable for parsing by the Rust test):

        BOC_PARITY_V1
        version <u8>
        scheme_id <u8>
        chain_id <u32>
        anchor <hex-64>
        expiry_block <u64>
        fee <u64>
        spend_count <u8>
        output_count <u8>
        tx_hash <hex-64>
        spend <i> nullifier <hex-64> rk <hex-64> sig <hex-128>
        ...
        output <j> cm <hex-64> epk <hex-64> filter_tag <u16> out_ct <hex-160> \
            enc_ct_blake3 <hex-64> mlkem_ct_blake3 <hex-64>
        ...
        zk_proof_blake3 <hex-64>

    Large variable-length fields (enc_ciphertext, mlkem_ct, zk_proof) are
    reduced to their BLAKE3(bytes) digest so stdout stays bounded; the
    digest still cryptographically binds content.

    On decode error: writes "decode_failed: <reason>" to stderr, exit 1.
    On success: dumps the decoded Transfer to stdout, exit 0.

    NOT registered as a ctest test — this is a helper binary driven only
    by the Rust cross-process integration test.
*/
#include "uno/core/transaction.h"
#include "uno/crypto/internal/blake3_adapter.h"

#include "td/utils/Slice.h"
#include "vm/cells/Cell.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

namespace {

// --- Hex formatting ---------------------------------------------------------

static const char kHexDigits[] = "0123456789abcdef";

std::string to_hex(const uint8_t* data, size_t len) {
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[2 * i + 0] = kHexDigits[(data[i] >> 4) & 0xF];
        out[2 * i + 1] = kHexDigits[data[i] & 0xF];
    }
    return out;
}

std::string to_hex_bits256(const td::Bits256& v) {
    return to_hex(reinterpret_cast<const uint8_t*>(v.data()), 32);
}

// --- BLAKE3 wrapper ---------------------------------------------------------

std::string blake3_hex(const std::string& bytes) {
    uint8_t digest[32] = {0};
    ::uno_workchain::crypto::internal::blake3_hash(
        td::Slice(bytes.data(), bytes.size()), digest);
    return to_hex(digest, 32);
}

// --- Read all of stdin into a byte buffer ----------------------------------

std::vector<uint8_t> read_all_stdin() {
    std::vector<uint8_t> buf;
    constexpr size_t kChunk = 64 * 1024;
    buf.reserve(kChunk);
    uint8_t tmp[kChunk];
    while (true) {
        size_t n = std::fread(tmp, 1, kChunk, stdin);
        if (n == 0) break;
        buf.insert(buf.end(), tmp, tmp + n);
        if (n < kChunk) {
            if (std::feof(stdin)) break;
            if (std::ferror(stdin)) break;
        }
    }
    return buf;
}

[[noreturn]] void fail(const std::string& reason) {
    std::fprintf(stderr, "decode_failed: %s\n", reason.c_str());
    std::fflush(stderr);
    std::exit(1);
}

}  // namespace

int main() {
    auto raw = read_all_stdin();
    if (raw.empty()) {
        fail("empty stdin (no BoC bytes)");
    }

    auto result = ::uno_workchain::decode_transfer_bytes(
        td::Slice(reinterpret_cast<const char*>(raw.data()), raw.size()));

    if (auto* e = std::get_if<::uno_workchain::TransferDecodeError>(&result)) {
        fail(e->reason);
    }
    const auto& tx = std::get<::uno_workchain::Transfer>(result);

    // Header
    std::cout << "BOC_PARITY_V1\n";
    std::cout << "version " << static_cast<unsigned>(tx.version) << "\n";
    std::cout << "scheme_id " << static_cast<unsigned>(tx.scheme_id) << "\n";
    std::cout << "chain_id " << tx.chain_id << "\n";
    std::cout << "anchor " << to_hex_bits256(tx.anchor) << "\n";
    std::cout << "expiry_block " << tx.expiry_block << "\n";
    std::cout << "fee " << tx.fee << "\n";
    std::cout << "spend_count " << tx.spends.size() << "\n";
    std::cout << "output_count " << tx.outputs.size() << "\n";
    std::cout << "tx_hash " << to_hex_bits256(tx.tx_hash) << "\n";

    // Spends
    for (size_t i = 0; i < tx.spends.size(); ++i) {
        const auto& s = tx.spends[i];
        std::cout << "spend " << i
                  << " nullifier " << to_hex_bits256(s.nullifier)
                  << " rk " << to_hex_bits256(s.rk)
                  << " sig " << to_hex(s.spend_auth_sig.data(), 64)
                  << "\n";
    }

    // Outputs. enc_ciphertext / mlkem_ct arrive as cell refs — walk the
    // chunk chain to recover the original byte stream, then BLAKE3 it.
    for (size_t j = 0; j < tx.outputs.size(); ++j) {
        const auto& o = tx.outputs[j];
        std::string enc_bytes =
            ::uno_workchain::load_bytes_from_chunk_chain(o.enc_ciphertext);
        std::string mlkem_bytes =
            ::uno_workchain::load_bytes_from_chunk_chain(o.mlkem_ct);
        if (enc_bytes.empty() && !o.enc_ciphertext.is_null()) {
            // load_bytes_from_chunk_chain returns {} on oversize / cycle /
            // malformed chain — treat as a decode error.
            fail("output.enc_ciphertext: malformed chunk chain");
        }
        if (mlkem_bytes.empty() && !o.mlkem_ct.is_null()) {
            fail("output.mlkem_ct: malformed chunk chain");
        }
        std::cout << "output " << j
                  << " cm " << to_hex_bits256(o.cm)
                  << " epk " << to_hex_bits256(o.epk)
                  << " filter_tag " << o.filter_tag
                  << " out_ct " << to_hex(o.out_ciphertext.data(),
                                          ::uno_workchain::kOutCiphertextBytes)
                  << " enc_ct_blake3 " << blake3_hex(enc_bytes)
                  << " mlkem_ct_blake3 " << blake3_hex(mlkem_bytes)
                  << "\n";
    }

    // zk_proof (also a chunk chain)
    std::string zk_bytes =
        ::uno_workchain::load_bytes_from_chunk_chain(tx.zk_proof);
    if (zk_bytes.empty() && !tx.zk_proof.is_null()) {
        fail("zk_proof: malformed chunk chain");
    }
    std::cout << "zk_proof_blake3 " << blake3_hex(zk_bytes) << "\n";

    std::cout.flush();
    return 0;
}
