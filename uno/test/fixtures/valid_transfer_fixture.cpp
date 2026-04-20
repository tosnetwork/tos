/*
    uno/test/fixtures/valid_transfer_fixture.cpp

    Implementation of the shared valid-Transfer builder described in the
    companion header. Byte-for-byte equivalent to the pre-refactor inline
    build_transfer() / make_wallet() helpers in test-uno-end-to-end.cpp.
*/
#include "uno/test/fixtures/valid_transfer_fixture.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "td/utils/Slice.h"
#include "td/utils/crypto.h"

#include "uno/crypto/stealth-address.h"
#include "vm/cells/CellBuilder.h"

namespace uno_workchain::test_fixtures {

namespace uw = ::uno_workchain;
namespace uc = ::uno_workchain::crypto;

// ---------------------------------------------------------------------------
// make_wallet
// ---------------------------------------------------------------------------
DemoWallet make_wallet(const char* name, uint8_t seed_byte) {
    DemoWallet w;
    w.name = name;
    for (int i = 0; i < 32; ++i) w.seed_bytes[i] = seed_byte;

    // ask: reduce_64 of a derived 64-byte stream; lands in [0, L).
    {
        std::array<uint8_t, 64> buf{};
        buf[0] = seed_byte;
        buf[1] = 0xA5;
        w.ask = uc::RistrettoScalar::reduce_64_bytes(
            td::Slice(reinterpret_cast<const char*>(buf.data()), 64));
    }
    // ak = ask * G (real group element)
    {
        auto r = uc::ristretto_basepoint_mul(w.ask);
        if (r.is_error()) {
            std::fprintf(stderr, "valid_transfer_fixture: ak gen: %s\n",
                         r.error().message().c_str());
            std::exit(1);
        }
        w.ak = r.move_as_ok();
    }
    // nk, ivk: sha256-derived stand-ins (Poseidon2 is stubbed at this gate).
    {
        uint8_t src[33];
        std::memcpy(src, w.seed_bytes.data(), 32);
        src[32] = 'N';
        td::sha256(td::Slice(reinterpret_cast<const char*>(src), 33),
                   td::MutableSlice(reinterpret_cast<char*>(w.nk.data()), 32));
        src[32] = 'I';
        td::sha256(td::Slice(reinterpret_cast<const char*>(src), 33),
                   td::MutableSlice(reinterpret_cast<char*>(w.ivk.data()), 32));
    }
    // ovk: 32 deterministic bytes so the audit path (end-to-end test) can
    // recover its own memo.
    {
        w.ovk = td::SecureString(32);
        for (int i = 0; i < 32; ++i) {
            ((uint8_t*)w.ovk.data())[i] = static_cast<uint8_t>(seed_byte + 0x40 + i);
        }
    }
    // diversifier
    for (int i = 0; i < 11; ++i) {
        w.diversifier[i] = static_cast<uint8_t>(seed_byte + i);
    }
    // pk_d: valid Ristretto point via hash-to-curve on the diversifier.
    w.pk_d = uc::derive_diversified_base_point(
        td::Slice(reinterpret_cast<const char*>(w.diversifier.data()), 11));

    // ivk_commitment: sha256(ivk || d).
    {
        uint8_t src[43];
        std::memcpy(src, w.ivk.data(), 32);
        std::memcpy(src + 32, w.diversifier.data(), 11);
        td::sha256(td::Slice(reinterpret_cast<const char*>(src), 43),
                   td::MutableSlice(reinterpret_cast<char*>(w.ivk_commitment.data()), 32));
    }
    return w;
}

// ---------------------------------------------------------------------------
// Helper re-exports
// ---------------------------------------------------------------------------
td::Bits256 make_note_cm(const DemoWallet& rec, uint64_t value,
                         const std::array<uint8_t, 32>& rcm) {
    uint8_t buf[11 + 32 + 32 + 8 + 32];
    std::memcpy(buf +   0, rec.diversifier.data(), 11);
    std::memcpy(buf +  11, rec.pk_d.bytes.data(), 32);
    std::memcpy(buf +  43, rec.ivk_commitment.data(), 32);
    for (int i = 0; i < 8; ++i) {
        buf[75 + i] = static_cast<uint8_t>((value >> (8 * i)) & 0xff);
    }
    std::memcpy(buf + 83, rcm.data(), 32);
    td::Bits256 cm;
    td::sha256(td::Slice(reinterpret_cast<const char*>(buf), sizeof(buf)),
               td::MutableSlice(reinterpret_cast<char*>(cm.data()), 32));
    return cm;
}

std::array<uint8_t, 32> test_digest(const void* p, std::size_t n) {
    std::array<uint8_t, 32> out{};
    td::sha256(td::Slice(reinterpret_cast<const char*>(p), n),
               td::MutableSlice(reinterpret_cast<char*>(out.data()), 32));
    return out;
}

td::Bits256 point_to_bits256(const uc::RistrettoPoint& p) {
    td::Bits256 b;
    std::memcpy(b.data(), p.bytes.data(), 32);
    return b;
}

// ---------------------------------------------------------------------------
// make_valid_transfer
// ---------------------------------------------------------------------------
ValidTransferFixture make_valid_transfer(const ValidTransferParams& p) {
    assert(p.sender   != nullptr && "sender wallet required");
    assert(p.receiver != nullptr && "receiver wallet required");
    assert(!p.outputs.empty()    && "at least one output required");

    if (p.enforce_balance) {
        uint64_t sum = p.fee_nano;
        for (const auto& o : p.outputs) sum += o.value;
        (void)sum;
        assert(sum == p.spend_value &&
               "balance mismatch: Σ outputs + fee ≠ spend_value "
               "(disable enforce_balance for inflation tests)");
    }

    ValidTransferFixture fx;
    uw::Transfer& tx = fx.tx;

    tx.version      = uw::kTransferVersion;
    tx.scheme_id    = uw::kSchemeIdV1;
    tx.chain_id     = p.chain_id;
    tx.anchor       = p.anchor;
    tx.expiry_block = p.expiry_block;
    tx.fee          = p.fee_nano;

    // --- Spend 0 -----------------------------------------------------------
    uw::SpendDescription spend;

    // nullifier (deterministic unless caller overrides).
    if (p.override_nullifier) {
        std::memcpy(spend.nullifier.data(), p.nullifier_bytes.data(), 32);
    } else {
        uint8_t seed[64] = {0};
        std::memcpy(seed, p.sender->nk.data(), 32);
        seed[32] = 0xA1;  // spend_index discriminator
        auto nf = test_digest(seed, 64);
        std::memcpy(spend.nullifier.data(), nf.data(), 32);
    }

    // rk = ak + α·G. α = reduce_64_bytes(H(...)).
    {
        std::array<uint8_t, 64> alpha_seed{};
        alpha_seed[0] = 0xAF;
        auto alpha = uc::RistrettoScalar::reduce_64_bytes(
            td::Slice(reinterpret_cast<const char*>(alpha_seed.data()), 64));
        auto rpair_r =
            uc::randomize_spend_auth(p.sender->ask, p.sender->ak, alpha);
        if (rpair_r.is_error()) {
            std::fprintf(stderr, "valid_transfer_fixture: "
                         "randomize_spend_auth: %s\n",
                         rpair_r.error().message().c_str());
            std::exit(1);
        }
        auto rpair = rpair_r.move_as_ok();
        spend.rk      = point_to_bits256(rpair.rk);
        fx.rsk        = std::move(rpair.rsk);
        fx.rk         = rpair.rk;
        // spend_auth_sig filled after canonical_tx_hash.
        spend.spend_auth_sig.fill(0);
    }
    tx.spends.push_back(std::move(spend));

    // --- Outputs -----------------------------------------------------------
    for (std::size_t oi = 0; oi < p.outputs.size(); ++oi) {
        const auto& os = p.outputs[oi];
        const DemoWallet* rec = (oi == 0) ? p.receiver : p.sender;

        uw::OutputDescription out;
        // rcm: per-output distinct placeholder.
        std::array<uint8_t, 32> rcm{};
        rcm[0] = static_cast<uint8_t>(0x10 * (oi + 1));
        out.cm = make_note_cm(*rec, os.value, rcm);

        // epk: a valid Ristretto point derived from the recipient's diversifier.
        out.epk = point_to_bits256(
            uc::derive_diversified_base_point(
                td::Slice(reinterpret_cast<const char*>(rec->diversifier.data()),
                          11)));

        // filter_tag: low 16 bits of sha256(ivk || cm). Wallet scan replicates.
        uint8_t fb[64] = {0};
        std::memcpy(fb,      rec->ivk.data(), 32);
        std::memcpy(fb + 32, out.cm.data(),   32);
        auto h = test_digest(fb, 64);
        out.filter_tag = static_cast<uint16_t>(
            static_cast<uint16_t>(h[0]) |
            (static_cast<uint16_t>(h[1]) << 8));

        // Opaque placeholder refs (not decoded by the consensus verify path).
        vm::CellBuilder ec;
        ec.store_long(static_cast<long long>((oi == 0) ? 0xDEADBEEFULL
                                                        : 0xCAFEBABEULL), 32);
        out.enc_ciphertext = ec.finalize();
        vm::CellBuilder mc;
        mc.store_long(static_cast<long long>((oi == 0) ? 0x12345678ULL
                                                        : 0x87654321ULL), 32);
        out.mlkem_ct = mc.finalize();

        // out_ciphertext: caller-supplied (defaults to zeros; the end-to-end
        // audit test fills in an ovk-AEAD-wrapped memo here).
        out.out_ciphertext = os.out_ciphertext;

        tx.outputs.push_back(std::move(out));
    }

    // --- zk_proof: non-empty placeholder (accepted by decoder) -------------
    // Using store_bytes_as_chunk_chain keeps the proof cell shape identical
    // to what the mandatory-negatives skeleton used historically; test
    // binaries' weak `uno_plonky3_verify` stub rejects regardless of content.
    {
        uint8_t proof_payload[32] = {0};
        proof_payload[0] = 'P';  // "PBPP" marker, same as the original test.
        proof_payload[1] = 'B';
        proof_payload[2] = 'P';
        proof_payload[3] = 'P';
        tx.zk_proof = uw::store_bytes_as_chunk_chain(
            td::Slice(reinterpret_cast<const char*>(proof_payload), 32));
    }

    tx.wire_size_bytes = uw::kTransferHeaderBytes
                       + uw::kSpendInlineBytes  * tx.spends.size()
                       + uw::kOutputInlineBytes * tx.outputs.size();

    // Canonical tx_hash (§4.1) — excludes spend_auth_sig + ^zk_proof.
    tx.tx_hash = uw::canonical_tx_hash(tx);

    // Sign over tx_hash.
    {
        auto sig_r = uc::schnorr_sign(
            fx.rsk, fx.rk,
            td::Slice(reinterpret_cast<const char*>(tx.tx_hash.data()), 32));
        if (sig_r.is_error()) {
            std::fprintf(stderr, "valid_transfer_fixture: schnorr_sign: %s\n",
                         sig_r.error().message().c_str());
            std::exit(1);
        }
        auto sig = sig_r.move_as_ok();
        std::memcpy(tx.spends[0].spend_auth_sig.data(), sig.data(), 64);
    }

    return fx;
}

void resign_spend0(ValidTransferFixture& fx) {
    fx.tx.tx_hash = uw::canonical_tx_hash(fx.tx);
    auto sig_r = uc::schnorr_sign(
        fx.rsk, fx.rk,
        td::Slice(reinterpret_cast<const char*>(fx.tx.tx_hash.data()), 32));
    if (sig_r.is_error()) {
        std::fprintf(stderr, "valid_transfer_fixture: resign_spend0: %s\n",
                     sig_r.error().message().c_str());
        std::exit(1);
    }
    auto sig = sig_r.move_as_ok();
    std::memcpy(fx.tx.spends[0].spend_auth_sig.data(), sig.data(), 64);
}

}  // namespace uno_workchain::test_fixtures
