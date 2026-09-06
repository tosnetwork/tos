#include "uno_crypto.h"
#include <array>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string_view>
#include <vector>
#ifdef UNO_TEST_HOST_ADAPTER
#include "uno/core/crypto-verifier.h"
#include "uno/core/private-transfer-state.h"
#include "vm/boc.h"
#endif

#ifdef UNO_TEST_HOST_ADAPTER
td::Result<bool> transfer_state_fixture(const uno_workchain::CryptoBundle& bundle,
                                      const std::array<td::uint8, 32>& digest,
                                      const uno_workchain::Amount& fee, bool output_only) {
  using namespace uno_workchain;
  // The test driver supplies the verified public funding fixture first, then
  // its real spend. This is a test bootstrap, never a runtime mint interface.
  static std::optional<NoteState> funding;
  if (output_only) {
    TRY_RESULT(empty, NoteTreeState::empty());
    std::vector<NoteTreeState::Commitment> outputs;
    std::vector<td::Bits256> keys;
    for (const auto& action : bundle.actions) {
      NoteTreeState::Commitment cmx;
      std::copy(std::begin(action.cmx), std::end(action.cmx), cmx.begin());
      outputs.push_back(cmx);
      td::Bits256 nf;
      std::copy(std::begin(action.nullifier), std::end(action.nullifier), nf.as_slice().ubegin());
      keys.push_back(nf);
    }
    TRY_RESULT(tree, empty.append(outputs, 0, 2));
    TRY_RESULT(nullifiers, NullifierState{}.with_used(keys));
    TRY_RESULT(anchors, AnchorWindow::genesis(3, 3, tree.root()));
    TRY_RESULT(notes, NoteState::assemble(std::move(tree), std::move(nullifiers), std::move(anchors)));
    funding = std::move(notes);
    TRY_RESULT(not_transfer, CryptoVerifiedTransfer::verify(bundle, fee, digest, {2, 7264}));
    return !not_transfer.has_value();
  }
  if (!funding) return false;
  auto caller_bundle = bundle;
  TRY_RESULT(verified, CryptoVerifiedTransfer::verify(caller_bundle, fee, digest, {2, 7264}));
  if (!verified) return false;
  caller_bundle.actions[0].cmx[0] ^= 1;
  if (verified->bundle().actions[0].cmx[0] != bundle.actions[0].cmx[0]) return false;
  auto wrong_digest = digest;
  wrong_digest[0] ^= 1;
  TRY_RESULT(wrong_signature, CryptoVerifiedTransfer::verify(bundle, fee, wrong_digest, {2, 7264}));
  if (wrong_signature) { std::cerr << "wrong digest produced a verified transfer\n"; return false; }
  auto broken = bundle;
  broken.proof[0] ^= 1;
  TRY_RESULT(wrong_proof, CryptoVerifiedTransfer::verify(broken, fee, digest, {2, 7264}));
  if (wrong_proof) return false;
  TRY_RESULT(wrong_fee, CryptoVerifiedTransfer::verify(bundle, Amount::from_nanotomi(101), digest, {2, 7264}));
  if (wrong_fee) return false;
  if (CryptoVerifiedTransfer::verify(bundle, fee, digest, {0, 0}).is_ok()) return false;

  TRY_RESULT(before, PrivateTransferState::assemble(*funding, {Amount::from_nanotomi(5000), {}, {}}));
  TRY_RESULT(before_cell, before.to_cell());
  TRY_RESULT(after, before.apply_block(1, {*verified}, {1, 2, 2}));
  if (after.accounting().notes.high() || after.accounting().notes.low() != 4900 ||
      after.accounting().fees.high() || after.accounting().fees.low() != 100 ||
      after.accounting().withdrawals.high() || after.accounting().withdrawals.low() ||
      after.notes().tree().next_position() != 4 || after.notes().nullifiers().used_count() != 4 ||
      after.notes().anchors().height() != 1) {
    std::cerr << "verified transfer did not commit the expected fee and paired effects\n";
    return false;
  }
  if (before.apply_block(1, {*verified, *verified}, {2, 2, 4}).is_ok()) return false;
  if (before.apply_block(1, {*verified}, {1, 2, 1}).is_ok()) return false;
  TRY_RESULT(poor, PrivateTransferState::assemble(*funding, {Amount::from_nanotomi(99), {}, {}}));
  if (poor.apply_block(1, {*verified}, {1, 2, 2}).is_ok()) return false;
  TRY_RESULT(unchanged, before.to_cell());
  if (unchanged->get_hash() != before_cell->get_hash()) return false;
  TRY_RESULT(after_cell, after.to_cell());
  TRY_RESULT(boc, vm::std_boc_serialize(after_cell));
  TRY_RESULT(decoded, vm::std_boc_deserialize(boc.as_slice()));
  TRY_RESULT(restored, PrivateTransferState::from_cell(decoded, 3, 3, {10, 0, 0, 0}));
  TRY_RESULT(restored_cell, restored.to_cell());
  if (restored_cell->get_hash() != after_cell->get_hash() ||
      restored.apply_block(2, {*verified}, {1, 2, 2}).is_ok()) return false;
  TRY_RESULT(idle, restored.apply_block(2, {}, {}));
  if (idle.accounting().notes.low() != 4900 || idle.accounting().fees.low() != 100 ||
      idle.notes().tree().root() != restored.notes().tree().root() || idle.notes().anchors().height() != 2) return false;
  std::cout << "Real transfer crypto, fee debit, atomic note state, restore and replay checks passed\n";
  return true;
}

bool host_fixture(const UnoCryptoVerifyRequest& request) {
  using namespace uno_workchain;
  CryptoBundle bundle;
  bundle.flags = request.flags;
  bundle.value_balance = request.value_balance;
  std::copy(std::begin(request.anchor), std::end(request.anchor), bundle.anchor.begin());
  std::copy(std::begin(request.binding_signature), std::end(request.binding_signature), bundle.binding_signature.begin());
  bundle.actions.assign(request.actions, request.actions + request.action_count);
  bundle.proof.assign(request.proof, request.proof + request.proof_bytes);
  std::array<td::uint8, 32> digest;
  std::copy(std::begin(request.sighash), std::end(request.sighash), digest.begin());
  const auto context = request.context == UNO_SHIELD_CLAIM ? BundleContext::ShieldClaim : BundleContext::Transfer;
  const auto principal = Amount::from_words(request.principal_hi, request.principal_lo);
  const auto fee = Amount::from_words(request.fee_hi, request.fee_lo);
  auto verify = [&] { return verify_crypto_bundle(bundle, context, principal, fee, digest,
                                                  {request.max_actions, request.max_proof_bytes}); };
  auto valid = verify();
  if (valid.is_error() || !valid.ok()) return false;
  bundle.proof[0] ^= 1;
  auto invalid = verify();
  if (invalid.is_error() || invalid.ok()) return false;
  bundle.proof[0] ^= 1;
  digest[0] ^= 1;
  auto wrong_digest = verify();
  if (wrong_digest.is_error() || wrong_digest.ok()) return false;
  digest[0] ^= 1;
  auto restored = verify();
  if (restored.is_error() || !restored.ok()) return false;
  auto applied = transfer_state_fixture(bundle, digest, fee, context == BundleContext::ShieldClaim);
  return applied.is_ok() && applied.ok();
}
#endif

template <size_t N>
bool read_bytes(std::istream& input, uint8_t (&bytes)[N]) {
  return static_cast<bool>(input.read(reinterpret_cast<char*>(bytes), N));
}

bool check(const char* label, uint32_t actual, uint32_t expected) {
  if (actual == expected) return true;
  std::cerr << label << ": got " << actual << ", expected " << expected << '\n';
  return false;
}

// Serial warm measurements of the full ABI call, including decoding and all
// verification. Fixture loading, proof generation and key construction are out
// of this loop. Every sample checks its result, including a rejection workload.
bool measure(const char* label, const UnoCryptoVerifyRequest& request, uint32_t expected, size_t samples) {
  for (unsigned i = 0; i < 10; ++i) {
    if (!check("measurement warmup", uno_crypto_verify_v0(&request), expected)) return false;
  }
  std::vector<double> timings;
  timings.reserve(samples);
  for (size_t i = 0; i < samples; ++i) {
    auto start = std::chrono::steady_clock::now();
    auto status = uno_crypto_verify_v0(&request);
    auto stop = std::chrono::steady_clock::now();
    if (!check("measurement sample", status, expected)) return false;
    timings.push_back(std::chrono::duration<double, std::milli>(stop - start).count());
  }
  std::sort(timings.begin(), timings.end());
  // Nearest-rank percentiles; sample count is bounded to [100, 10000] by main.
  auto percentile = [&](size_t percent) { return timings[(samples * percent + 99) / 100 - 1]; };
  std::cout << "ABI_MEASURE workload=" << label << " context=" << request.context
            << " actions=" << request.action_count << " proof_bytes=" << request.proof_bytes
            << " samples=" << samples << " warmups=10 unit=ms"
            << " p50=" << percentile(50) << " p95=" << percentile(95)
            << " p99=" << percentile(99) << " max=" << timings.back() << '\n';
  return true;
}

bool fixture(const char* path, uint32_t context, uint64_t principal, uint64_t fee, int64_t balance, size_t samples,
             const uint8_t* expected_anchor, uint8_t* produced_anchor) {
  std::ifstream input(path, std::ios::binary);
  std::array<char, 8> magic{};
  if (!input.read(magic.data(), magic.size()) || magic != std::array<char, 8>{'U','N','O','A','B','I','T','0'}) return false;
  UnoCryptoVerifyRequest request{};
  uint8_t flags[1], balance_bytes[8];
  if (!read_bytes(input, flags) || !read_bytes(input, balance_bytes)) return false;
  uint64_t encoded_balance = 0;
  for (unsigned i = 0; i < 8; ++i) encoded_balance |= uint64_t(balance_bytes[i]) << (8 * i);
  if (encoded_balance != static_cast<uint64_t>(balance)) return false;
  request.flags = flags[0];
  request.value_balance = balance;
  if (!read_bytes(input, request.anchor) || !read_bytes(input, request.binding_signature)) return false;
  uint8_t proof[7264];
  UnoCryptoAction actions[2];
  if (!read_bytes(input, proof)) return false;
  for (auto& action : actions) {
    if (!read_bytes(input, action.cv_net) || !read_bytes(input, action.nullifier) ||
        !read_bytes(input, action.rk) || !read_bytes(input, action.cmx) || !read_bytes(input, action.epk) ||
        !read_bytes(input, action.enc_ciphertext) || !read_bytes(input, action.out_ciphertext) ||
        !read_bytes(input, action.spend_signature)) return false;
  }
  if (input.peek() != std::char_traits<char>::eof() || input.bad()) return false;
  request.abi_version = UNO_CRYPTO_ABI_VERSION;
  request.profile = UNO_CRYPTO_FIXED_PROFILE;
  request.context = context;
  request.principal_lo = principal;
  request.fee_lo = fee;
  for (auto& byte : request.sighash) byte = 42;
  request.actions = actions;
  request.action_count = 2;
  request.proof = proof;
  request.proof_bytes = sizeof(proof);
  request.max_actions = 2;
  request.max_proof_bytes = sizeof(proof);
  if (expected_anchor && std::memcmp(request.anchor, expected_anchor, 32)) return false;
  if (produced_anchor) {
    UnoTreeFrontier empty{};
    UnoTreeRequest tree{};
    tree.profile = UNO_CRYPTO_FIXED_PROFILE;
    tree.frontier = &empty;
    uint8_t commitments[2][32];
    for (unsigned i = 0; i < 2; ++i) std::memcpy(commitments[i], actions[i].cmx, 32);
    tree.commitments = commitments;
    tree.commitment_count = tree.max_commitments = 2;
    UnoTreeResult result{};
    if (!check("real output tree", uno_crypto_tree_append_v0(&tree, &result), UNO_CRYPTO_OK) ||
        result.frontier.next_position != 2) return false;
    std::memcpy(produced_anchor, result.root, 32);
  }
  auto first_start = std::chrono::steady_clock::now();
  auto first_status = uno_crypto_verify_v0(&request);
  auto first_stop = std::chrono::steady_clock::now();
  if (!check("valid", first_status, UNO_CRYPTO_OK)) return false;
  if (samples) {
    std::cout << "ABI_FIRST_CALL context=" << context << " unit=ms elapsed="
              << std::chrono::duration<double, std::milli>(first_stop - first_start).count()
              << " key_previously_used=" << (context != UNO_SHIELD_CLAIM) << '\n';
  }
  request.sighash[0] ^= 1;
  if (!check("wrong digest", uno_crypto_verify_v0(&request), UNO_CRYPTO_VERIFY)) return false;
  request.sighash[0] ^= 1;
  proof[0] ^= 1;
  if (!check("bad proof", uno_crypto_verify_v0(&request), UNO_CRYPTO_VERIFY)) return false;
  proof[0] ^= 1;
  for (auto& action : actions) {
    action.spend_signature[0] ^= 1;
    if (!check("bad spend signature", uno_crypto_verify_v0(&request), UNO_CRYPTO_VERIFY)) return false;
    action.spend_signature[0] ^= 1;
  }
  request.binding_signature[0] ^= 1;
  if (!check("bad binding signature", uno_crypto_verify_v0(&request), UNO_CRYPTO_VERIFY)) return false;
  request.binding_signature[0] ^= 1;
  request.max_actions = 1;
  if (!check("action bound", uno_crypto_verify_v0(&request), UNO_CRYPTO_ARGUMENTS)) return false;
  request.max_actions = 2;
  request.principal_hi = 1;
  if (!check("wide public amount", uno_crypto_verify_v0(&request),
             context == UNO_TRANSFER ? UNO_CRYPTO_ARGUMENTS : UNO_CRYPTO_VERIFY)) return false;
  request.principal_hi = 0;
#ifdef UNO_TEST_HOST_ADAPTER
  if (!host_fixture(request)) {
    std::cerr << "host adapter fixture failed\n";
    return false;
  }
#endif
  if (!check("restored valid", uno_crypto_verify_v0(&request), UNO_CRYPTO_OK)) return false;
  if (samples) {
    if (!measure("valid", request, UNO_CRYPTO_OK, samples)) return false;
    request.sighash[0] ^= 1;
    if (!measure("wrong_digest", request, UNO_CRYPTO_VERIFY, samples)) return false;
    request.sighash[0] ^= 1;
    if (!check("post-measurement valid", uno_crypto_verify_v0(&request), UNO_CRYPTO_OK)) return false;
  }
  return true;
}

int main(int argc, char** argv) {
  if (argc != 3 && argc != 4) return 1;
  size_t samples = 0;
  if (argc == 4) {
    std::string_view text(argv[3]);
    auto parsed = std::from_chars(text.data(), text.data() + text.size(), samples);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || samples < 100 || samples > 10000) {
      std::cerr << "measurement sample count must be in [100, 10000]\n";
      return 1;
    }
  }
  uint8_t output_anchor[32];
  if (!fixture(argv[1], UNO_SHIELD_CLAIM, 5000, 0, -5000, samples, nullptr, output_anchor)) return 2;
  if (!fixture(argv[2], UNO_TRANSFER, 0, 100, 100, samples, output_anchor, nullptr)) return 3;
  std::cout << "Both real ABI fixtures and their mutations passed\n";
  return 0;
}
