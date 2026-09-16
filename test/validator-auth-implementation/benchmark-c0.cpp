#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <sodium.h>

#include "block/signature-set.h"
#include "keys/keys.hpp"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-tl.hpp"
#include "validator/auth/context.h"

#include "native-fixture.h"
using namespace auth_fixture;
namespace {
td::Bits256 bits(const Hash& h) {
  td::Bits256 out;
  std::copy(h.begin(), h.end(), out.data());
  return out;
}
Bytes bytes(td::Slice s) {
  return Bytes(s.begin(), s.end());
}
Bytes sign(const Bytes& message, const std::array<unsigned char, 64>& secret) {
  Bytes signature(64);
  check(crypto_sign_detached(signature.data(), nullptr, message.data(), message.size(), secret.data()) == 0, "sign");
  return signature;
}
double percentile(std::vector<double> values, double p) {
  std::sort(values.begin(), values.end());
  return values.at(static_cast<std::size_t>(std::ceil(p * static_cast<double>(values.size()))) - 1);
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 1 || (argc == 2 && (std::string(argv[1]) == "--enforce" || std::string(argv[1]) == "--check")),
          "arguments");
    check(sodium_init() >= 0, "sodium");
    constexpr unsigned count = 400, samples = 30, repeats = 3;
    Policy policy{1, {}, interface_fingerprint, 0, 0, {{1, 1}}, 4096, 524288};
    Committee committee{value(object_id("policy", policy), "policy-id"), h(65000), -1, 0x8000000000000000ULL, 1, 7, {}};
    std::vector<std::array<unsigned char, 64>> signing_keys;
    std::vector<tos::ValidatorDescr> validators;
    for (unsigned n = 1; n <= count; ++n) {
      Member member{h(n), h(n + 1000), 1, h(n + 2000), {}};
      for (unsigned role = 1; role <= 5; ++role) {
        auto seed = h(5 * n + role + 3000);
        Hash public_key{};
        std::array<unsigned char, 64> secret{};
        check(crypto_sign_seed_keypair(public_key.data(), secret.data(), seed.data()) == 0, "keygen");
        member.keys_.push_back(Key{member.identity_,
                                   static_cast<std::uint8_t>(role),
                                   1,
                                   1,
                                   1,
                                   0,
                                   1000,
                                   Bytes(public_key.begin(), public_key.end()),
                                   {},
                                   0});
        if (role == 3) {
          signing_keys.push_back(secret);
          validators.emplace_back(tos::Ed25519_PublicKey{bits(public_key)}, 1);
        }
      }
      committee.members_.push_back(std::move(member));
    }
    auto snapshot = value(RegistrySnapshot::compile(committee, policy), "snapshot");
    auto vset = td::make_ref<block::ValidatorSet>(7, tos::ShardIdFull{-1, 0x8000000000000000ULL}, validators);
    ChainContext chain{-239, h(64000), h(64001), h(64002)};
    auto session = value(session_id(chain, snapshot, {}), "session");
    tos::BlockIdExt block_id{-1, 0x8000000000000000ULL, 2, bits(h(63000)), bits(h(63001))};
    auto candidate = tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
        tos::create_tl_block_id(block_id),
        tos::create_tl_object<tos::tos_api::consensus_candidateId>(0, bits(h(62000))));
    auto candidate_hash = td::Bits256{tos::get_tl_object_sha256(candidate).raw};
    auto native_payload = tos::create_serialize_tl_object<tos::tos_api::consensus_simplex_finalizeVote>(
        tos::create_tl_object<tos::tos_api::consensus_candidateId>(1, candidate_hash));
    auto payload = bytes(native_payload.as_slice());
    auto native_statement =
        tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(bits(session), native_payload.clone());
    auto duty = value(make_duty(chain, snapshot, session, 3, 1, payload), "duty");
    Certificate cert{duty, payload, {}};
    std::vector<tos::BlockSignature> signatures;
    for (unsigned n = 0; n < count; ++n) {
      const auto& member = committee.members_[n];
      auto ref = value(key_reference(member.keys_[2]), "keyref");
      Record record{member.identity_, {{1, 1, 1, ref.key_id_, {}}}};
      record.components_[0].signature_ = sign(value(signing_statement(duty, record), "statement"), signing_keys[n]);
      cert.records_.push_back(record);
      auto sig = sign(bytes(native_statement.as_slice()), signing_keys[n]);
      auto node = tos::PublicKey{tos::pubkeys::Ed25519{validators[n].key}}.compute_short_id().bits256_value();
      signatures.emplace_back(node, td::BufferSlice(td::Slice(reinterpret_cast<const char*>(sig.data()), sig.size())));
    }
    auto legacy = block::BlockSignatureSet::create_simplex(std::move(signatures), 7, vset->get_validator_set_hash(),
                                                           bits(session), 1, std::move(candidate));
    auto verify_legacy = [&] {
      auto result = legacy->check_signatures(vset, block_id);
      if (result.is_error())
        throw std::runtime_error("legacy-valid: " + result.error().message().str());
      check(result.ok() == count, "legacy-weight");
    };
    auto verify_ed25519 = [&] {
      auto result = snapshot.verify(cert, duty);
      check(result.ok() && result.value().weight() == count, "p0-valid");
    };
    // Prove each measurement reaches authentication before timing either path.
    auto invalid = cert;
    invalid.records_[0].components_[0].signature_[0] ^= 1;
    check(!snapshot.verify(invalid, duty).ok(), "p0-negative-control");
    auto invalid_legacy = legacy->tl();
    auto& invalid_set = static_cast<tos::tos_api::tosNode_signatureSet_simplex&>(*invalid_legacy);
    auto changed_signature = td::BufferSlice(invalid_set.signatures_[0]->signature_.as_slice());
    changed_signature.as_slice()[0] ^= 1;
    invalid_set.signatures_[0]->signature_ = std::move(changed_signature);
    auto invalid_legacy_set = block::BlockSignatureSet::fetch(invalid_legacy);
    check(invalid_legacy_set.not_null() && invalid_legacy_set->check_signatures(vset, block_id).is_error(),
          "legacy-signature-negative-control");
    auto other_block = block_id;
    other_block.root_hash = bits(h(60000));
    check(legacy->check_signatures(vset, other_block).is_error(), "legacy-negative-control");
    verify_legacy();
    verify_ed25519();
    if (argc == 2 && std::string(argv[1]) == "--check") {
      std::cout << "PASS: 400-member native certificate benchmark controls\n";
      return 0;
    }
    auto elapsed = [&](auto&& verify) {
      auto begin = std::chrono::steady_clock::now();
      for (unsigned i = 0; i < repeats; ++i)
        verify();
      return std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - begin).count() / repeats;
    };
    std::vector<double> old_times, new_times, paired;
    for (unsigned i = 0; i < samples + 4; ++i) {
      double old_time, new_time;
      if (i % 2) {
        new_time = elapsed(verify_ed25519);
        old_time = elapsed(verify_legacy);
      } else {
        old_time = elapsed(verify_legacy);
        new_time = elapsed(verify_ed25519);
      }
      if (i >= 4) {
        old_times.push_back(old_time);
        new_times.push_back(new_time);
        paired.push_back(new_time / old_time);
      }
    }
    double median = percentile(new_times, .5) / percentile(old_times, .5),
           p95 = percentile(new_times, .95) / percentile(old_times, .95);
    bool within = median <= 1.05 && p95 <= 1.10;
    std::cout << std::setprecision(10) << "{\"scope\":\"native-certificate-verification\",\"members\":" << count
              << ",\"samples\":" << samples << ",\"repeats\":" << repeats
              << ",\"legacy_us\":{\"p50\":" << percentile(old_times, .5) << ",\"p95\":" << percentile(old_times, .95)
              << ",\"p99\":" << percentile(old_times, .99) << "},\"ed25519_us\":{\"p50\":" << percentile(new_times, .5)
              << ",\"p95\":" << percentile(new_times, .95) << ",\"p99\":" << percentile(new_times, .99)
              << "},\"median_ratio\":" << median << ",\"p95_ratio\":" << p95
              << ",\"paired_median_ratio\":" << percentile(paired, .5)
              << ",\"within_budget\":" << (within ? "true" : "false") << "}\n";
    return argc == 2 && !within ? 2 : 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
