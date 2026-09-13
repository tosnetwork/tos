#include <iostream>

#include "validator/auth/native-proof.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"

#include "native-fixture.h"
using namespace p0_fixture;
int main() {
  try {
    auto registry = state();
    auto root = masterchain(registry);
    auto pinned = anchor(root);
    ObjectReader reader({});
    auto profile_request = value(encode(GetProfileRequest{pinned}), "profile-request");
    auto profile = value(make_native_response(root, pinned, -239, 8, profile_request), "profile-proof");
    auto verified = value(verify_native_response(8, profile_request, profile, pinned, -239, reader), "verify-profile");
    check(verified.bytes() == profile, "verified-profile-bytes");
    auto policy_request = value(encode(GetPolicyRequest{pinned, registry.current_policy()}), "policy-request");
    auto policy = value(make_native_response(root, pinned, -239, 9, policy_request), "policy-proof");
    value(verify_native_response(9, policy_request, policy, pinned, -239, reader), "verify-policy");
    auto key_id = registry.identities().begin()->second.active_[0].key_.key_id_;
    auto key_request = value(encode(GetKeyRequest{pinned, key_id}), "key-request");
    auto key = value(make_native_response(root, pinned, -239, 11, key_request), "key-proof");
    value(verify_native_response(11, key_request, key, pinned, -239, reader), "verify-key");
    auto query = value(encode(GetRegistryRequest{pinned, 2, {}}), "page-request");
    auto page_raw = value(make_native_response(root, pinned, -239, 10, query), "page-proof");
    value(verify_native_response(10, query, page_raw, pinned, -239, reader), "verify-page");
    auto page = value(decode<RegistryResult>(page_raw), "page");
    check(page.identities_.size() == 2 && page.cursor_.size() == 1, "page-boundary");
    auto next_query = value(encode(GetRegistryRequest{pinned, 2, page.cursor_}), "next-query");
    auto last_raw = value(make_native_response(root, pinned, -239, 10, next_query), "last-page");
    value(verify_native_response(10, next_query, last_raw, pinned, -239, reader), "verify-last-page");
    auto last = value(decode<RegistryResult>(last_raw), "last");
    check(last.identities_.size() == 1 && last.cursor_.empty(), "terminal-page");
    auto forged = page;
    forged.identities_.erase(forged.identities_.begin());
    check(!verify_native_response(10, query, value(encode(forged), "omitted"), pinned, -239, reader).ok(),
          "range-omission");
    forged = page;
    forged.cursor_.clear();
    check(!verify_native_response(10, query, value(encode(forged), "false-terminal"), pinned, -239, reader).ok(),
          "range-terminal");
    auto wrong = pinned;
    wrong.state_ = h(7000);
    check(!verify_native_response(8, profile_request, profile, wrong, -239, reader).ok(), "anchor-substitution");
    check(!verify_native_response(8, profile_request, profile, pinned, -238, reader).ok(), "network-substitution");
    auto substituted = value(decode<ProfileResult>(profile), "substituted-profile");
    substituted.anchor_ = wrong;
    substituted.proof_.anchor_ = wrong;
    auto wrong_request = value(encode(GetProfileRequest{wrong}), "wrong-root-request");
    check(
        !verify_native_response(8, wrong_request, value(encode(substituted), "substituted"), wrong, -239, reader).ok(),
        "authenticated-state-root");
    auto full = vm::MerkleProof::generate(root, [](const td::Ref<vm::Cell>&) { return false; });
    check(full.is_ok(), "full-proof");
    auto full_boc = vm::std_boc_serialize(full.ok());
    check(full_boc.is_ok(), "full-proof-boc");
    auto full_bytes = std::span<const std::uint8_t>(full_boc.ok().as_slice().ubegin(), full_boc.ok().size());
    auto excessive = value(decode<ProfileResult>(profile), "excessive-profile");
    excessive.proof_.proof_ = value(object_value(5, full_bytes), "full-proof-object");
    excessive.proof_.proof_hash_ = value(digest("proof", full_bytes), "full-proof-hash");
    check(!verify_native_response(8, profile_request, value(encode(excessive), "excessive"), pinned, -239, reader).ok(),
          "unrelated-proof-values");
    auto bad_profile = value(decode<ProfileResult>(profile), "profile");
    bad_profile.proof_.proof_hash_[0] ^= 1;
    check(
        !verify_native_response(8, profile_request, value(encode(bad_profile), "bad-proof-hash"), pinned, -239, reader)
             .ok(),
        "proof-hash");
    auto disabled = masterchain(registry, 0, 0);
    check(!make_native_response(disabled, anchor(disabled), -239, 8,
                                value(encode(GetProfileRequest{anchor(disabled)}), "disabled-request"))
               .ok(),
          "capability-gate");
    std::cout << "PASS: native masterchain proof linkage, pinned pages and negative proofs\n";
    return 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
