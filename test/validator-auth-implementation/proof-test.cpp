#include <iostream>

#include "validator/auth/native-proof.h"
#include "validator/auth/object-store.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"

#include "native-fixture.h"
using namespace p0_fixture;
// This fixture supplies already accepted lifecycle requests. This proof test
// authenticates their resulting native state, not the admission authority.
class AcceptedFixtureRequests : public LifecycleAuthority {
 public:
  Result<bool> owner(const OwnerAuth&, const Update&, const Identity&) const override {
    return true;
  }
  Result<bool> possession(const PossessionAuth&, const Update&, const Key&) const override {
    return true;
  }
  Result<bool> administration(const IdentityAuth&, const Update&, const Identity&, std::uint32_t) const override {
    return true;
  }
};
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
    auto sparse_profile = value(decode<ProfileResult>(profile), "sparse-profile");
    auto sparse_raw = sparse_profile.proof_.proof_.inline_;
    vm::BagOfCells sparse_bag;
    check(sparse_bag.deserialize(td::Slice(reinterpret_cast<const char*>(sparse_raw.data()), sparse_raw.size()), 1)
              .is_ok(),
          "sparse-boc");
    vm::CellBuilder unrelated;
    unrelated.store_long(0xa51def, 24);
    vm::BagOfCells baggage;
    check(baggage.set_roots({sparse_bag.get_root_cell(), unrelated.finalize()}) == 2, "baggage-roots");
    check(baggage.import_cells().is_ok(), "baggage-import");
    auto baggage_boc = baggage.serialize_to_slice(0);
    check(baggage_boc.is_ok(), "baggage-serialize");
    Bytes detached(baggage_boc.ok().as_slice().ubegin(), baggage_boc.ok().as_slice().uend());
    vm::BagOfCells::Info metadata;
    check(metadata.parse_serialized_header(td::Slice(reinterpret_cast<const char*>(detached.data()), detached.size())) >
              0,
          "baggage-header");
    metadata.write_ref(detached.data() + 6 + metadata.ref_byte_size, 1);
    detached.erase(detached.begin() + metadata.roots_offset + metadata.ref_byte_size,
                   detached.begin() + metadata.roots_offset + 2 * metadata.ref_byte_size);
    vm::BagOfCells generic;
    auto generic_result =
        generic.deserialize(td::Slice(reinterpret_cast<const char*>(detached.data()), detached.size()), 1);
    sparse_profile.proof_.proof_ = value(object_value(5, detached), "detached-object");
    sparse_profile.proof_.proof_hash_ = value(digest("proof", detached), "detached-proof-hash");
    ObjectReader detached_reader({});
    auto detached_result = verify_native_response(8, profile_request, value(encode(sparse_profile), "detached-result"),
                                                  pinned, -239, detached_reader);
    check(generic_result.is_ok(), "generic-boc-accepted");
    check(!detached_result.ok(), "proof-no-detached-cells");
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
    auto large_registry = state(128);
    std::vector<std::pair<Update, Authorizations>> updates;
    for (const auto& [id, identity] : large_registry.identities()) {
      Update retire{
          3,  id, 0, value(object_id("identity", identity), "retire-predecessor"), 2, identity.active_[0].key_.key_id_,
          {}, {}, {}};
      Authorizations accepted;
      accepted.administration_.push_back(
          {value(object_id("update", retire), "retire-id"), id,
           value(object_value(4, value(encode(Certificate{}), "fixture-certificate")), "fixture-carrier")});
      updates.emplace_back(retire, accepted);
    }
    large_registry = value(large_registry.apply_block(1, updates, AcceptedFixtureRequests{}), "pending-state");
    auto large_root = masterchain(large_registry, 1);
    auto large_anchor = anchor(large_root, 1);
    auto large_query = value(encode(GetRegistryRequest{large_anchor, 128, {}}), "large-query");
    auto unstored = make_native_response(large_root, large_anchor, -239, 10, large_query);
    check(!unstored.ok() && unstored.error().code == "proof-needs-object-store", "large-proof-needs-storage");
    ScopedObjectStore storage;
    auto published = value(make_native_response(large_root, large_anchor, -239, 10, large_query,
                                                [&](const ObjectRef& ref, std::span<const std::uint8_t> raw) {
                                                  return storage.publish(h(9000), large_anchor, ref, raw, 1);
                                                }),
                           "large-proof-publish");
    auto large_page = value(decode<RegistryResult>(published), "large-page");
    check(large_page.identities_.size() == 128 && large_page.proof_.proof_.reference_.size() == 1,
          "large-page-manifest");
    ObjectReader from_store(
        [&](const ObjectRef& ref, std::uint8_t index) { return storage.get(h(9000), large_anchor, ref, index, 1); });
    value(verify_native_response(10, large_query, published, large_anchor, -239, from_store), "large-proof-verified");
    auto refused =
        make_native_response(large_root, large_anchor, -239, 10, large_query,
                             [](const ObjectRef&, std::span<const std::uint8_t>) { return Result<bool>(false); });
    check(!refused.ok(), "publication-before-manifest");
    std::cout << "PASS: native masterchain proof linkage, pinned pages, large published proofs and negative proofs\n";
    return 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
