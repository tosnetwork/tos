#include <filesystem>
#include <fstream>
#include <iostream>

#include "block/mc-config.h"
#include "validator/auth/native-proof.h"
#include "validator/auth/object-store.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"

#include "native-fixture.h"
using namespace p0_fixture;
int main(int argc, char** argv) {
  try {
    std::filesystem::path output;
    if (argc == 2) {
      output = argv[1];
      check(std::filesystem::create_directory(output), "fresh-proof-export");
    } else
      check(argc == 1, "proof-export-arguments");
    auto write = [&](const std::string& name, std::span<const std::uint8_t> bytes) {
      if (output.empty())
        return;
      std::ofstream file(output / name, std::ios::binary);
      file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
      check(file.good(), "proof-export-write");
    };
    unsigned example = 0;
    auto verify = [&](std::uint8_t method, std::span<const std::uint8_t> request,
                      std::span<const std::uint8_t> response, const Anchor& a, std::int32_t network,
                      ObjectReader& reader) {
      auto result = ::tos::auth::verify_native_response(method, request, response, a, network, reader);
      if (!output.empty()) {
        auto name = std::to_string(example++);
        write(name + ".request", request);
        write(name + ".response", response);
        write(name + ".anchor", value(encode(a), "anchor-export"));
        std::ofstream meta(output / (name + ".case"));
        meta << unsigned(method) << ' ' << network << ' ' << result.ok() << '\n';
        check(meta.good(), "proof-export-meta");
      }
      return result;
    };
    auto registry = state();
    auto root = masterchain(registry);
    auto pinned = anchor(root);
    ObjectReader reader({});
    auto profile_request = value(encode(GetProfileRequest{pinned}), "profile-request");
    auto profile = value(make_native_response(root, pinned, -239, 8, profile_request), "profile-proof");
    auto verified = value(verify(8, profile_request, profile, pinned, -239, reader), "verify-profile");
    check(verified.bytes() == profile, "verified-profile-bytes");
    auto policy_request = value(encode(GetPolicyRequest{pinned, registry.current_policy()}), "policy-request");
    auto policy = value(make_native_response(root, pinned, -239, 9, policy_request), "policy-proof");
    value(verify(9, policy_request, policy, pinned, -239, reader), "verify-policy");
    auto key_id = registry.identities().begin()->second.active_[0].key_.key_id_;
    auto key_request = value(encode(GetKeyRequest{pinned, key_id}), "key-request");
    auto key = value(make_native_response(root, pinned, -239, 11, key_request), "key-proof");
    value(verify(11, key_request, key, pinned, -239, reader), "verify-key");
    auto query = value(encode(GetRegistryRequest{pinned, 2, {}}), "page-request");
    auto page_raw = value(make_native_response(root, pinned, -239, 10, query), "page-proof");
    value(verify(10, query, page_raw, pinned, -239, reader), "verify-page");
    auto page = value(decode<RegistryResult>(page_raw), "page");
    check(page.identities_.size() == 2 && page.cursor_.size() == 1, "page-boundary");
    auto next_query = value(encode(GetRegistryRequest{pinned, 2, page.cursor_}), "next-query");
    auto last_raw = value(make_native_response(root, pinned, -239, 10, next_query), "last-page");
    value(verify(10, next_query, last_raw, pinned, -239, reader), "verify-last-page");
    auto last = value(decode<RegistryResult>(last_raw), "last");
    check(last.identities_.size() == 1 && last.cursor_.empty(), "terminal-page");
    auto forged = page;
    forged.identities_.erase(forged.identities_.begin());
    check(!verify(10, query, value(encode(forged), "omitted"), pinned, -239, reader).ok(), "range-omission");
    forged = page;
    forged.cursor_.clear();
    check(!verify(10, query, value(encode(forged), "false-terminal"), pinned, -239, reader).ok(), "range-terminal");
    auto wrong = pinned;
    wrong.state_ = h(7000);
    check(!verify(8, profile_request, profile, wrong, -239, reader).ok(), "anchor-substitution");
    check(!verify(8, profile_request, profile, pinned, -238, reader).ok(), "network-substitution");
    auto substituted = value(decode<ProfileResult>(profile), "substituted-profile");
    substituted.anchor_ = wrong;
    substituted.proof_.anchor_ = wrong;
    auto wrong_request = value(encode(GetProfileRequest{wrong}), "wrong-root-request");
    check(!verify(8, wrong_request, value(encode(substituted), "substituted"), wrong, -239, reader).ok(),
          "authenticated-state-root");
    auto full = vm::MerkleProof::generate(root, [](const td::Ref<vm::Cell>&) { return false; });
    check(full.is_ok(), "full-proof");
    auto full_boc = vm::std_boc_serialize(full.ok());
    check(full_boc.is_ok(), "full-proof-boc");
    auto full_bytes = std::span<const std::uint8_t>(full_boc.ok().as_slice().ubegin(), full_boc.ok().size());
    auto excessive = value(decode<ProfileResult>(profile), "excessive-profile");
    excessive.proof_.proof_ = value(object_value(5, full_bytes), "full-proof-object");
    excessive.proof_.proof_hash_ = value(digest("proof", full_bytes), "full-proof-hash");
    check(!verify(8, profile_request, value(encode(excessive), "excessive"), pinned, -239, reader).ok(),
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
    auto detached_result =
        verify(8, profile_request, value(encode(sparse_profile), "detached-result"), pinned, -239, detached_reader);
    check(generic_result.is_ok(), "generic-boc-accepted");
    check(!detached_result.ok(), "proof-no-detached-cells");
    auto bad_profile = value(decode<ProfileResult>(profile), "profile");
    bad_profile.proof_.proof_hash_[0] ^= 1;
    check(!verify(8, profile_request, value(encode(bad_profile), "bad-proof-hash"), pinned, -239, reader).ok(),
          "proof-hash");
    auto disabled = masterchain(registry, 0, 0);
    check(!make_native_response(disabled, anchor(disabled), -239, 8,
                                value(encode(GetProfileRequest{anchor(disabled)}), "disabled-request"))
               .ok(),
          "capability-gate");
    auto config = block::Config::extract_from_state(root);
    check(config.is_ok(), "mutation-config");
    auto flip_bit = [](td::Ref<vm::Cell> cell, unsigned bit) {
      vm::CellSlice s(vm::NoVm{}, cell);
      vm::CellBuilder b;
      auto bits = s.size();
      for (unsigned n = 0; n < bits; ++n)
        b.store_long(s.fetch_ulong(1) ^ (n == bit), 1);
      while (s.size_refs())
        b.store_ref(s.fetch_ref());
      return td::Ref<vm::Cell>(b.finalize());
    };
    auto altered_config = [&](int index, const std::function<td::Ref<vm::Cell>(td::Ref<vm::Cell>)>& alter) {
      auto original = config.ok()->get_config_param(index);
      check(original.not_null(), "original-parameter");
      auto target = original->get_hash();
      unsigned replaced = 0;
      std::function<td::Ref<vm::Cell>(td::Ref<vm::Cell>)> replace = [&](td::Ref<vm::Cell> cell) {
        if (cell->get_hash(0) == target) {
          ++replaced;
          return alter(cell);
        }
        vm::CellSlice s(vm::NoVm{}, cell);
        vm::CellBuilder b;
        b.store_bits(s.fetch_bits(s.size()));
        while (s.size_refs())
          b.store_ref(replace(s.fetch_ref()));
        return td::Ref<vm::Cell>(b.finalize(s.is_special()));
      };
      auto inner = replace(vm::load_cell_slice_special(sparse_bag.get_root_cell()).prefetch_ref(0));
      check(replaced >= 1, "changed-parameter");
      auto merkle = vm::CellBuilder::create_merkle_proof(inner);
      auto boc = vm::std_boc_serialize(merkle);
      check(boc.is_ok(), "changed-parameter-boc");
      auto changed = pinned;
      auto hash = inner->get_hash(0).as_slice();
      std::copy(hash.ubegin(), hash.uend(), changed.state_.begin());
      auto response = value(decode<ProfileResult>(profile), "changed-profile");
      response.anchor_ = changed;
      response.proof_.anchor_ = changed;
      auto bytes = std::span<const std::uint8_t>(boc.ok().as_slice().ubegin(), boc.ok().size());
      response.proof_.proof_ = value(object_value(5, bytes), "changed-proof-object");
      response.proof_.proof_hash_ = value(digest("proof", bytes), "changed-proof-hash");
      ObjectReader fresh({});
      return verify(8, value(encode(GetProfileRequest{changed}), "changed-request"),
                    value(encode(response), "changed-response"), changed, -239, fresh);
    };
    check(!altered_config(8, [&](auto cell) { return flip_bit(cell, 93); }).ok(), "proof-capability-gate");
    check(!altered_config(16, [&](auto cell) { return flip_bit(cell, 15); }).ok(), "proof-validator-ceiling");
    check(!altered_config(46, [&](auto cell) { return flip_bit(cell, 47); }).ok(), "proof-config-version");
    check(!altered_config(46,
                          [&](auto cell) {
                            vm::CellSlice s(vm::NoVm{}, cell);
                            vm::CellBuilder b;
                            b.store_bits(s.fetch_bits(48));
                            s.advance(256);
                            b.store_zeroes(256);
                            b.store_bits(s.fetch_bits(s.size()));
                            while (s.size_refs())
                              b.store_ref(s.fetch_ref());
                            return td::Ref<vm::Cell>(b.finalize());
                          })
               .ok(),
          "proof-chain-domain");
    auto wrong_proof = value(decode<ProfileResult>(profile), "wrong-proof-kind");
    wrong_proof.proof_.kind_ = 5;
    ObjectReader fresh({});
    check(!verify(8, profile_request, value(encode(wrong_proof), "wrong-kind"), pinned, -239, fresh).ok(),
          "proof-kind-binding");
    wrong_proof = value(decode<ProfileResult>(profile), "wrong-proof-object");
    wrong_proof.proof_.object_id_ = h(7001);
    check(!verify(8, profile_request, value(encode(wrong_proof), "wrong-object"), pinned, -239, fresh).ok(),
          "proof-object-binding");
    auto misplaced = value(decode<ProfileResult>(profile), "misplaced-proof");
    misplaced.proof_.anchor_.root_ = h(7002);
    check(!verify(8, profile_request, value(encode(misplaced), "misplaced-response"), pinned, -239, fresh).ok(),
          "proof-anchor-binding");
    auto large_registry = pending_state(128);
    auto large_root = masterchain(large_registry, 1);
    auto large_anchor = anchor(large_root, 1);
    auto large_query = value(encode(GetRegistryRequest{large_anchor, 128, {}}), "large-query");
    auto unstored = make_native_response(large_root, large_anchor, -239, 10, large_query);
    check(!unstored.ok() && unstored.error().code == "proof-needs-object-store", "large-proof-needs-storage");
    ScopedObjectStore storage;
    auto published = value(make_native_response(large_root, large_anchor, -239, 10, large_query,
                                                [&](const ObjectRef& ref, std::span<const std::uint8_t> raw) {
                                                  std::string name;
                                                  for (auto byte : ref.object_id_) {
                                                    name.push_back("0123456789abcdef"[byte >> 4]);
                                                    name.push_back("0123456789abcdef"[byte & 15]);
                                                  }
                                                  write(name, raw);
                                                  return storage.publish(h(9000), large_anchor, ref, raw, 1);
                                                }),
                           "large-proof-publish");
    auto large_page = value(decode<RegistryResult>(published), "large-page");
    check(large_page.identities_.size() == 128 && large_page.proof_.proof_.reference_.size() == 1,
          "large-page-manifest");
    ObjectReader from_store(
        [&](const ObjectRef& ref, std::uint8_t index) { return storage.get(h(9000), large_anchor, ref, index, 1); });
    value(verify(10, large_query, published, large_anchor, -239, from_store), "large-proof-verified");
    auto refused =
        make_native_response(large_root, large_anchor, -239, 10, large_query,
                             [](const ObjectRef&, std::span<const std::uint8_t>) { return Result<bool>(false); });
    check(!refused.ok(), "publication-before-manifest");
    if (!output.empty()) {
      std::ofstream done(output / "complete");
      done << example << '\n';
      check(done.good(), "proof-export-complete");
    }
    std::cout << "PASS: native masterchain proof linkage, pinned pages, large published proofs and negative proofs\n";
    return 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
