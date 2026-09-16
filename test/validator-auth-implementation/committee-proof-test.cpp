#include <filesystem>
#include <fstream>
#include <iostream>

#include "validator/auth/committee-proof.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"

#include "native-fixture.h"
using namespace auth_fixture;
namespace {
Bytes read(const std::filesystem::path& path) {
  std::ifstream f(path, std::ios::binary);
  check(f.good(), "input");
  return Bytes(std::istreambuf_iterator<char>(f), {});
}
void write(const std::filesystem::path& path, const Bytes& raw) {
  std::ofstream f(path, std::ios::binary);
  f.write(reinterpret_cast<const char*>(raw.data()), raw.size());
  check(f.good(), "output");
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 2 || argc == 3, "arguments");
    std::filesystem::path input(argv[1]), output;
    if (argc == 3) {
      output = argv[2];
      check(std::filesystem::create_directory(output), "fresh-output");
    }
    unsigned count = 0, cases = 0;
    std::ifstream(input / "complete") >> count;
    check(count >= 39, "complete-input");
    for (unsigned i = 0; i < count; ++i) {
      auto path = input / std::to_string(i);
      std::int32_t wc;
      std::uint64_t shard;
      std::uint32_t cc;
      bool accepted;
      std::string label;
      std::ifstream(path.string() + ".case") >> wc >> shard >> cc >> accepted >> label;
      auto a = value(decode<Anchor>(read(path.string() + ".anchor")), "anchor");
      auto chain_raw = read(path.string() + ".chain");
      Reader r(chain_raw);
      ChainContext chain;
      r.integer(chain.network);
      r.hash(chain.genesis_root);
      r.hash(chain.genesis_file);
      r.hash(chain.chain_domain);
      check(r.ok(), "chain");
      auto bytes = read(path.string() + ".boc");
      auto root = vm::std_boc_deserialize(td::Slice(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
      check(root.is_ok(), "input-boc");
      ChunkStore store;
      auto publish = [&](const ObjectRef& manifest, std::span<const std::uint8_t> raw) -> Result<bool> {
        for (std::size_t n = 0, offset = 0; offset < raw.size(); ++n, offset += chunk_bytes) {
          auto stored = store.put(manifest, static_cast<std::uint8_t>(n),
                                  raw.subspan(offset, std::min(chunk_bytes, raw.size() - offset)), 1);
          if (!stored.ok())
            return stored.error();
        }
        return true;
      };
      auto generated = make_committee_proof(root.ok(), a, chain, {wc, shard}, cc, publish);
      check(generated.ok() == accepted, "proof-source-admission");
      if (!accepted)
        continue;
      auto proof = generated.value();
      ObjectReader reader([&](const ObjectRef& manifest, std::uint8_t n) { return store.get(manifest, n, 1); });
      auto raw = value(reader.resolve(proof.proof_, 5), "proof-carrier");
      auto run = [&](const Proofref& p, const Anchor& anchor, const ChainContext& c, tos::ShardIdFull target,
                     std::uint32_t catchain, const char* name, bool ok) {
        ObjectReader fresh([&](const ObjectRef& manifest, std::uint8_t n) { return store.get(manifest, n, 1); });
        auto result = verify_committee_proof(p, anchor, c, target, catchain, fresh);
        check(result.ok() == ok, name);
        if (ok)
          check(value(encode(result.value().snapshot().committee()), "committee") == read(path.string() + ".committee"),
                "proof-committee");
        if (!output.empty()) {
          auto out = output / std::to_string(cases);
          write(out.string() + ".proof", value(encode(p), "proof"));
          write(out.string() + ".anchor", value(encode(anchor), "anchor"));
          Writer w;
          w.integer(c.network);
          w.bytes(c.genesis_root);
          w.bytes(c.genesis_file);
          w.bytes(c.chain_domain);
          write(out.string() + ".chain", w.data);
          ObjectReader export_reader(
              [&](const ObjectRef& manifest, std::uint8_t n) { return store.get(manifest, n, 1); });
          write(out.string() + ".raw", value(export_reader.resolve(p.proof_, 5), "export-raw"));
          std::ofstream meta(out.string() + ".case");
          meta << target.workchain << ' ' << target.shard << ' ' << catchain << ' ' << ok << ' ' << name << '\n';
          if (ok)
            write(out.string() + ".committee", read(path.string() + ".committee"));
        }
        ++cases;
      };
      run(proof, a, chain, {wc, shard}, cc, "committee-proof", true);
      if (i == 0) {
        auto changed = proof;
        changed.kind_ = 2;
        run(changed, a, chain, {wc, shard}, cc, "proof-kind", false);
        changed = proof;
        changed.anchor_.file_[0] ^= 1;
        run(changed, a, chain, {wc, shard}, cc, "proof-anchor", false);
        changed = proof;
        changed.proof_hash_[0] ^= 1;
        run(changed, a, chain, {wc, shard}, cc, "proof-hash", false);
        changed = proof;
        changed.object_id_[0] ^= 1;
        run(changed, a, chain, {wc, shard}, cc, "proof-object", false);
        auto wrong = a;
        wrong.state_[0] ^= 1;
        changed = proof;
        changed.anchor_ = wrong;
        run(changed, wrong, chain, {wc, shard}, cc, "proof-state", false);
        run(proof, a, chain, {wc, shard}, cc + 1, "proof-catchain", false);
        auto alien = chain;
        alien.network += 1;
        run(proof, a, alien, {wc, shard}, cc, "proof-network", false);
        auto full = vm::MerkleProof::generate(root.ok(), [](const td::Ref<vm::Cell>&) { return false; });
        check(full.is_ok(), "full-proof");
        auto full_boc = vm::std_boc_serialize(full.ok(), 31);
        check(full_boc.is_ok(), "full-boc");
        auto full_slice = full_boc.ok().as_slice();
        Bytes full_raw(full_slice.ubegin(), full_slice.uend());
        changed = proof;
        changed.proof_ = value(object_value(5, full_raw), "full-carrier");
        changed.proof_hash_ = value(digest("proof", full_raw), "full-hash");
        if (!changed.proof_.reference_.empty())
          value(publish(changed.proof_.reference_[0], full_raw), "full-publish");
        run(changed, a, chain, {wc, shard}, cc, "proof-unrelated-values", false);
        vm::BagOfCells sparse;
        check(sparse.deserialize(td::Slice(reinterpret_cast<const char*>(raw.data()), raw.size()), 1).is_ok(),
              "sparse-proof");
        vm::CellBuilder unrelated;
        unrelated.store_long(0xa51def, 24);
        vm::BagOfCells baggage;
        check(baggage.set_roots({sparse.get_root_cell(), unrelated.finalize()}) == 2, "baggage-roots");
        check(baggage.import_cells().is_ok(), "baggage-import");
        auto baggage_boc = baggage.serialize_to_slice(0);
        check(baggage_boc.is_ok(), "baggage-boc");
        auto baggage_slice = baggage_boc.ok().as_slice();
        Bytes detached(baggage_slice.ubegin(), baggage_slice.uend());
        vm::BagOfCells::Info metadata;
        check(metadata.parse_serialized_header(
                  td::Slice(reinterpret_cast<const char*>(detached.data()), detached.size())) > 0,
              "baggage-header");
        metadata.write_ref(detached.data() + 6 + metadata.ref_byte_size, 1);
        detached.erase(detached.begin() + metadata.roots_offset + metadata.ref_byte_size,
                       detached.begin() + metadata.roots_offset + 2 * metadata.ref_byte_size);
        vm::BagOfCells generic;
        check(
            generic.deserialize(td::Slice(reinterpret_cast<const char*>(detached.data()), detached.size()), 1).is_ok(),
            "generic-boc-accepted");
        changed = proof;
        changed.proof_ = value(object_value(5, detached), "detached-carrier");
        changed.proof_hash_ = value(digest("proof", detached), "detached-hash");
        run(changed, a, chain, {wc, shard}, cc, "proof-no-detached-cells", false);
      }
      if (!proof.proof_.reference_.empty()) {
        check(!make_committee_proof(root.ok(), a, chain, {wc, shard}, cc).ok(), "proof-storage-required");
        check(
            !make_committee_proof(root.ok(), a, chain, {wc, shard}, cc,
                                  [](const ObjectRef&, std::span<const std::uint8_t>) -> Result<bool> { return false; })
                 .ok(),
            "proof-publication");
      }
    }
    if (!output.empty()) {
      std::ofstream done(output / "complete");
      done << cases << '\n';
    }
    std::cout << "PASS: native committee proofs " << cases << " cases\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
