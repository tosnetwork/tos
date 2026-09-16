#include "validator/auth/native-evidence.h"

#include "owner-fixture.h"
using namespace p0_owner_fixture;
namespace {
using ChunkKey = std::array<std::uint8_t, 33>;
ChunkKey key(Hash id, std::size_t index) {
  ChunkKey k{};
  std::copy(id.begin(), id.end(), k.begin());
  k[32] = static_cast<std::uint8_t>(index);
  return k;
}
vm::Dictionary attachments(const ObjectValue& v, const Bytes& raw) {
  vm::Dictionary d(264);
  if (!v.reference_.empty()) {
    const auto& r = v.reference_[0];
    for (std::size_t i = 0; i < r.chunk_hashes_.size(); ++i) {
      auto k = key(r.object_id_, i);
      auto bytes = std::span<const std::uint8_t>(raw).subspan(i * chunk_bytes,
                                                              std::min(chunk_bytes, raw.size() - i * chunk_bytes));
      check(d.set_ref(td::ConstBitPtr(k.data()), 264, value(pack_bytes(bytes), "fixture-chunk")), "fixture-dictionary");
    }
  }
  return d;
}
td::Ref<vm::Cell> envelope(td::Ref<vm::Cell> auth, td::Ref<vm::Cell> header, vm::Dictionary d, unsigned mode = 0) {
  vm::CellBuilder b;
  b.store_long(mode == 1 ? 0 : native_evidence_tag, 32).store_long(mode == 2 ? 2 : 1, 16);
  if (mode == 3)
    b.store_long(0, 1);
  b.store_long(!d.is_empty(), 1).store_ref(auth).store_ref(header);
  if (!d.is_empty())
    b.store_ref(d.get_root_cell());
  if (mode == 4)
    b.store_ref(vm::CellBuilder().finalize());
  return b.finalize();
}
td::Ref<vm::Cell> authcell(const Authorizations& a) {
  return value(pack_bytes(value(encode(a), "fixture-auth")), "fixture-auth-cell");
}
td::Ref<vm::Cell> declaration(std::size_t n) {
  return vm::CellBuilder()
      .store_long(0x76616231, 32)
      .store_long(1, 16)
      .store_long(n, 32)
      .store_zeroes(256)
      .store_ref(vm::CellBuilder().finalize())
      .finalize();
}
Hash chunk_digest(const Hash& id, unsigned index, const Bytes& raw) {
  auto bytes = Bytes(id.begin(), id.end());
  bytes.push_back(static_cast<std::uint8_t>(index));
  bytes.insert(bytes.end(), raw.begin(), raw.end());
  return value(digest("object-chunk", bytes), "fixture-chunk-hash");
}
}  // namespace
int main(int argc, char** argv) {
  try {
    SET_VERBOSITY_LEVEL(0);
    check(argc == 3 || argc == 4, "arguments");
    std::filesystem::path input(argv[1]), out(argv[2]);
    // An optional case name. A mutation aimed at one case proves nothing while
    // an earlier case trips first on the same guard, so a harness has to be able
    // to ask for the case it named and no other.
    const std::string only = argc == 4 ? argv[3] : "";
    unsigned selected = 0;
    check(std::filesystem::create_directory(out), "fresh-output");
    auto chainraw = read(input / "0/chain");
    Reader cr(chainraw);
    ChainContext chain;
    cr.integer(chain.network);
    cr.hash(chain.genesis_root);
    cr.hash(chain.genesis_file);
    cr.hash(chain.chain_domain);
    check(cr.ok(), "fixture-chain");
    unsigned reads = 0;
    auto history =
        value(NativeFinalizedHistory::open(cell(read(input / "0/state")),
                                           value(decode<Anchor>(read(input / "0/head")), "fixture-head"), chain,
                                           [&](const tos::BlockIdExt&, std::size_t) -> Result<Bytes> {
                                             ++reads;
                                             return Error{"archive-offline"};
                                           },
                                           {0, 0}),
              "fixture-history");
    auto proof = cell(read(input / "0/proof"));
    auto anchor = value(decode<Anchor>(read(input / "0/result")), "fixture-anchor");
    auto empty = vm::CellBuilder().finalize();
    vm::Dictionary none(264);
    unsigned count = 0;
    auto run = [&](td::Ref<vm::Cell> root, const char* label, const char* error, unsigned reject_charge = 0,
                   bool owner = false) {
      if (!only.empty() && only != label)
        return;
      ++selected;
      auto folder = out / std::to_string(count++);
      check(std::filesystem::create_directory(folder), "case-dir");
      write(folder / "evidence", boc(root));
      std::ofstream(folder / "case") << label << ' ' << error << ' ' << reject_charge << ' ' << owner << '\n';
      std::vector<std::size_t> charges;
      auto result = NativeEvidence::open(root, [&](std::size_t n) -> Result<bool> {
        charges.push_back(n);
        if (charges.size() == reject_charge)
          return Error{"test-out-of-gas"};
        return true;
      });
      Result<bool> outcome = result.ok() ? Result<bool>(true) : Result<bool>(result.error());
      if (result.ok() && owner) {
        auto trusted = result.value().authenticate_owner(history);
        if (!trusted.ok())
          outcome = trusted.error();
        else
          check(trusted.value() == anchor, label);
      }
      if (std::string(error) == "-") {
        check(outcome.ok(), label);
        write(folder / "authorizations", value(encode(result.value().authorizations()), "fixture-result"));
      } else
        check(!outcome.ok() && outcome.error().code == error, label);
      if (std::string(label) == "evidence-first-charge")
        check(charges == std::vector<std::size_t>{12}, label);
      if (std::string(label) == "evidence-second-charge")
        check(charges == std::vector<std::size_t>({12, 0}), label);
      std::ofstream ch(folder / "charges");
      for (auto n : charges)
        ch << n << '\n';
      check(reads == 0, "evidence-no-io");
    };
    auto wrap = [&](const Authorizations& a, vm::Dictionary d) {
      return envelope(authcell(a), a.owner_.empty() ? empty : proof, std::move(d));
    };
    Authorizations a;
    run(wrap(a, none), "evidence-empty", "-");
    for (unsigned mode = 1; mode <= 4; ++mode)
      run(envelope(authcell(a), empty, none, mode),
          mode == 1   ? "evidence-tag"
          : mode == 2 ? "evidence-version"
          : mode == 3 ? "evidence-trailing"
                      : "evidence-reference-count",
          mode <= 2 ? "evidence-version" : "evidence-shape");
    run(envelope(authcell(a), vm::CellBuilder().store_long(1, 1).finalize(), none), "evidence-unused-header",
        "evidence-unused-header");
    run(envelope(declaration(native_authorizations_limit + 1), empty, none), "evidence-authorization-bound",
        "evidence-byte-bound");
    run(envelope(declaration(0), empty, none), "evidence-authorization-empty", "evidence-byte-bound");
    run(wrap(a, none), "evidence-first-charge", "test-out-of-gas", 1);
    run(wrap(a, none), "evidence-second-charge", "test-out-of-gas", 2);
    run(envelope(value(pack_bytes(Bytes(12, 0)), "fixture-invalid-auth"), empty, none),
        "evidence-charge-before-auth-decode", "test-out-of-gas", 1);
    run(wrap(a, none), "evidence-no-owner-authority", "evidence-owner-absent", 0, true);
    Bytes raw(65537, 3);
    auto obj = value(object_value(4, raw), "fixture-object");
    a.administration_.push_back({h(1), h(2), obj});
    auto chunks = attachments(obj, raw);
    run(wrap(a, chunks), "evidence-chunked-certificate", "-");
    run(wrap(a, none), "evidence-missing-chunk", "evidence-missing-chunk");
    auto wrong = chunks;
    auto k = key(h(999), 0);
    check(wrong.set_ref(td::ConstBitPtr(k.data()), 264, declaration(chunk_bytes + 1)), "fixture-extra");
    run(wrap(a, wrong), "evidence-unused-chunk-bound-first", "evidence-extra-chunk");
    auto originalkey = key(obj.reference_[0].object_id_, 0);
    wrong = none;
    check(wrong.set_ref(td::ConstBitPtr(k.data()), 264, value(pack_bytes(raw), "fixture-unknown-chunk")),
          "fixture-unknown");
    run(wrap(a, wrong), "evidence-unknown-chunk", "evidence-extra-chunk");
    wrong = none;
    k = key(obj.reference_[0].object_id_, 1);
    check(wrong.set_ref(td::ConstBitPtr(k.data()), 264, value(pack_bytes(raw), "fixture-index-chunk")),
          "fixture-index");
    run(wrap(a, wrong), "evidence-chunk-index", "evidence-extra-chunk");
    for (unsigned mode = 0; mode < 3; ++mode) {
      wrong = none;
      vm::CellBuilder b;
      if (mode == 0)
        b.store_long(0, 1).store_ref(value(pack_bytes(raw), "fixture-leaf"));
      if (mode == 1)
        b.store_ref(declaration(raw.size() - 1));
      if (mode == 2)
        b.store_ref(declaration(chunk_bytes + 1));
      check(wrong.set_builder(td::ConstBitPtr(originalkey.data()), 264, b), "fixture-bad-leaf");
      run(wrap(a, wrong),
          mode == 0   ? "evidence-chunk-leaf"
          : mode == 1 ? "evidence-chunk-declared-size"
                      : "evidence-chunk-byte-bound",
          mode == 0   ? "evidence-chunk-shape"
          : mode == 1 ? "evidence-chunk-length"
                      : "evidence-byte-bound");
    }
    wrong = none;
    auto changed = raw;
    changed[0] ^= 1;
    check(wrong.set_ref(td::ConstBitPtr(originalkey.data()), 264, value(pack_bytes(changed), "fixture-changed")),
          "fixture-changed-put");
    run(wrap(a, wrong), "evidence-chunk-digest", "chunk-hash");
    run(wrap(a, wrong), "evidence-charge-before-chunk-decode", "test-out-of-gas", 2);
    auto b = a;
    b.administration_[0].certificate_.reference_[0].object_id_ = h(31);
    b.administration_[0].certificate_.reference_[0].chunk_hashes_[0] = chunk_digest(h(31), 0, raw);
    run(wrap(b, attachments(b.administration_[0].certificate_, raw)), "evidence-whole-object-digest", "object-hash");
    b = a;
    b.administration_[0].certificate_.kind_ = 5;
    run(wrap(b, chunks), "evidence-object-type", "object-kind");
    b = a;
    b.administration_[0].certificate_.reference_[0].kind_ = 5;
    run(wrap(b, chunks), "evidence-manifest-type", "object-kind");
    b = a;
    b.administration_[0].certificate_.inline_ = {1};
    run(wrap(b, chunks), "evidence-dual-object", "object-representation");
    b = a;
    b.governance_.push_back({h(3), h(4), obj});
    run(wrap(b, chunks), "evidence-shared-object", "-");
    b.governance_[0].certificate_.reference_[0].chunk_hashes_[0] = h(1);
    run(wrap(b, chunks), "evidence-conflicting-manifest", "evidence-manifest-conflict");
    vm::CellBuilder noncanonical;
    noncanonical.store_long(0, 1);
    for (unsigned i = 0; i < 264; ++i)
      noncanonical.store_long(1, 1);
    noncanonical.store_long(0, 1)
        .store_bits(td::ConstBitPtr(originalkey.data()), 264)
        .store_ref(value(pack_bytes(raw), "fixture-label"));
    run(wrap(a, vm::Dictionary(td::Ref<vm::Cell>(noncanonical.finalize()), 264)), "evidence-nonminimal-dictionary",
        "evidence-dictionary");
    a = {};
    a.owner_.push_back(
        {h(1), h(2), -1, h(3), {anchor, 1, h(4), h(5), value(object_value(5, Bytes{1, 2, 3}), "fixture-proof")}});
    run(wrap(a, none), "evidence-authenticated-owner", "-", 0, true);
    for (unsigned mode = 0; mode < 3; ++mode) {
      b = a;
      auto& p = b.owner_[0].proof_.anchor_;
      if (mode == 0)
        p.file_[0] ^= 1;
      if (mode == 1)
        p.root_[0] ^= 1;
      if (mode == 2)
        p.state_[0] ^= 1;
      run(wrap(b, none),
          mode == 0   ? "evidence-anchor-file"
          : mode == 1 ? "evidence-anchor-root"
                      : "evidence-anchor-state",
          "evidence-owner-anchor", 0, true);
    }
    run(envelope(authcell(a), empty, none), "evidence-owner-header-required", "header-surface", 0, true);
    a.possession_.push_back({h(1), {}, Bytes(65536, 7)});
    a.owner_[0].proof_.proof_ = value(object_value(5, Bytes(65536, 1)), "fixture-inline-proof");
    a.administration_.push_back({h(1), h(2), value(object_value(4, Bytes(65536, 2)), "fixture-inline-admin")});
    a.governance_.push_back({h(1), h(2), value(object_value(4, Bytes(65536, 3)), "fixture-inline-gov")});
    run(wrap(a, none), "evidence-all-authorization-families", "-", 0, true);
    b = a;
    b.owner_[0].proof_.proof_ = {5, {}, {{5, 67108864, h(9), std::vector<Hash>(64, h(8))}}};
    run(wrap(b, none), "evidence-total-attachment-budget", "attachment-budget");
    a = {};
    raw.resize(chunk_bytes + 17, 7);
    obj = value(object_value(4, raw), "fixture-multichunk");
    a.administration_.push_back({h(1), h(2), obj});
    run(wrap(a, attachments(obj, raw)), "evidence-multiple-chunks", "-");

    // An owner proof big enough to be carried as chunks. Every owner proof above
    // is inline, so the chunk reader is never asked for one, and the path that
    // matters here is untested: with the chunks present the reader resolves the
    // proof, and with them removed the failure must name the missing chunk
    // rather than the proof. Losing storage and being handed a malformed proof
    // are different accusations, and the reader keeps them apart on purpose.
    a = {};
    Bytes owner_raw(inline_bytes + 1, 0x5a);
    auto owner_object = value(object_value(5, owner_raw), "fixture-owner-proof");
    a.owner_.push_back({h(1), h(2), -1, h(3), {anchor, 1, h(4), h(5), owner_object}});
    run(wrap(a, attachments(owner_object, owner_raw)), "evidence-chunked-owner-proof", "-", 0, true);
    run(wrap(a, none), "evidence-owner-proof-missing-chunk", "evidence-missing-chunk", 0, true);
    for (const char* name : {"state", "head", "chain"})
      write(out / name, read(input / "0" / name));
    write(out / "anchor", value(encode(anchor), "fixture-anchor-output"));
    std::ofstream(out / "complete") << count << '\n';
    // A name that matches nothing runs nothing and would otherwise report
    // success for a case that no longer exists.
    check(only.empty() || selected == 1, "selected-case");
    std::cout << "PASS: native evidence " << count << " cases\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
