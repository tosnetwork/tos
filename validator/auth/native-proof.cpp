#include "block/block-auto.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "vm/boc.h"
#include "vm/cells/CellSlice.h"
#include "vm/cells/MerkleProof.h"
#include "vm/dict.h"

#include "api-types.h"
#include "native-proof.h"
namespace tos::auth {
namespace {
using Response = std::variant<ProfileResult, PolicyResult, RegistryResult, KeyResult>;
struct Query {
  Response response;
  Hash object_id{};
  std::uint8_t kind = 0;
};
td::Slice slice(std::span<const std::uint8_t> b) {
  return {reinterpret_cast<const char*>(b.data()), b.size()};
}
bool hash_equal(const td::Ref<vm::Cell>& root, const Hash& expected) {
  return root.not_null() && root->get_hash().as_slice() == slice(expected);
}
Result<bool> anchor_valid(const Anchor& a) {
  if (a.seqno_ == std::numeric_limits<std::uint32_t>::max() || a.root_ == Hash{} || a.file_ == Hash{} ||
      a.state_ == Hash{})
    return Error{"anchor"};
  return true;
}
Result<vm::Dictionary> dictionary(td::Ref<vm::Cell> root) {
  if (root.is_null())
    return Error{"dictionary-shape"};
  vm::CellSlice s{vm::NoVm{}, root};
  if (!s.is_valid() || s.is_special() || s.size() != 1 || s.size_refs() != s.prefetch_ulong(1))
    return Error{"dictionary-shape"};
  return vm::Dictionary(s, 256);
}
template <class T>
Result<T> lookup(td::Ref<vm::Cell> root, const Hash& id, std::string_view domain) {
  auto dict = dictionary(root);
  if (!dict.ok())
    return dict.error();
  auto cell = dict.value().lookup_ref(td::ConstBitPtr(id.data()), 256);
  if (cell.is_null())
    return Error{"history-unavailable"};
  auto raw = unpack_bytes(cell);
  if (!raw.ok())
    return raw.error();
  auto value = decode<T>(raw.value());
  if (!value.ok())
    return value.error();
  auto hash = object_id(domain, value.value());
  if (!hash.ok())
    return hash.error();
  if (hash.value() != id)
    return Error{"entry-hash"};
  return value;
}
Result<Query> query(td::Ref<vm::Cell> root, const Anchor& anchor, std::int32_t network, std::uint8_t method,
                    std::span<const std::uint8_t> request) {
  auto valid = anchor_valid(anchor);
  if (!valid.ok())
    return valid.error();
  if (!hash_equal(root, anchor.state_))
    return Error{"state-root"};
  if (method < 8 || method > 11)
    return Error{"unsupported-method"};
  auto framing = validate_api_binary(method, false, false, request);
  if (!framing.ok())
    return framing.error();
  block::gen::ShardStateUnsplit::Record header;
  if (!::tlb::unpack_cell(root, header))
    return Error{"masterchain-state"};
  block::ShardId shard(header.shard_id);
  if (header.global_id != network || header.seq_no != anchor.seqno_ || shard.workchain_id != -1 ||
      shard.shard_pfx_len != 0)
    return Error{"state-context"};
  auto config = block::Config::extract_from_state(root);
  if (config.is_error())
    return Error{"native-config"};
  auto param8 = config.ok()->get_config_param(8);
  vm::CellSlice cap{vm::NoVm{}, param8};
  if (!cap.is_valid() || cap.is_special() || cap.size() != 104 || cap.size_refs() != 0 || cap.fetch_ulong(8) != 0xc4)
    return Error{"config-capability"};
  cap.fetch_ulong(32);
  if (!(cap.fetch_ulong(64) & 1024))
    return Error{"config-capability"};
  for (int index : {9, 10}) {
    auto cell = config.ok()->get_config_param(index);
    if (cell.is_null())
      return Error{"config-mandatory"};
    vm::Dictionary required(cell, 32);
    auto entry = required.lookup(td::ConstBitPtr(std::array<std::uint8_t, 4>{0, 0, 0, 46}.data()), 32);
    if (entry.is_null() || entry->size() != 0 || entry->size_refs() != 0)
      return Error{"config-mandatory"};
  }
  vm::CellSlice count{vm::NoVm{}, config.ok()->get_config_param(16)};
  if (!count.is_valid() || count.is_special() || count.size() != 48 || count.size_refs() != 0)
    return Error{"validator-count"};
  auto maximum = count.fetch_ulong(16), main = count.fetch_ulong(16), minimum = count.fetch_ulong(16);
  if (maximum > 400 || maximum < main || main < minimum || minimum < 1)
    return Error{"validator-count"};
  vm::CellSlice p0{vm::NoVm{}, config.ok()->get_config_param(46)};
  if (!p0.is_valid() || p0.is_special() || p0.size() != 880 || p0.size_refs() != 4 ||
      p0.fetch_ulong(32) != 0x76617131 || p0.fetch_ulong(16) != 1)
    return Error{"config46-shape"};
  Hash chain_domain{}, fingerprint{}, policy_id{};
  if (!p0.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(chain_domain.data()), 32)) || chain_domain == Hash{} ||
      !p0.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(fingerprint.data()), 32)) ||
      fingerprint != interface_fingerprint)
    return Error{"interface-digest"};
  p0.fetch_ulong(64);
  if (!p0.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(policy_id.data()), 32)))
    return Error{"config46-shape"};
  auto identities = p0.fetch_ref(), keys = p0.fetch_ref(), policies = p0.fetch_ref();
  auto selected = lookup<Policy>(policies, policy_id, "policy");
  if (!selected.ok())
    return selected.error();
  const auto& policy = selected.value();
  if (policy.phase_ != 0 || policy.suites_ != std::vector<Suite>{{1, 1}} || policy.interface_digest_ != fingerprint ||
      policy.effective_from_ > anchor.seqno_ || policy.max_envelope_ != 4096 || policy.max_certificate_ != 524288)
    return Error{"unsupported-profile"};
  if (method == 8) {
    auto req = decode<GetProfileRequest>(request);
    if (!req.ok())
      return req.error();
    if (req.value().anchor_ != anchor)
      return Error{"request-anchor"};
    ProfileState state{fingerprint, policy_id, policy.suites_};
    auto id = object_id("profile_state", state);
    if (!id.ok())
      return id.error();
    return Query{ProfileResult{anchor, fingerprint, policy_id, {{1, 1}}, policy.suites_, 1, 1, {}}, id.value(), 6};
  }
  if (method == 9) {
    auto req = decode<GetPolicyRequest>(request);
    if (!req.ok())
      return req.error();
    if (req.value().anchor_ != anchor)
      return Error{"request-anchor"};
    auto value = lookup<Policy>(policies, req.value().policy_id_, "policy");
    if (!value.ok())
      return value.error();
    return Query{PolicyResult{anchor, value.value(), {}}, req.value().policy_id_, 2};
  }
  if (method == 11) {
    auto req = decode<GetKeyRequest>(request);
    if (!req.ok())
      return req.error();
    if (req.value().anchor_ != anchor)
      return Error{"request-anchor"};
    auto value = lookup<Key>(keys, req.value().key_id_, "key");
    if (!value.ok())
      return value.error();
    return Query{KeyResult{anchor, value.value(), {}}, req.value().key_id_, 4};
  }
  auto req = decode<GetRegistryRequest>(request);
  if (!req.ok())
    return req.error();
  if (req.value().anchor_ != anchor)
    return Error{"request-anchor"};
  if (req.value().limit_ < 1 || req.value().limit_ > 128)
    return Error{"page-limit"};
  auto encoded_anchor = encode(anchor);
  if (!encoded_anchor.ok())
    return encoded_anchor.error();
  encoded_anchor.value().push_back(req.value().limit_);
  auto qid = digest("registry-query", encoded_anchor.value());
  if (!qid.ok())
    return qid.error();
  Hash start{};
  if (!req.value().cursor_.empty()) {
    const auto& cursor = req.value().cursor_[0];
    if (cursor.anchor_ != anchor || cursor.query_id_ != qid.value() || cursor.last_identity_ == Hash{})
      return Error{"cursor-binding"};
    start = cursor.last_identity_;
  }
  auto dict = dictionary(identities);
  if (!dict.ok())
    return dict.error();
  RegistryResult page{anchor, qid.value(), {}, {}, {}};
  Hash cursor = start;
  bool more = false;
  for (unsigned n = 0; n <= req.value().limit_; ++n) {
    auto leaf = dict.value().lookup_nearest_key(td::BitPtr(cursor.data()), 256, true, false);
    if (leaf.is_null())
      break;
    if (leaf->size() != 0 || leaf->size_refs() != 1 || cursor == Hash{})
      return Error{"identity-entry"};
    if (n == req.value().limit_) {
      more = true;
      break;
    }
    auto raw = unpack_bytes(leaf->prefetch_ref());
    if (!raw.ok())
      return raw.error();
    auto state = decode<Identity>(raw.value());
    if (!state.ok())
      return state.error();
    if (state.value().identity_ != cursor)
      return Error{"identity-key"};
    page.identities_.push_back(state.value());
  }
  if (more) {
    if (page.identities_.empty())
      return Error{"page-shape"};
    page.cursor_.push_back({anchor, qid.value(), page.identities_.back().identity_});
  }
  Writer writer;
  writer.bytes(qid.value());
  writer.bytes(start);
  writer.list(page.identities_, 1, 128);
  writer.list(page.cursor_, 1, 1);
  if (!writer.ok())
    return Error{writer.error};
  auto id = digest("registry-page", writer.data);
  if (!id.ok())
    return id.error();
  return Query{std::move(page), id.value(), 3};
}
Result<Bytes> finish(Query& result, const Proofref& proof) {
  return std::visit(
      [&](auto& value) -> Result<Bytes> {
        value.proof_ = proof;
        auto bytes = encode(value);
        if (!bytes.ok())
          return bytes.error();
        if (bytes.value().size() > 2000000)
          return Error{"api-binary-bound"};
        return bytes;
      },
      result.response);
}
Result<Proofref> response_proof(std::uint8_t method, std::span<const std::uint8_t> raw) {
  if (raw.size() > 2000000)
    return Error{"api-binary-bound"};
  switch (method) {
    case 8: {
      auto v = decode<ProfileResult>(raw);
      if (!v.ok())
        return v.error();
      return v.value().proof_;
    }
    case 9: {
      auto v = decode<PolicyResult>(raw);
      if (!v.ok())
        return v.error();
      return v.value().proof_;
    }
    case 10: {
      auto v = decode<RegistryResult>(raw);
      if (!v.ok())
        return v.error();
      return v.value().proof_;
    }
    case 11: {
      auto v = decode<KeyResult>(raw);
      if (!v.ok())
        return v.error();
      return v.value().proof_;
    }
    default:
      return Error{"unsupported-method"};
  }
}
Result<td::Ref<vm::Cell>> read_proof(std::span<const std::uint8_t> raw) {
  if (raw.empty() || raw.size() > 67108864)
    return Error{"proof-bound"};
  vm::BagOfCells::Info info;
  auto size = info.parse_serialized_header(slice(raw).substr(0, std::min<std::size_t>(256, raw.size())));
  if (size <= 0 || static_cast<std::size_t>(size) != raw.size() || info.root_count != 1 || info.cell_count <= 0 ||
      info.cell_count > 400001 || info.absent_count != 0)
    return Error{"proof-header"};
  vm::BagOfCells boc;
  auto consumed = boc.deserialize(slice(raw), 1);
  if (consumed.is_error() || consumed.ok() != static_cast<long long>(raw.size()) || boc.get_root_count() != 1)
    return Error{"proof-boc"};
  vm::CellStorageStat reachable(info.cell_count);
  auto walked = reachable.compute_used_storage(boc.get_root_cell());
  if (walked.is_error() || reachable.cells != static_cast<unsigned>(info.cell_count))
    return Error{"proof-unreachable-cells"};
  return boc.get_root_cell();
}
}  // namespace
Result<Bytes> make_native_response(td::Ref<vm::Cell> root, const Anchor& anchor, std::int32_t network,
                                   std::uint8_t method, std::span<const std::uint8_t> request,
                                   ObjectPublisher publisher) {
  if (request.size() > 2000000)
    return Error{"api-binary-bound"};
  try {
    vm::MerkleProofBuilder builder(root);
    auto result = query(builder.root(), anchor, network, method, request);
    if (!result.ok())
      return result.error();
    auto proof = builder.extract_proof_boc();
    if (proof.is_error())
      return Error{"proof-generation"};
    auto raw = proof.ok().as_slice();
    auto span = std::span<const std::uint8_t>(raw.ubegin(), raw.size());
    auto id = digest("proof", span);
    if (!id.ok())
      return id.error();
    auto object = object_value(5, span);
    if (!object.ok())
      return object.error();
    if (!object.value().reference_.empty()) {
      if (!publisher)
        return Error{"proof-needs-object-store"};
      auto published = publisher(object.value().reference_[0], span);
      if (!published.ok())
        return published.error();
      if (!published.value())
        return Error{"proof-publication"};
    }
    Proofref ref{anchor, result.value().kind, result.value().object_id, id.value(), object.value()};
    return finish(result.value(), ref);
  } catch (const vm::VmError&) {
    return Error{"native-proof"};
  } catch (const vm::VmVirtError&) {
    return Error{"incomplete-proof"};
  }
}
Result<VerifiedNativeResponse> verify_native_response(std::uint8_t method, std::span<const std::uint8_t> request,
                                                      std::span<const std::uint8_t> response, const Anchor& anchor,
                                                      std::int32_t network, ObjectReader& reader) {
  if (request.size() > 2000000 || response.size() > 2000000)
    return Error{"api-binary-bound"};
  try {
    auto proof = response_proof(method, response);
    if (!proof.ok())
      return proof.error();
    if (proof.value().anchor_ != anchor)
      return Error{"proof-anchor"};
    auto raw = reader.resolve(proof.value().proof_, 5);
    if (!raw.ok())
      return raw.error();
    auto hash = digest("proof", raw.value());
    if (!hash.ok())
      return hash.error();
    if (hash.value() != proof.value().proof_hash_)
      return Error{"proof-hash"};
    auto cell = read_proof(raw.value());
    if (!cell.ok())
      return cell.error();
    auto virtualized = vm::MerkleProof::virtualize(cell.value());
    if (virtualized.is_error())
      return Error{"proof-merkle"};
    vm::MerkleProofBuilder used(virtualized.ok());
    auto expected = query(used.root(), anchor, network, method, request);
    if (!expected.ok())
      return expected.error();
    if (proof.value().kind_ != expected.value().kind || proof.value().object_id_ != expected.value().object_id)
      return Error{"proof-object"};
    auto minimal = used.extract_proof();
    if (minimal.is_error() || minimal.ok()->get_hash() != cell.value()->get_hash())
      return Error{"proof-unrelated-values"};
    auto canonical = finish(expected.value(), proof.value());
    if (!canonical.ok())
      return canonical.error();
    if (canonical.value().size() != response.size() ||
        !std::equal(canonical.value().begin(), canonical.value().end(), response.begin()))
      return Error{"response-association"};
    return VerifiedNativeResponse{std::move(canonical.value()), anchor, method};
  } catch (const vm::VmError&) {
    return Error{"native-proof"};
  } catch (const vm::VmVirtError&) {
    return Error{"incomplete-proof"};
  }
}
}  // namespace tos::auth
