#include <set>

#include "block/block-auto.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "tos/tos-shard.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"

#include "owner-proof.h"
#include "registry-view.h"
namespace tos::auth {
namespace {
td::Slice slice(const Hash& h) {
  return {reinterpret_cast<const char*>(h.data()), h.size()};
}
Hash cell_hash(const td::Ref<vm::Cell>& root) {
  Hash h{};
  auto owned = root->get_hash();
  auto raw = owned.as_slice();
  std::copy(raw.ubegin(), raw.uend(), h.begin());
  return h;
}
Result<Hash> binding(const ChainContext& chain, const Update& update, const Identity& current) {
  if (chain.genesis_root == Hash{} || chain.genesis_file == Hash{} || chain.chain_domain == Hash{})
    return Error{"chain-context"};
  if ((update.operation_ != 1 && update.operation_ != 2 && update.operation_ != 5) || update.identity_ == Hash{} ||
      update.identity_ != current.identity_ || current.stake_id_ == Hash{})
    return Error{"owner-target"};
  return object_id("update", update);
}
bool address(td::Ref<vm::CellSlice> cell, std::int32_t workchain, const Hash& expected) {
  // Anycast would introduce a second account interpretation for the same proof.
  auto s = *cell;
  auto tag = s.fetch_ulong(2);
  if ((tag != 2 && tag != 3) || s.fetch_ulong(1) != 0)
    return false;
  if (tag == 3 && s.fetch_ulong(9) != 256)
    return false;
  auto wc = s.fetch_long(tag == 2 ? 8 : 32);
  Hash id{};
  return wc == workchain && s.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(id.data()), id.size())) &&
         id == expected && s.empty_ext();
}
Result<Hash> executed(td::Ref<vm::Cell> state, td::Ref<vm::Cell> block_root, const Anchor& anchor,
                      const ChainContext& chain, const Update& update, const Identity& current, std::uint64_t lt,
                      std::uint16_t index) {
  auto uid = binding(chain, update, current);
  if (!uid.ok())
    return uid.error();
  if (anchor.seqno_ == 0 || anchor.seqno_ == UINT32_MAX || anchor.root_ == Hash{} || anchor.file_ == Hash{} ||
      state.is_null() || cell_hash(state) != anchor.state_)
    return Error{"owner-anchor"};
  block::gen::ShardStateUnsplit::Record header;
  if (!tlb::unpack_cell(state, header))
    return Error{"masterchain-state"};
  block::ShardId mc(header.shard_id);
  if (header.global_id != chain.network || header.seq_no != anchor.seqno_ || mc.workchain_id != -1 ||
      mc.shard_pfx_len != 0)
    return Error{"state-context"};
  auto config = block::Config::extract_from_state(state);
  if (config.is_error())
    return Error{"native-config"};
  vm::CellSlice caps{vm::NoVm{}, config.ok()->get_config_param(8)};
  if (!caps.is_valid() || caps.is_special() || caps.size() != 104 || caps.size_refs() != 0 ||
      caps.fetch_ulong(8) != 0xc4 || caps.fetch_ulong(32) < 16 || !(caps.fetch_ulong(64) & 1024))
    return Error{"owner-capability"};
  auto registry = RegistryView::open(config.ok()->get_config_param(46), anchor.seqno_);
  if (!registry.ok())
    return registry.error();
  if (registry.value().chain_domain() != chain.chain_domain)
    return Error{"chain-domain"};
  auto allocated = registry.value().identity(current.identity_);
  if (!allocated.ok())
    return allocated.error();
  if (allocated.value().stake_id_ != current.stake_id_ ||
      allocated.value().owner_workchain_ != current.owner_workchain_ ||
      allocated.value().owner_address_ != current.owner_address_)
    return Error{"owner-allocation"};
  vm::CellSlice elector{vm::NoVm{}, config.ok()->get_config_param(1)};
  Hash recipient{};
  if (!elector.is_valid() || elector.is_special() || elector.size() != 256 || elector.size_refs() != 0 ||
      !elector.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(recipient.data()), recipient.size())) ||
      recipient == Hash{})
    return Error{"owner-recipient"};
  block::gen::Block::Record native_block;
  block::gen::BlockInfo::Record info;
  if (!tlb::unpack_cell(block_root, native_block) || !tlb::unpack_cell(native_block.info, info))
    return Error{"owner-block"};
  block::ShardId shard(info.shard);
  tos::Bits256 owner{td::ConstBitPtr(current.owner_address_.data())};
  if (native_block.global_id != chain.network || shard.workchain_id != current.owner_workchain_ ||
      !tos::shard_contains(shard.shard_pfx, owner))
    return Error{"owner-block-context"};
  if (current.owner_workchain_ == -1) {
    if (shard.shard_pfx_len != 0 || info.seq_no != anchor.seqno_ || cell_hash(block_root) != anchor.root_)
      return Error{"owner-block-anchor"};
    vm::CellSlice change{vm::NoVm{}, native_block.state_update};
    if (!change.is_special() || change.prefetch_ulong(8) != 4 || change.size_ext() != 0x20228 ||
        cell_hash(change.prefetch_ref(1)) != anchor.state_)
      return Error{"owner-state-update"};
  } else {
    auto shards = block::ShardConfig::extract_shard_hashes_dict(state);
    vm::CellSlice desc;
    tos::ShardIdFull actual;
    tos::ShardIdFull expected{shard.workchain_id, shard.shard_pfx};
    if (!shards || !block::ShardConfig::get_shard_hash_raw_from(*shards, desc, expected, actual) || actual != expected)
      return Error{"owner-shard-anchor"};
    auto top = block::McShardHash::unpack(desc, actual);
    if (top.is_null() || top->top_block_id().seqno() != info.seq_no ||
        top->top_block_id().root_hash.as_slice() != block_root->get_hash().as_slice())
      return Error{"owner-shard-anchor"};
  }
  auto found = block::get_block_transaction(block_root, current.owner_workchain_, owner, lt);
  if (found.is_error() || found.ok().is_null())
    return Error{"owner-transaction"};
  block::gen::Transaction::Record transaction;
  if (!tlb::unpack_cell(found.ok(), transaction) || transaction.account_addr != owner || transaction.lt != lt)
    return Error{"owner-transaction-binding"};
  block::gen::TransactionDescr::Record_trans_ord ordinary;
  block::gen::TrComputePhase::Record_tr_phase_compute_vm compute;
  block::gen::TrActionPhase::Record action;
  if (!tlb::unpack_cell(transaction.description, ordinary) || !tlb::csr_unpack(ordinary.compute_ph, compute) ||
      !compute.success || ordinary.aborted || ordinary.destroyed || ordinary.action->size_refs() != 1 ||
      !tlb::unpack_cell(ordinary.action->prefetch_ref(), action) || !action.success || !action.valid ||
      action.no_funds || action.result_code != 0)
    return Error{"owner-execution"};
  if (index >= transaction.outmsg_cnt || action.msgs_created != transaction.outmsg_cnt)
    return Error{"owner-message-index"};
  auto message_root = vm::Dictionary(transaction.r1.out_msgs, 15).lookup_ref(td::BitArray<15>{index});
  block::gen::Message::Record message;
  block::gen::CommonMsgInfo::Record_int_msg_info message_info;
  if (message_root.is_null() || !tlb::type_unpack_cell(message_root, block::gen::t_Message_Any, message) ||
      !tlb::csr_unpack(message.info, message_info) || message_info.bounced || !message_info.ihr_disabled ||
      !address(message_info.src, current.owner_workchain_, current.owner_address_) ||
      !address(message_info.dest, -1, recipient) || message.init->size() != 1 || message.init->prefetch_ulong(1) != 0)
    return Error{"owner-message"};
  if (lt > UINT64_MAX - 1 - index || message_info.created_lt != lt + 1 + index)
    return Error{"owner-message-time"};
  auto expected_body = owner_approval_body(chain, update, current);
  if (!expected_body.ok())
    return expected_body.error();
  auto body = *message.body;
  if (body.fetch_ulong(1) != 1 || body.size() != 0 || body.size_refs() != 1 ||
      body.fetch_ref()->get_hash() != expected_body.value()->get_hash())
    return Error{"owner-approval"};
  // Reveal the bounded approval body so a peer cannot replace it by a pruned
  // hash while still advertising an execution proof as self-contained evidence.
  auto body_cell = message.body->prefetch_ref();
  vm::CellSlice reveal{vm::NoVm{}, body_cell};
  if (reveal.is_special() || reveal.size() != 816 || reveal.size_refs() != 0)
    return Error{"owner-approval"};
  return cell_hash(found.ok());
}
Result<td::Ref<vm::Cell>> canonical_proof(const vm::MerkleProofBuilder& used) {
  std::set<vm::Cell::Hash> loaded;
  const auto& usage = used.get_usage_tree();
  std::function<void(td::Ref<vm::Cell>, vm::CellUsageTree::NodeId)> collect = [&](auto cell, auto node) {
    if (!usage.is_loaded(node))
      return;
    loaded.insert(cell->get_hash());
    vm::CellSlice s{vm::NoVm{}, cell};
    for (unsigned i = 0; i < s.size_refs(); ++i)
      collect(s.prefetch_ref(i), usage.get_child(node, i));
  };
  collect(used.original_root(), usage.root_id());
  std::map<std::pair<vm::Cell::Hash, unsigned>, td::Ref<vm::Cell>> memo;
  std::function<Result<td::Ref<vm::Cell>>(td::Ref<vm::Cell>, unsigned, unsigned)> build =
      [&](auto cell, unsigned depth, unsigned height) -> Result<td::Ref<vm::Cell>> {
    auto key = std::make_pair(cell->get_hash(), depth);
    auto old = memo.find(key);
    if (old != memo.end())
      return old->second;
    if (height > 1024 || memo.size() >= 400001 || depth > 3)
      return Error{"proof-pruning-bound"};
    td::Ref<vm::Cell> result;
    // An existing lower-level pruned branch is native data committed by an
    // enclosing Merkle update. Its higher hash cannot be replaced by a new prune.
    if (!cell->is_virtualized() && cell->get_level() <= depth && cell->get_level() != 0) {
      vm::CellSlice s{vm::NoVm{}, cell};
      if (s.special_type() == vm::Cell::SpecialType::PrunnedBranch)
        result = cell;
    }
    if (result.is_null() && !loaded.contains(cell->get_hash())) {
      if (depth >= 3)
        return Error{"proof-pruning-bound"};
      result = vm::CellBuilder::do_create_pruned_branch(cell, depth + 1);
    }
    if (result.is_null()) {
      vm::CellSlice s{vm::NoVm{}, cell};
      vm::CellBuilder b;
      b.store_bits(s.fetch_bits(s.size()));
      auto child_depth = s.child_merkle_depth(depth);
      for (unsigned i = 0; i < s.size_refs(); ++i) {
        auto child = build(s.prefetch_ref(i), child_depth, height + 1);
        if (!child.ok())
          return child.error();
        b.store_ref(child.value());
      }
      result = b.finalize(s.is_special());
    }
    memo.emplace(key, result);
    return result;
  };
  auto root = build(used.original_root(), 0, 0);
  if (!root.ok())
    return root.error();
  return td::Ref<vm::Cell>(vm::CellBuilder::create_merkle_proof(root.value()));
}
Result<td::Ref<vm::Cell>> read_proof(std::span<const std::uint8_t> raw) {
  if (raw.empty() || raw.size() > 67108864)
    return Error{"proof-bound"};
  td::Slice bytes(reinterpret_cast<const char*>(raw.data()), raw.size());
  vm::BagOfCells::Info info;
  auto length = info.parse_serialized_header(bytes.substr(0, std::min<std::size_t>(256, raw.size())));
  if (length <= 0 || static_cast<std::size_t>(length) != raw.size() || info.root_count != 1 || info.cell_count <= 0 ||
      info.cell_count > 400001 || info.absent_count != 0)
    return Error{"proof-header"};
  vm::BagOfCells boc;
  auto parsed = boc.deserialize(bytes, 1);
  if (parsed.is_error() || parsed.ok() != static_cast<long long>(raw.size()))
    return Error{"proof-boc"};
  vm::CellStorageStat reachable(info.cell_count);
  auto walked = reachable.compute_used_storage(boc.get_root_cell());
  if (walked.is_error() || reachable.cells != static_cast<unsigned>(info.cell_count))
    return Error{"proof-unreachable-cells"};
  return boc.get_root_cell();
}
}  // namespace
Result<td::Ref<vm::Cell>> owner_approval_body(const ChainContext& chain, const Update& update,
                                              const Identity& current) {
  auto id = binding(chain, update, current);
  if (!id.ok())
    return id.error();
  vm::CellBuilder body;
  body.store_long(owner_approval_tag, 32)
      .store_long(1, 16)
      .store_bytes(slice(chain.chain_domain))
      .store_bytes(slice(current.stake_id_))
      .store_bytes(slice(id.value()));
  return td::Ref<vm::Cell>(body.finalize());
}
#ifdef TOS_VALIDATOR_AUTH_TEST_PRODUCER
Result<OwnerAuth> make_owner_execution_proof(td::Ref<vm::Cell> state, td::Ref<vm::Cell> block, const Anchor& anchor,
                                             const ChainContext& chain, const Update& update, const Identity& current,
                                             std::uint64_t lt, std::uint16_t index, ObjectPublisher publisher) {
  try {
    vm::MerkleProofBuilder used_state(state), used_block(block);
    auto verified = executed(used_state.root(), used_block.root(), anchor, chain, update, current, lt, index);
    if (!verified.ok())
      return verified.error();
    auto state_proof = canonical_proof(used_state), block_proof = canonical_proof(used_block);
    if (!state_proof.ok() || !block_proof.ok())
      return Error{"proof-generation"};
    vm::CellBuilder header;
    header.store_long(owner_proof_tag, 32)
        .store_long(1, 16)
        .store_long(lt, 64)
        .store_long(index, 15)
        .store_ref(state_proof.value())
        .store_ref(block_proof.value());
    auto raw = vm::std_boc_serialize(header.finalize());
    if (raw.is_error())
      return Error{"proof-generation"};
    std::span<const std::uint8_t> bytes(raw.ok().as_slice().ubegin(), raw.ok().size());
    auto carrier = object_value(5, bytes);
    auto hash = digest("proof", bytes);
    auto id = object_id("update", update);
    if (!carrier.ok())
      return carrier.error();
    if (!hash.ok())
      return hash.error();
    if (!id.ok())
      return id.error();
    if (!carrier.value().reference_.empty()) {
      if (!publisher)
        return Error{"proof-needs-object-store"};
      auto published = publisher(carrier.value().reference_[0], bytes);
      if (!published.ok())
        return published.error();
      if (!published.value())
        return Error{"proof-publication"};
    }
    return OwnerAuth{id.value(),
                     current.stake_id_,
                     current.owner_workchain_,
                     current.owner_address_,
                     {anchor, 1, id.value(), hash.value(), carrier.value()}};
  } catch (const vm::VmError&) {
    return Error{"owner-proof"};
  } catch (const vm::VmVirtError&) {
    return Error{"incomplete-proof"};
  }
}
#endif
Result<VerifiedOwnerExecution> verify_owner_execution(const OwnerAuth& auth, const Update& update,
                                                      const Identity& current, const Anchor& anchor,
                                                      const ChainContext& chain, ObjectReader& reader) {
  try {
    auto id = binding(chain, update, current);
    if (!id.ok())
      return id.error();
    if (auth.update_id_ != id.value() || auth.stake_id_ != current.stake_id_ ||
        auth.owner_workchain_ != current.owner_workchain_ || auth.owner_address_ != current.owner_address_)
      return Error{"owner-binding"};
    const auto& proof = auth.proof_;
    if (proof.anchor_ != anchor)
      return Error{"proof-anchor"};
    if (proof.kind_ != 1)
      return Error{"proof-kind"};
    if (proof.object_id_ != id.value())
      return Error{"proof-object"};
    auto raw = reader.resolve(proof.proof_, 5);
    if (!raw.ok())
      return raw.error();
    auto hash = digest("proof", raw.value());
    if (!hash.ok())
      return hash.error();
    if (hash.value() != proof.proof_hash_)
      return Error{"proof-hash"};
    auto parsed = read_proof(raw.value());
    if (!parsed.ok())
      return parsed.error();
    vm::CellSlice header{vm::NoVm{}, parsed.value()};
    if (header.is_special() || header.size() != 127 || header.size_refs() != 2 ||
        header.fetch_ulong(32) != owner_proof_tag || header.fetch_ulong(16) != 1)
      return Error{"owner-proof-header"};
    auto lt = header.fetch_ulong(64);
    auto index = static_cast<std::uint16_t>(header.fetch_ulong(15));
    auto state_proof = header.fetch_ref(), block_proof = header.fetch_ref();
    auto state = vm::MerkleProof::virtualize(state_proof), block = vm::MerkleProof::virtualize(block_proof);
    if (state.is_error() || block.is_error())
      return Error{"proof-merkle"};
    vm::MerkleProofBuilder used_state(state.ok()), used_block(block.ok());
    auto verified = executed(used_state.root(), used_block.root(), anchor, chain, update, current, lt, index);
    if (!verified.ok())
      return verified.error();
    auto minimal_state = canonical_proof(used_state), minimal_block = canonical_proof(used_block);
    if (!minimal_state.ok() || !minimal_block.ok() || minimal_state.value()->get_hash() != state_proof->get_hash() ||
        minimal_block.value()->get_hash() != block_proof->get_hash())
      return Error{"proof-unrelated-values"};
    return VerifiedOwnerExecution{id.value(), verified.value(), anchor};
  } catch (const vm::VmError&) {
    return Error{"owner-proof"};
  } catch (const vm::VmVirtError&) {
    return Error{"incomplete-proof"};
  }
}
}  // namespace tos::auth
