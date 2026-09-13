#include <sodium.h>

#include "block/block-auto.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "tos/tos-shard.h"
#include "vm/boc.h"

#include "native-history.h"
#include "registry-view.h"
namespace tos::auth {
namespace {
Hash hash(td::Slice raw) {
  Hash value{};
  if (raw.size() == value.size())
    std::copy(raw.ubegin(), raw.uend(), value.begin());
  return value;
}
td::Bits256 bits(const Hash& h) {
  return td::Bits256(td::ConstBitPtr(h.data()));
}
Result<td::Ref<vm::Cell>> block_boc(std::span<const std::uint8_t> raw) {
  td::Slice bytes(reinterpret_cast<const char*>(raw.data()), raw.size());
  vm::BagOfCells::Info info;
  auto size = info.parse_serialized_header(bytes.substr(0, std::min<std::size_t>(256, raw.size())));
  if (size <= 0 || static_cast<std::size_t>(size) != raw.size() || info.root_count != 1 || info.cell_count <= 0 ||
      info.cell_count > 400001 || info.absent_count != 0)
    return Error{"history-boc-header"};
  vm::BagOfCells boc;
  auto parsed = boc.deserialize(bytes, 1);
  if (parsed.is_error() || parsed.ok() != static_cast<long long>(raw.size()))
    return Error{"history-boc"};
  vm::CellStorageStat reachable(info.cell_count);
  auto walked = reachable.compute_used_storage(boc.get_root_cell());
  if (walked.is_error() || reachable.cells != static_cast<unsigned>(info.cell_count))
    return Error{"history-unreachable-cells"};
  return boc.get_root_cell();
}
}  // namespace
NativeFinalizedHistory::NativeFinalizedHistory() = default;
NativeFinalizedHistory::~NativeFinalizedHistory() = default;
NativeFinalizedHistory::NativeFinalizedHistory(NativeFinalizedHistory&&) noexcept = default;
NativeFinalizedHistory& NativeFinalizedHistory::operator=(NativeFinalizedHistory&&) noexcept = default;
Result<NativeFinalizedHistory> NativeFinalizedHistory::open(td::Ref<vm::Cell> root, const Anchor& head,
                                                            const ChainContext& chain, NativeBlockReader read,
                                                            HistoryReadBudget budget) {
  try {
    if (root.is_null() || root->get_level() != 0 || head.seqno_ == UINT32_MAX || head.root_ == Hash{} ||
        head.file_ == Hash{} || head.state_ != hash(root->get_hash().as_slice()))
      return Error{"history-anchor"};
    if (chain.genesis_root == Hash{} || chain.genesis_file == Hash{} || chain.chain_domain == Hash{})
      return Error{"chain-context"};
    tos::BlockIdExt id{{tos::masterchainId, tos::shardIdAll, head.seqno_}, bits(head.root_), bits(head.file_)};
    auto config = block::ConfigInfo::extract_config(
        root, id, block::ConfigInfo::needPrevBlocks | block::Config::needCapabilities);
    if (config.is_error())
      return Error{"history-native-state"};
    const auto& cfg = *config.ok();
    if (cfg.get_global_blockchain_id() != chain.network)
      return Error{"history-network"};
    auto zero = cfg.get_zerostate_id();
    if (hash(zero.root_hash.as_slice()) != chain.genesis_root ||
        hash(zero.file_hash.as_slice()) != chain.genesis_file || (head.seqno_ == 0 && head.root_ != head.state_))
      return Error{"history-genesis"};
    if (cfg.get_global_version() < 16 || !(cfg.get_capabilities() & tos::capValidatorAuth))
      return Error{"history-capability"};
    auto registry = RegistryView::open(cfg.get_config_param(46), head.seqno_);
    if (!registry.ok())
      return registry.error();
    if (registry.value().chain_domain() != chain.chain_domain)
      return Error{"history-domain"};
    NativeFinalizedHistory result;
    result.config_ = config.move_as_ok();
    result.head_ = head;
    result.chain_ = chain;
    result.read_ = std::move(read);
    result.budget_ = budget;
    return result;
  } catch (const vm::VmError&) {
    return Error{"history-native-state"};
  } catch (const vm::VmVirtError&) {
    return Error{"history-pruned"};
  }
}
Result<Anchor> NativeFinalizedHistory::finalized_anchor(std::uint32_t at) const {
  try {
    if (at > head_.seqno_ || at == UINT32_MAX)
      return Error{"history-future"};
    if (at == head_.seqno_)
      return head_;
    if (auto found = cache_.find(at); found != cache_.end())
      return found->second;
    tos::BlockIdExt id;
    if (!config_->get_old_mc_block_id(at, id) || id.seqno() != at || !id.is_masterchain() ||
        id.id.shard != tos::shardIdAll || id.root_hash.is_zero() || id.file_hash.is_zero())
      return Error{"finalized-anchor-unavailable"};
    if (at == 0)
      return Anchor{0, chain_.genesis_root, chain_.genesis_file, chain_.genesis_root};
    if (budget_.blocks == 0 || budget_.bytes == 0)
      return Error{"history-resource"};
    --budget_.blocks;
    if (!read_)
      return Error{"history-block-unavailable"};
    auto maximum = std::min<std::size_t>(67108864, budget_.bytes);
    auto bytes = read_(id, maximum);
    if (!bytes.ok())
      return bytes.error();
    const auto& raw = bytes.value();
    if (raw.empty() || raw.size() > maximum)
      return Error{"history-block-bound"};
    budget_.bytes -= raw.size();
    Hash file{};
    if (crypto_hash_sha256(file.data(), raw.data(), raw.size()) != 0)
      return Error{"hash-backend"};
    if (file != hash(id.file_hash.as_slice()))
      return Error{"history-file-hash"};
    auto root = block_boc(raw);
    if (!root.ok())
      return Error{"history-boc"};
    if (root.value()->get_level() != 0 || root.value()->get_hash().as_slice() != id.root_hash.as_slice())
      return Error{"history-block-root"};
    block::gen::Block::Record block;
    block::gen::BlockInfo::Record info;
    if (!tlb::unpack_cell(root.value(), block) || !tlb::unpack_cell(block.info, info))
      return Error{"history-block"};
    block::ShardId shard(info.shard);
    if (block.global_id != chain_.network || info.seq_no != at || shard.workchain_id != -1 || shard.shard_pfx_len != 0)
      return Error{"history-block-context"};
    auto update = vm::load_cell_slice_special(block.state_update);
    if (!update.is_special() || update.size() != 552 || update.size_refs() != 2 || update.fetch_ulong(8) != 4 ||
        !update.advance(256))
      return Error{"history-state-update"};
    Hash state{};
    if (!update.fetch_bytes(td::MutableSlice(state.data(), state.size())) || state == Hash{})
      return Error{"history-state-update"};
    Anchor result{at, hash(id.root_hash.as_slice()), hash(id.file_hash.as_slice()), state};
    cache_.emplace(at, result);
    return result;
  } catch (const vm::VmError&) {
    return Error{"history-block"};
  } catch (const vm::VmVirtError&) {
    return Error{"history-pruned"};
  }
}
}  // namespace tos::auth
