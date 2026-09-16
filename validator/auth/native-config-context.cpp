#include "block/block-auto.h"
#include "block/mc-config.h"
#include "block/transaction.h"

#include "native-config-context.h"
namespace tos::auth {
namespace {
Hash hash(td::Ref<vm::Cell> cell) {
  Hash result{};
  if (cell.not_null()) {
    auto owned = cell->get_hash();
    std::copy_n(owned.as_slice().ubegin(), result.size(), result.begin());
  }
  return result;
}
bool same(td::Ref<vm::Cell> a, td::Ref<vm::Cell> b) {
  return a.is_null() == b.is_null() && (a.is_null() || a->get_hash() == b->get_hash());
}
}  // namespace
Result<ConfigurationAccountData> read_configuration_account(td::Ref<vm::Cell> data) {
  try {
    if (data.is_null())
      return Error{"config-data"};
    vm::CellSlice cs{vm::NoVm{}, std::move(data)};
    // The layout the configuration contract stores: the parameter dictionary,
    // the sequence number and public key, an optional vote dictionary, and the
    // registry checkpoint last. The width is checked before anything is taken
    // from it, so a cell of another shape is refused rather than reinterpreted.
    if (cs.is_special() || cs.size() != 289 || cs.size_refs() < 2)
      return Error{"config-data"};
    ConfigurationAccountData parsed;
    parsed.configuration = cs.fetch_ref();
    if (!cs.advance(288))
      return Error{"config-data"};
    if (cs.fetch_ulong(1) == 1) {
      if (cs.size_refs() != 2)
        return Error{"config-data"};
      cs.fetch_ref();
    }
    if (cs.size_refs() != 1)
      return Error{"config-data"};
    parsed.checkpoint = cs.fetch_ref();
    return parsed;
  } catch (const vm::VmError&) {
    return Error{"config-data"};
  } catch (const vm::VmVirtError&) {
    return Error{"config-data-pruned"};
  }
}

NativeConfigContext::NativeConfigContext(ChainContext chain, Anchor head, Hash address, td::Ref<vm::Cell> code,
                                         td::Ref<vm::Cell> data, td::Ref<vm::Cell> library, td::Ref<vm::Cell> config,
                                         NativeRegistry parent, NativeCommittee committee,
                                         NativeFinalizedHistory history)
    : chain_(chain)
    , head_(head)
    , address_(address)
    , code_(std::move(code))
    , data_(std::move(data))
    , library_(std::move(library))
    , config_(std::move(config))
    , parent_(std::move(parent))
    , committee_(std::move(committee))
    , history_(std::move(history)) {
}
Result<Hash> declared_configuration_account(const block::Config& config, td::Ref<vm::Cell> masterchain_state) {
  auto parameter = config.get_config_param(0);
  if (parameter.is_null())
    return Error{"config-address"};
  vm::CellSlice address_cell{vm::NoVm{}, std::move(parameter)};
  Hash address{};
  if (!address_cell.is_valid() || address_cell.is_special() || address_cell.size() != 256 ||
      address_cell.size_refs() != 0 || !address_cell.fetch_bytes(td::MutableSlice(address.data(), address.size())) ||
      address == Hash{})
    return Error{"config-address"};
  block::gen::ShardStateUnsplit::Record state;
  block::gen::McStateExtra::Record extra;
  block::gen::ConfigParams::Record params;
  if (masterchain_state.is_null() || !tlb::unpack_cell(masterchain_state, state) || state.custom.is_null() ||
      !tlb::unpack_cell(state.custom->prefetch_ref(), extra) || !tlb::csr_unpack(extra.config, params) ||
      params.config_addr != td::Bits256(td::ConstBitPtr(address.data())))
    return Error{"config-address-binding"};
  return address;
}

Result<NativeConfigContext> NativeConfigContext::open(td::Ref<vm::Cell> root, const Anchor& head,
                                                      const ChainContext& chain, const NativeRegistry* cached,
                                                      StateReadBudget budget) {
  try {
    // Establish chain/state trust before extracting account-controlled values.
    auto history = NativeFinalizedHistory::open(root, head, chain, {}, {0, 0});
    if (!history.ok())
      return history.error();
    tos::BlockIdExt id{{tos::masterchainId, tos::shardIdAll, head.seqno_},
                       td::Bits256(td::ConstBitPtr(head.root_.data())),
                       td::Bits256(td::ConstBitPtr(head.file_.data()))};
    auto loaded = block::ConfigInfo::extract_config(
        root, id,
        block::ConfigInfo::needAccountsRoot | block::ConfigInfo::needPrevBlocks | block::Config::needCapabilities);
    if (loaded.is_error())
      return Error{"config-native-state"};
    auto& cfg = *loaded.ok();
    auto declared = declared_configuration_account(cfg, root);
    if (!declared.ok())
      return declared.error();
    const auto address = declared.value();
    block::Account account(-1, td::ConstBitPtr(address.data()));
    auto accounts = cfg.get_accounts_dict();
    if (!account.unpack(accounts.lookup(account.addr), cfg.utime, true) ||
        account.status != block::Account::acc_active || !account.tick || account.addr_rewrite_length != 0 ||
        account.code.is_null() || account.data.is_null() || account.code->get_level() != 0 ||
        account.data->get_level() != 0)
      return Error{"config-account"};
    auto parsed = read_configuration_account(account.data);
    if (!parsed.ok())
      return parsed.error();
    if (!same(parsed.value().configuration, cfg.get_root_cell()))
      return Error{"config-dictionary-binding"};
    auto checkpoint = parsed.value().checkpoint;
    auto registry = cfg.get_config_param(46);
    auto parent = [&]() -> Result<NativeRegistry> {
      if (cached) {
        auto check = cached->checkpoint();
        auto encoded = cached->encode_cell();
        if (!check.ok() || !encoded.ok() || cached->coordinate() != head.seqno_ || !same(check.value(), checkpoint) ||
            !same(encoded.value(), registry))
          return Error{"config-cache-binding"};
        return *cached;
      }
      return NativeRegistry::restore(checkpoint, hash(registry), head.seqno_, budget);
    }();
    if (!parent.ok())
      return parent.error();
    auto committee =
        NativeCommittee::derive(root, head, chain, {tos::masterchainId, tos::shardIdAll}, cfg.cc_seqno_, budget);
    if (!committee.ok())
      return committee.error();
    return NativeConfigContext(chain, head, address, account.code, account.data, account.library, cfg.get_root_cell(),
                               std::move(parent.value()), std::move(committee.value()), std::move(history.value()));
  } catch (const vm::VmError&) {
    return Error{"config-native-state"};
  } catch (const vm::VmVirtError&) {
    return Error{"config-pruned"};
  }
}
Result<bool> NativeConfigContext::binds(std::int32_t workchain, const Hash& address, td::Ref<vm::Cell> code,
                                        td::Ref<vm::Cell> data, td::Ref<vm::Cell> library) const {
  if (workchain != -1 || address != address_ || !same(code, code_) || !same(data, data_) || !same(library, library_))
    return Error{"config-transaction-binding"};
  return true;
}
}  // namespace tos::auth
