#include <memory>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"

#include "native-config-context.h"
#include "native-config-message.h"
#include "native-evidence.h"
#include "native-prefetch.h"
#include "native-registry-admission.h"
namespace tos::auth {
namespace {
Result<bool> uncharged(std::size_t) {
  return true;
}

struct RecognizedUpdate {
  Hash destination{};
  NativeRegistryMessage message;
  NativeEvidence evidence;
};

Result<RecognizedUpdate> recognize(td::Ref<vm::Cell> message) {
  if (message.is_null())
    return Error{"registry-admission-input"};
  block::gen::CommonMsgInfo::Record_ext_in_msg_info info;
  vm::CellSlice cs;
  try {
    cs = vm::load_cell_slice(message);
    if (!tlb::unpack(cs, info))
      return Error{"registry-admission-not-external"};
  } catch (const vm::VmError&) {
    return Error{"registry-admission-not-external"};
  }

  auto destination = info.dest.write();
  if (destination.fetch_ulong(2) != 2 || destination.fetch_ulong(1) != 0)
    return Error{"registry-admission-not-configuration"};
  if (destination.fetch_long(8) != tos::masterchainId)
    return Error{"registry-admission-not-configuration"};
  Hash account{};
  if (!destination.fetch_bytes(td::MutableSlice(account.data(), account.size())))
    return Error{"registry-admission-not-configuration"};

  if (cs.size_refs() != 1)
    return Error{"registry-admission-not-registry"};
  auto recognized = recognize_registry_message(cs.fetch_ref());
  if (!recognized.ok())
    return Error{"registry-admission-not-registry"};
  auto evidence = NativeEvidence::open(recognized.value().evidence, uncharged);
  if (!evidence.ok())
    return evidence.error();
  return RecognizedUpdate{account, std::move(recognized.value()), std::move(evidence.value())};
}
}  // namespace

Result<std::vector<std::uint32_t>> registry_message_requirements(td::Ref<vm::Cell> message, std::uint32_t inclusion) {
  auto recognized = recognize(std::move(message));
  if (!recognized.ok())
    return recognized.error();
  return required_finalized_coordinates(recognized.value().evidence.authorizations(), inclusion);
}

Result<RegistryAdmissionInputs> gather_registry_admission_inputs(
    td::Ref<vm::Cell> message, const Hash& configuration_account, td::Ref<vm::Cell> masterchain_state,
    const tos::BlockIdExt& parent_block, const ChainContext& chain, tos::ShardIdFull shard,
    std::uint32_t catchain, std::uint32_t inclusion) {
  const auto parent = anchor_of(parent_block, masterchain_state);

  RegistryAdmissionInputs inputs;
  inputs.message = std::move(message);
  inputs.configuration_account = configuration_account;
  inputs.transaction.masterchain_state = std::move(masterchain_state);
  inputs.transaction.parent = parent;
  inputs.transaction.chain = chain;
  inputs.transaction.shard = shard;
  inputs.transaction.catchain = catchain;
  inputs.transaction.inclusion = inclusion;

  // These two facts cannot be reconstructed from the state without inventing a
  // second source. Preserve the values the collator supplied exactly and make
  // assembly drift observable before admission can create an authority.
  if (inputs.transaction.parent != parent)
    return Error{"registry-gathering-parent"};
  if (inputs.transaction.catchain != catchain)
    return Error{"registry-gathering-catchain"};
  return inputs;
}

Result<std::unique_ptr<NativeConfigTransaction>> admit_registry_message(const RegistryAdmissionInputs& inputs,
                                                                        const NativeAnchorCache& cache) {
  auto recognized = recognize(inputs.message);
  if (!recognized.ok())
    return recognized.error();

  if (inputs.configuration_account == Hash{} || inputs.transaction.masterchain_state.is_null())
    return Error{"registry-admission-input"};

  // The account gathered by the collator is checked against the parent state
  // here instead of becoming a second authority. Config0 and the state's own
  // configuration header must agree, and the gathered value must be that same
  // account. A wrong gathered value therefore fails before it can look like an
  // ordinary message to another account.
  auto config = block::Config::extract_from_state(inputs.transaction.masterchain_state, 0);
  if (config.is_error())
    return Error{"registry-admission-input"};
  auto declared = declared_configuration_account(*config.ok(), inputs.transaction.masterchain_state);
  if (!declared.ok())
    return declared.error();
  if (declared.value() != inputs.configuration_account)
    return Error{"registry-admission-configuration-input"};
  if (recognized.value().destination != declared.value())
    return Error{"registry-admission-not-configuration"};

  auto required =
      required_finalized_coordinates(recognized.value().evidence.authorizations(), inputs.transaction.inclusion);
  if (!required.ok())
    return required.error();

  auto history = cache.source(required.value());
  if (!history.ok())
    return Error{"registry-admission-deferred"};
  auto owned_history = std::make_shared<PrefetchedAnchorSource>(std::move(history.value()));

  return NativeConfigTransaction::open(inputs.transaction, recognized.value().message.evidence,
                                       std::move(owned_history), uncharged);
}
}  // namespace tos::auth
