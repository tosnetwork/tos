#include <memory>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"

#include "native-config-context.h"
#include "native-config-message.h"
#include "native-evidence.h"
#include "native-history.h"
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
    const tos::BlockIdExt& established_parent_block, const tos::BlockIdExt& parent_block,
    const ChainContext& chain, tos::ShardIdFull shard, std::uint32_t established_catchain,
    std::uint32_t catchain, std::uint32_t inclusion) {
  if (parent_block != established_parent_block)
    return Error{"registry-admission-parent-source"};
  if (catchain != established_catchain)
    return Error{"registry-admission-catchain-source"};

  RegistryAdmissionInputs inputs;
  inputs.message = std::move(message);
  inputs.configuration_account = configuration_account;
  inputs.parent_block = established_parent_block;
  inputs.catchain_source = established_catchain;
  inputs.transaction.masterchain_state = masterchain_state;
  inputs.transaction.parent = anchor_of(established_parent_block, masterchain_state);
  inputs.transaction.chain = chain;
  inputs.transaction.shard = shard;
  inputs.transaction.catchain = established_catchain;
  inputs.transaction.inclusion = inclusion;
  return inputs;
}

Result<std::unique_ptr<NativeConfigTransaction>> admit_registry_message(
    const RegistryAdmissionInputs& inputs) {
  auto recognized = recognize(inputs.message);
  if (!recognized.ok())
    return recognized.error();

  if (inputs.configuration_account == Hash{} || inputs.transaction.masterchain_state.is_null())
    return Error{"registry-admission-input"};

  const auto parent = anchor_of(inputs.parent_block, inputs.transaction.masterchain_state);
  if (inputs.transaction.parent != parent)
    return Error{"registry-admission-parent-input"};
  if (inputs.transaction.catchain != inputs.catchain_source)
    return Error{"registry-admission-catchain-input"};

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

  // The bound this enforces is the one that matters here: an approval may not
  // name a block at or after the one being built, so a transaction cannot
  // authorise itself with state it is in the middle of producing. The
  // coordinates it returns are not used as a second authority below -- they
  // restate what the approval already declares, and the anchor that reaches
  // execution is the authenticated one.
  auto required =
      required_finalized_coordinates(recognized.value().evidence.authorizations(), inputs.transaction.inclusion);
  if (!required.ok())
    return required.error();

  // The finality an approval relies on is carried by the message and checked
  // against this state's own history index. Nothing here reads an archive, so
  // the authority is a function of the parent state and the message alone --
  // which is what re-execution needs: a validator holding the same block
  // reaches the same answer whatever its archive happens to contain.
  // An update with no owner approval names no finalized history, so there is
  // nothing to witness and the source stays empty.
  std::map<std::uint32_t, Anchor> witnessed;
  if (!required.value().empty()) {
    // The archive is deliberately unreachable here. Authenticating a header is
    // documented never to read one, and a reader that refuses turns that
    // promise into something a test can fail rather than a comment. The budget
    // below is not what prevents the read -- a default-constructed one allows
    // plenty -- the refusing reader is.
    auto reader = [](const tos::BlockIdExt&, std::size_t) -> Result<Bytes> {
      return Error{"registry-admission-archive-read"};
    };
    auto index = NativeFinalizedHistory::open(inputs.transaction.masterchain_state, inputs.transaction.parent,
                                              inputs.transaction.chain, reader, HistoryReadBudget{});
    if (!index.ok())
      return index.error();
    auto authenticated = recognized.value().evidence.authenticate_owner(index.value());
    if (!authenticated.ok())
      return authenticated.error();
    // One entry, and it is the authenticated anchor. Comparing it against the
    // declared coordinates again would be a guard that cannot fail: both come
    // from the same approval, and authentication already refuses unless the
    // witness proves that exact anchor. A wider source is what would matter,
    // and the source is built here from this one value.
    witnessed.emplace(authenticated.value().seqno_, authenticated.value());
  }
  auto owned_history = std::make_shared<PrefetchedAnchorSource>(std::move(witnessed));

  return NativeConfigTransaction::open(inputs.transaction, recognized.value().message.evidence,
                                       std::move(owned_history), uncharged);
}
}  // namespace tos::auth
