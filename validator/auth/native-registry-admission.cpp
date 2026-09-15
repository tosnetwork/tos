#include <memory>

#include "block/block-auto.h"
#include "block/block-parse.h"

#include "native-config-message.h"
#include "native-evidence.h"
#include "native-prefetch.h"
#include "native-registry-admission.h"
namespace tos::auth {
namespace {
// The evidence parser charges its caller; admission does no chain work of its
// own, so it accounts for nothing and leaves charging to execution.
Result<bool> uncharged(std::size_t) {
  return true;
}

// What a recognised registry message carries: where it was sent, the update
// itself, and the evidence read out of it. All of it comes from one parse, so
// no later step can restate the parse and disagree with it.
struct RecognizedUpdate {
  Hash destination{};
  NativeRegistryMessage message;
  NativeEvidence evidence;
};

// Recognise the message without reading any chain state, or say why not.
//
// This runs for every external message the block considers, so it must stay
// cheap: a message that is not a registry update is refused here, before
// anything opens a state.
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

  // Addressed to a standard masterchain account. A message elsewhere is not
  // refused because it is malformed; it is simply not this.
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

Result<std::unique_ptr<NativeConfigTransaction>> admit_registry_message(const RegistryAdmissionInputs& inputs,
                                                                        const NativeAnchorCache& cache) {
  auto recognized = recognize(inputs.message);
  if (!recognized.ok())
    return recognized.error();

  if (inputs.configuration_account == Hash{})
    return Error{"registry-admission-input"};
  if (recognized.value().destination != inputs.configuration_account)
    return Error{"registry-admission-not-configuration"};

  auto required =
      required_finalized_coordinates(recognized.value().evidence.authorizations(), inputs.transaction.inclusion);
  if (!required.ok())
    return required.error();

  // Missing history is a deferral, not a defect: this is the block in which the
  // node learns what it has to resolve. Once complete, the source is owned by
  // the returned authority because owner verification can run after this call
  // has returned.
  auto history = cache.source(required.value());
  if (!history.ok())
    return Error{"registry-admission-deferred"};
  auto owned_history = std::make_shared<PrefetchedAnchorSource>(std::move(history.value()));

  return NativeConfigTransaction::open(inputs.transaction, recognized.value().message.evidence,
                                       std::move(owned_history), uncharged);
}
}  // namespace tos::auth
