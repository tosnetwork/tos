#include "block/block-auto.h"
#include "block/block-parse.h"

#include "native-config-message.h"
#include "native-evidence.h"
#include "native-prefetch.h"
#include "native-registry-admission.h"
namespace tos::auth {
namespace {
// The evidence parser charges its caller; admission does no chain work, so it
// accounts for nothing and leaves charging to execution.
Result<bool> uncharged(std::size_t) {
  return true;
}

// What a recognised registry message carries: the update itself, and the
// evidence read out of it. Both come from one parse, so no later step can
// restate the parse and disagree with it.
struct RecognizedUpdate {
  NativeRegistryMessage message;
  NativeEvidence evidence;
};

// Recognise the message and reach its evidence, or say why not.
Result<RecognizedUpdate> open_evidence(td::Ref<vm::Cell> message, const Hash& configuration_account) {
  if (message.is_null() || configuration_account == Hash{})
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

  // Addressed to the configuration account in the masterchain, and to nothing
  // else. A message to another account is not refused because it is malformed;
  // it is simply not this.
  auto destination = info.dest.write();
  if (destination.fetch_ulong(2) != 2 || destination.fetch_ulong(1) != 0)
    return Error{"registry-admission-not-configuration"};
  if (destination.fetch_long(8) != tos::masterchainId)
    return Error{"registry-admission-not-configuration"};
  Hash account{};
  if (!destination.fetch_bytes(td::MutableSlice(account.data(), account.size())))
    return Error{"registry-admission-not-configuration"};
  if (account != configuration_account)
    return Error{"registry-admission-not-configuration"};

  if (cs.size_refs() != 1)
    return Error{"registry-admission-not-registry"};
  auto recognized = recognize_registry_message(cs.fetch_ref());
  if (!recognized.ok())
    return Error{"registry-admission-not-registry"};
  auto evidence = NativeEvidence::open(recognized.value().evidence, uncharged);
  if (!evidence.ok())
    return evidence.error();
  return RecognizedUpdate{std::move(recognized.value()), std::move(evidence.value())};
}
}  // namespace

Result<std::vector<std::uint32_t>> registry_message_requirements(td::Ref<vm::Cell> message,
                                                                 const Hash& configuration_account,
                                                                 std::uint32_t inclusion) {
  auto opened = open_evidence(std::move(message), configuration_account);
  if (!opened.ok())
    return opened.error();
  return required_finalized_coordinates(opened.value().evidence.authorizations(), inclusion);
}

Result<std::unique_ptr<NativeConfigTransaction>> admit_registry_message(const RegistryAdmissionInputs& inputs,
                                                                        const NativeAnchorCache& cache) {
  auto opened = open_evidence(inputs.message, inputs.configuration_account);
  if (!opened.ok())
    return opened.error();

  auto required =
      required_finalized_coordinates(opened.value().evidence.authorizations(), inputs.transaction.inclusion);
  if (!required.ok())
    return required.error();

  // Missing history is a deferral, not a defect: this is the block in which the
  // node learns what it has to resolve.
  auto history = cache.source(required.value());
  if (!history.ok())
    return Error{"registry-admission-deferred"};

  return NativeConfigTransaction::open(inputs.transaction, opened.value().message.evidence, history.value(), uncharged);
}
}  // namespace tos::auth
