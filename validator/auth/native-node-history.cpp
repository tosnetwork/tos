#include "native-node-history.h"

#include "context.h"
#include "native-committee.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace tos::auth {
namespace {

Error preserve_source(const Error& error) {
  return error;
}

Result<bool> consume_read(std::size_t& remaining) {
  if (remaining == 0)
    return Error{"history-resource"};
  --remaining;
  return true;
}

Result<bool> consume_bytes(std::size_t& remaining, std::size_t amount) {
  if (amount > remaining)
    return Error{"history-resource"};
  remaining -= amount;
  return true;
}

Result<std::uint32_t> session_key_block(const NativeSessionIdInput& input) {
  switch (input.form) {
    case NativeSessionIdForm::group:
    case NativeSessionIdForm::group_ex:
      return std::uint32_t{0};
    case NativeSessionIdForm::group_new:
      return input.last_key_block_seqno;
    default:
      return Error{"native-session-form"};
  }
}

bool same_target(const NativeSessionIdInput& input,
                 tos::ShardIdFull target) {
  return input.workchain == target.workchain &&
         input.shard == target.shard;
}

}  // namespace

Result<Bytes> encode_native_duty_history_record(
    const NativeDutyHistoryRecord& record) {
  auto payload = validate_payload(record.duty, record.payload);
  if (!payload.ok())
    return payload.error();
  Writer writer;
  writer.header("VAHd");
  write(writer, record.duty);
  writer.blob(record.payload, 4096);
  if (!writer.ok())
    return Error{writer.error};
  return std::move(writer.data);
}

Result<NativeDutyHistoryRecord> decode_native_duty_history_record(
    std::span<const std::uint8_t> raw) {
  Reader reader(raw);
  reader.header("VAHd");
  NativeDutyHistoryRecord record;
  read(reader, record.duty);
  reader.blob(record.payload, 4096);
  if (!reader.ok() || reader.remaining() != 0)
    return Error{"node-history-duty-archive"};
  auto valid = validate_payload(record.duty, record.payload);
  if (!valid.ok())
    return valid.error();
  return record;
}

Result<std::unique_ptr<NativeNodeHistoryAdapter>>
NativeNodeHistoryAdapter::open(
    td::Ref<vm::Cell> head_state, Anchor head, ChainContext chain,
    NativeNodeHistoryReaders readers, NativeNodeHistoryBudget budget) {
  if (!readers.block || !readers.state || !readers.identity ||
      !readers.duty || !readers.certificate)
    return Error{"node-history-reader"};

  auto history_source = readers.block;
  NativeBlockReader authenticated_blocks =
      [history_source = std::move(history_source)](
          const tos::BlockIdExt& id, std::size_t maximum) -> Result<Bytes> {
    auto loaded = history_source(id, maximum);
    if (!loaded.ok())
      return preserve_source(loaded.error());
    return loaded.value();
  };

  auto history = NativeFinalizedHistory::open(
      std::move(head_state), head, chain, std::move(authenticated_blocks),
      budget.finalized);
  if (!history.ok())
    return history.error();

  return std::unique_ptr<NativeNodeHistoryAdapter>(
      new NativeNodeHistoryAdapter(
          std::move(history.value()), std::move(head), std::move(chain),
          std::move(readers), budget));
}

Result<Anchor> NativeNodeHistoryAdapter::authenticate(
    const Anchor& request) const {
  auto authenticated = history_.finalized_anchor(request.seqno_);
  if (!authenticated.ok())
    return authenticated.error();
  if (authenticated.value() != request)
    return Error{"node-history-anchor-conflict"};
  return authenticated.value();
}

Result<Anchor> NativeNodeHistoryAdapter::finalized_anchor(
    std::uint32_t coordinate) const {
  if (coordinate == head_.seqno_)
    return head_;
  return history_.finalized_anchor(coordinate);
}

Result<td::Ref<vm::Cell>> NativeNodeHistoryAdapter::load_state(
    const Anchor& anchor) const {
  auto admitted = consume_read(budget_.state_reads);
  if (!admitted.ok())
    return admitted.error();

  auto loaded = readers_.state(anchor);
  if (!loaded.ok())
    return preserve_source(loaded.error());

  auto bound = native_session_history_detail::bind_state(
      loaded.value(), anchor, chain_);
  if (!bound.ok())
    return bound.error();
  return loaded.value();
}

Result<td::Ref<vm::Cell>> NativeNodeHistoryAdapter::state(
    const Anchor& request) const {
  auto authenticated = authenticate(request);
  if (!authenticated.ok())
    return authenticated.error();
  return load_state(authenticated.value());
}

Result<ChainContext> NativeNodeHistoryAdapter::chain_context() const {
  return chain_;
}

Result<NativeSessionIdInput> NativeNodeHistoryAdapter::load_identity(
    const Anchor& request, td::Ref<vm::Cell> state,
    tos::ShardIdFull target) const {
  auto authenticated = authenticate(request);
  if (!authenticated.ok())
    return authenticated.error();

  auto bound = native_session_history_detail::bind_state(
      state, authenticated.value(), chain_);
  if (!bound.ok())
    return bound.error();

  auto admitted = consume_read(budget_.identity_reads);
  if (!admitted.ok())
    return admitted.error();

  auto loaded = readers_.identity(
      authenticated.value(), std::move(state), target);
  if (!loaded.ok())
    return preserve_source(loaded.error());
  if (!same_target(loaded.value(), target))
    return Error{"session-history-identity-shard"};
  return loaded.value();
}

Result<Bytes> NativeNodeHistoryAdapter::load_archive(
    const NativeNodeArchiveReader& reader, const Anchor& anchor,
    const Hash& id, std::size_t per_object_limit, std::size_t& reads,
    std::size_t& bytes) const {
  auto admitted = consume_read(reads);
  if (!admitted.ok())
    return admitted.error();
  if (bytes == 0)
    return Error{"history-resource"};

  const auto maximum = std::min(per_object_limit, bytes);
  auto loaded = reader(anchor, id, maximum);
  if (!loaded.ok())
    return preserve_source(loaded.error());
  if (loaded.value().empty() || loaded.value().size() > maximum)
    return Error{"node-history-archive-bound"};

  auto charged = consume_bytes(bytes, loaded.value().size());
  if (!charged.ok())
    return charged.error();
  return loaded.value();
}

Result<Duty> NativeNodeHistoryAdapter::expected_duty(
    const Anchor& request, const Duty& claim) const {
  auto authenticated = authenticate(request);
  if (!authenticated.ok())
    return authenticated.error();

  auto bound_state = load_state(authenticated.value());
  if (!bound_state.ok())
    return bound_state.error();

  auto claim_id = object_id("duty", claim);
  if (!claim_id.ok())
    return claim_id.error();

  auto raw = load_archive(
      readers_.duty, authenticated.value(), claim_id.value(), 8192,
      budget_.duty_reads, budget_.duty_bytes);
  if (!raw.ok())
    return raw.error();

  auto archived = decode_native_duty_history_record(raw.value());
  if (!archived.ok())
    return archived.error();
  auto canonical = encode_native_duty_history_record(archived.value());
  if (!canonical.ok())
    return canonical.error();
  if (canonical.value() != raw.value())
    return Error{"node-history-duty-archive"};
  auto archived_id = object_id("duty", archived.value().duty);
  if (!archived_id.ok())
    return archived_id.error();
  if (archived_id.value() != claim_id.value())
    return Error{"node-history-duty-id"};

  const auto& duty = archived.value().duty;
  if (duty.network_ != chain_.network ||
      duty.genesis_root_ != chain_.genesis_root ||
      duty.genesis_file_ != chain_.genesis_file ||
      duty.anchor_mc_ != authenticated.value().seqno_)
    return Error{"expected-context"};

  tos::ShardIdFull target{duty.workchain_, duty.shard_};
  auto identity = load_identity(
      authenticated.value(), bound_state.value(), target);
  if (!identity.ok())
    return identity.error();

  auto epoch = derive_native_session_epoch(
      bound_state.value(), authenticated.value(), chain_, identity.value());
  if (!epoch.ok())
    return epoch.error();
  if (!epoch.value())
    return Error{"history-unavailable"};
  if (epoch.value()->workchain != duty.workchain_ ||
      epoch.value()->shard != duty.shard_ ||
      epoch.value()->catchain != duty.catchain_)
    return Error{"expected-context"};

  auto committee = NativeCommittee::derive(
      bound_state.value(), authenticated.value(), chain_, target,
      duty.catchain_);
  if (!committee.ok())
    return committee.error();
  const auto& snapshot = committee.value().snapshot();
  if (snapshot.policy_id() != duty.policy_ ||
      snapshot.committee_id() != duty.committee_)
    return Error{"expected-context"};

  Result<Hash> session(Error{"expected-context"});
  if (duty.role_ == 5) {
    auto update = decode<Update>(archived.value().payload);
    if (!update.ok())
      return update.error();
    session = admin_session_id(chain_, update.value().identity_);
  } else {
    auto key_block = session_key_block(identity.value());
    if (!key_block.ok())
      return key_block.error();
    session = session_id(
        chain_, snapshot,
        SessionOrigin{identity.value().native_options_hash,
                      identity.value().maximal_vertical_seqno,
                      key_block.value()});
  }
  if (!session.ok())
    return session.error();
  if (session.value() != duty.session_)
    return Error{"expected-context"};

  return duty;
}

Result<Certificate> NativeNodeHistoryAdapter::certificate(
    const Anchor& request, const Hash& id) const {
  auto authenticated = authenticate(request);
  if (!authenticated.ok())
    return authenticated.error();
  if (id == Hash{})
    return Error{"certificate-id"};

  auto raw = load_archive(
      readers_.certificate, authenticated.value(), id, 524288,
      budget_.certificate_reads, budget_.certificate_bytes);
  if (!raw.ok())
    return raw.error();

  auto archived = decode<Certificate>(raw.value());
  if (!archived.ok())
    return Error{"node-history-certificate-archive"};
  auto canonical = encode(archived.value());
  if (!canonical.ok())
    return canonical.error();
  if (canonical.value() != raw.value())
    return Error{"node-history-certificate-archive"};
  auto archived_id = object_id("certificate", archived.value());
  if (!archived_id.ok())
    return archived_id.error();
  if (archived_id.value() != id)
    return Error{"certificate-id"};
  return archived.value();
}

Result<Bytes> NativeNodeHistoryAdapter::read_session_block(
    const tos::BlockIdExt& id, std::size_t maximum) const {
  if (!id.is_masterchain() || id.id.shard != tos::shardIdAll ||
      id.root_hash.is_zero() || id.file_hash.is_zero())
    return Error{"history-block-id"};
  if (maximum == 0)
    return Error{"history-block-bound"};
  if (budget_.session_blocks.blocks == 0 ||
      budget_.session_blocks.bytes == 0)
    return Error{"history-resource"};

  auto block_admitted = consume_read(budget_.session_blocks.blocks);
  if (!block_admitted.ok())
    return block_admitted.error();
  const auto admitted_maximum = std::min(
      {maximum, std::size_t{67108864}, budget_.session_blocks.bytes});
  if (admitted_maximum == 0)
    return Error{"history-resource"};

  auto loaded = readers_.block(id, admitted_maximum);
  if (!loaded.ok())
    return preserve_source(loaded.error());
  if (loaded.value().empty() ||
      loaded.value().size() > admitted_maximum)
    return Error{"history-block-bound"};

  auto charged = consume_bytes(
      budget_.session_blocks.bytes, loaded.value().size());
  if (!charged.ok())
    return charged.error();
  return loaded.value();
}

NativeBlockReader NativeNodeHistoryAdapter::block_reader() const {
  return [this](const tos::BlockIdExt& id,
                std::size_t maximum) -> Result<Bytes> {
    return read_session_block(id, maximum);
  };
}

NativeSessionStateReader NativeNodeHistoryAdapter::state_reader() const {
  return [this](const Anchor& anchor) -> Result<td::Ref<vm::Cell>> {
    return state(anchor);
  };
}

NativeSessionIdentityInputReader
NativeNodeHistoryAdapter::identity_reader() const {
  return [this](const Anchor& anchor, td::Ref<vm::Cell> state,
                tos::ShardIdFull target) -> Result<NativeSessionIdInput> {
    return load_identity(anchor, std::move(state), target);
  };
}

}  // namespace tos::auth
