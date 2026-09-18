#include "native-session-continuity.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <limits>
#include <span>
#include <utility>

#include "td/utils/port/Stat.h"

#include "context.h"

namespace tos::auth {
namespace {
// The frozen canonical consensus session id, H(session, ...), derived from the
// authenticated committee snapshot and the birth origin. This is the value that
// belongs in Duty.session; it is deliberately not the native ValidatorSessionId,
// which addresses the native consensus group rather than the P0 signing domain.
Result<Hash> derive_p0_session_id(
    const NativeSessionCommitteeContext& context, const ChainContext& chain,
    const SessionBirthEpoch& epoch) {
  return session_id(chain, context.committee().snapshot(),
                    SessionOrigin{epoch.native_options_hash,
                                  epoch.vertical_seqno, epoch.key_block_seqno});
}
constexpr std::array<std::uint8_t, 8> log_header{
    'V', 'S', 'C', 'L', 0, 1, 0, 0};
constexpr std::array<std::uint8_t, 8> frontier_header{
    'V', 'S', 'C', 'F', 0, 1, 0, 0};
constexpr std::uint32_t max_local_record = 4096;
constexpr std::uint64_t frontier_size = 48;

std::span<const std::uint8_t> bytes(td::Slice raw) {
  return {raw.ubegin(), raw.size()};
}

void write_bits(Writer& writer, const td::Bits256& value) {
  writer.bytes(bytes(value.as_slice()));
}

bool read_exact(const td::FileFd& fd, std::uint64_t offset,
                std::span<std::uint8_t> output) {
  while (!output.empty()) {
    if (offset > static_cast<std::uint64_t>(
                     std::numeric_limits<td::int64>::max()))
      return false;
    td::MutableSlice slice(reinterpret_cast<char*>(output.data()),
                           output.size());
    auto read = fd.pread(slice, static_cast<td::int64>(offset));
    if (read.is_error() || read.ok() == 0)
      return false;
    auto count = read.ok();
    output = output.subspan(count);
    offset += count;
  }
  return true;
}

bool write_exact(td::FileFd& fd, std::uint64_t offset,
                 std::span<const std::uint8_t> input) {
  while (!input.empty()) {
    if (offset > static_cast<std::uint64_t>(
                     std::numeric_limits<td::int64>::max()))
      return false;
    td::Slice slice(reinterpret_cast<const char*>(input.data()),
                    input.size());
    auto written = fd.pwrite(slice, static_cast<td::int64>(offset));
    if (written.is_error() || written.ok() == 0)
      return false;
    auto count = written.ok();
    input = input.subspan(count);
    offset += count;
  }
  return true;
}

void write_epoch(Writer& writer, const SessionBirthEpoch& epoch) {
  writer.bytes(epoch.native_session_id);
  writer.bytes(epoch.election_cell_hash);
  writer.bytes(epoch.native_options_hash);
  writer.integer(epoch.workchain);
  writer.integer(epoch.shard);
  writer.integer(epoch.catchain);
  writer.integer(epoch.vertical_seqno);
  writer.integer(epoch.key_block_seqno);
}

void read_epoch(Reader& reader, SessionBirthEpoch& epoch) {
  reader.hash(epoch.native_session_id);
  reader.hash(epoch.election_cell_hash);
  reader.hash(epoch.native_options_hash);
  reader.integer(epoch.workchain);
  reader.integer(epoch.shard);
  reader.integer(epoch.catchain);
  reader.integer(epoch.vertical_seqno);
  reader.integer(epoch.key_block_seqno);
}

void write_birth(Writer& writer, const SessionBirthBlock& birth) {
  writer.integer(birth.seqno);
  writer.bytes(birth.root);
  writer.bytes(birth.file);
  writer.bytes(birth.state);
}

void read_birth(Reader& reader, SessionBirthBlock& birth) {
  reader.integer(birth.seqno);
  reader.hash(birth.root);
  reader.hash(birth.file);
  reader.hash(birth.state);
}

Result<Bytes> encode_commitment(const NativeSessionCommitment& value) {
  if (value.session_id == Hash{} ||
      value.session_id != value.epoch.native_session_id ||
      value.chain.genesis_root == Hash{} ||
      value.chain.genesis_file == Hash{} ||
      value.chain.chain_domain == Hash{} ||
      value.epoch.election_cell_hash == Hash{} ||
      value.epoch.native_options_hash == Hash{} ||
      value.birth.root == Hash{} || value.birth.file == Hash{} ||
      value.birth.state == Hash{} ||
      value.committee_hash == Hash{} ||
      value.transport_order_hash == Hash{})
    return Error{"session-commitment-value"};

  Writer writer;
  writer.header("VSC1");
  writer.integer(value.chain.network);
  writer.bytes(value.chain.genesis_root);
  writer.bytes(value.chain.genesis_file);
  writer.bytes(value.chain.chain_domain);
  writer.bytes(value.session_id);
  write_epoch(writer, value.epoch);
  write_birth(writer, value.birth);
  writer.bytes(value.committee_hash);
  writer.bytes(value.transport_order_hash);
  if (!writer.ok())
    return Error{writer.error};
  if (writer.data.empty() || writer.data.size() > max_local_record)
    return Error{"session-commitment-bound"};
  return std::move(writer.data);
}

Result<NativeSessionCommitment> decode_commitment(
    std::span<const std::uint8_t> raw) {
  if (raw.empty() || raw.size() > max_local_record)
    return Error{"session-commitment-bound"};
  Reader reader(raw);
  reader.header("VSC1");
  NativeSessionCommitment value;
  reader.integer(value.chain.network);
  reader.hash(value.chain.genesis_root);
  reader.hash(value.chain.genesis_file);
  reader.hash(value.chain.chain_domain);
  reader.hash(value.session_id);
  read_epoch(reader, value.epoch);
  read_birth(reader, value.birth);
  reader.hash(value.committee_hash);
  reader.hash(value.transport_order_hash);
  if (!reader.ok() || reader.remaining() != 0)
    return Error{"session-commitment-corrupt"};
  auto canonical = encode_commitment(value);
  if (!canonical.ok() || canonical.value() != Bytes(raw.begin(), raw.end()))
    return Error{"session-commitment-corrupt"};
  return value;
}

Result<Hash> next_record_hash(const Hash& previous,
                              std::uint64_t sequence,
                              std::span<const std::uint8_t> payload) {
  Writer writer;
  writer.bytes(previous);
  writer.integer(sequence);
  writer.length(payload.size(), 4);
  writer.bytes(payload);
  if (!writer.ok())
    return Error{writer.error};
  return digest("session-commitment-record", writer.data);
}

Result<Hash> transport_order_hash(const NativeCommittee& committee) {
  const auto& order = committee.transport_order();
  if (order.empty() || order.size() > 400)
    return Error{"session-commitment-transport"};
  Writer writer;
  writer.length(order.size(), 2);
  for (const auto& member : order) {
    if (!member.auth_binding)
      return Error{"session-commitment-transport"};
    write_bits(writer, member.key.as_bits256());
    writer.integer(member.weight);
    write_bits(writer, member.addr);
    write_bits(writer, member.auth_binding->identity);
    write_bits(writer, member.auth_binding->stake_id);
  }
  if (!writer.ok())
    return Error{writer.error};
  return digest("session-transport-order", writer.data);
}

SessionBirthBlock session_block(const Anchor& anchor) {
  return {anchor.seqno_, anchor.root_, anchor.file_, anchor.state_};
}

Result<std::pair<std::uint64_t, Hash>> read_frontier(
    const td::FileFd& fd) {
  auto size = fd.get_size();
  if (size.is_error() ||
      size.ok() != static_cast<td::int64>(frontier_size))
    return Error{"session-commitment-frontier"};
  std::array<std::uint8_t, frontier_size> raw{};
  if (!read_exact(fd, 0, raw))
    return Error{"session-commitment-frontier"};
  if (!std::equal(frontier_header.begin(), frontier_header.end(),
                  raw.begin()))
    return Error{"session-commitment-frontier"};
  Reader reader(std::span<const std::uint8_t>(raw).subspan(8));
  std::uint64_t sequence = 0;
  Hash hash{};
  reader.integer(sequence);
  reader.hash(hash);
  if (!reader.ok() || reader.remaining() != 0)
    return Error{"session-commitment-frontier"};
  return std::pair{sequence, hash};
}

}  // namespace

Result<NativeSessionCommitment> make_native_session_commitment(
    const NativeSessionCommitteeContext& context,
    const ChainContext& chain) {
  const auto& selected = context.birth().selected();
  const auto& native = context.committee();
  const auto& committee = native.snapshot().committee();
  Anchor birth_anchor{selected.block.seqno, selected.block.root,
                      selected.block.file, selected.block.state};

  if (native.anchor() != birth_anchor ||
      committee.anchor_mc_ != selected.block.seqno ||
      committee.workchain_ != selected.epoch.workchain ||
      committee.shard_ != selected.epoch.shard ||
      committee.catchain_ != selected.epoch.catchain)
    return Error{"session-commitment-context"};

  auto committee_hash = object_id("session-committee-local", committee);
  if (!committee_hash.ok())
    return committee_hash.error();
  auto order_hash = transport_order_hash(native);
  if (!order_hash.ok())
    return order_hash.error();

  return NativeSessionCommitment{
      chain,
      selected.epoch.native_session_id,
      selected.epoch,
      selected.block,
      committee_hash.value(),
      order_hash.value(),
  };
}

Result<std::unique_ptr<NativeSessionCommitmentStore>>
NativeSessionCommitmentStore::initialize(const std::string& path,
                                         std::uint64_t limit) {
  if (limit < log_header.size() + 36)
    return Error{"session-commitment-limit"};
  if (td::stat(path).is_ok() || td::stat(path + ".frontier").is_ok())
    return Error{"session-commitment-store-exists"};

  auto log = td::FileFd::open(
      path, td::FileFd::Read | td::FileFd::Write |
                td::FileFd::CreateNew,
      0600);
  if (log.is_error())
    return Error{"session-commitment-storage"};
  auto frontier = td::FileFd::open(
      path + ".frontier",
      td::FileFd::Read | td::FileFd::Write |
          td::FileFd::CreateNew,
      0600);
  if (frontier.is_error())
    return Error{"session-commitment-storage"};

  auto result = std::unique_ptr<NativeSessionCommitmentStore>(
      new NativeSessionCommitmentStore(
          log.move_as_ok(), frontier.move_as_ok(), path, limit));
  if (result->log_.lock(td::FileFd::LockFlags::Write, path, 1)
          .is_error())
    return Error{"session-commitment-writer-conflict"};
  result->locked_ = true;

  if (!write_exact(result->log_, 0, log_header) ||
      result->log_.sync().is_error())
    return Error{"session-commitment-storage"};
  result->size_ = log_header.size();

  auto frontier_written = result->write_frontier(0, Hash{});
  if (!frontier_written.ok())
    return frontier_written.error();
  return result;
}

Result<std::unique_ptr<NativeSessionCommitmentStore>>
NativeSessionCommitmentStore::open(const std::string& path,
                                   std::uint64_t limit) {
  auto log_stat = td::stat(path);
  auto frontier_stat = td::stat(path + ".frontier");
  if (log_stat.is_error() || frontier_stat.is_error())
    return Error{"session-commitment-store-missing"};
  if (!log_stat.ok().is_reg_ || !frontier_stat.ok().is_reg_)
    return Error{"session-commitment-storage"};

  auto log = td::FileFd::open(path, td::FileFd::Read | td::FileFd::Write);
  auto frontier = td::FileFd::open(
      path + ".frontier", td::FileFd::Read | td::FileFd::Write);
  if (log.is_error() || frontier.is_error())
    return Error{"session-commitment-storage"};

  auto result = std::unique_ptr<NativeSessionCommitmentStore>(
      new NativeSessionCommitmentStore(
          log.move_as_ok(), frontier.move_as_ok(), path, limit));
  if (result->log_.lock(td::FileFd::LockFlags::Write, path, 1)
          .is_error())
    return Error{"session-commitment-writer-conflict"};
  result->locked_ = true;
  auto loaded = result->load();
  if (!loaded.ok())
    return loaded.error();
  return result;
}

Result<bool> NativeSessionCommitmentStore::load() {
  auto size = log_.get_size();
  if (size.is_error() || size.ok() < static_cast<td::int64>(log_header.size()))
    return Error{"session-commitment-corrupt"};
  if (static_cast<std::uint64_t>(size.ok()) > limit_)
    return Error{"session-commitment-limit"};
  size_ = static_cast<std::uint64_t>(size.ok());

  std::array<std::uint8_t, log_header.size()> header{};
  if (!read_exact(log_, 0, header) || header != log_header)
    return Error{"session-commitment-corrupt"};

  std::uint64_t offset = log_header.size();
  std::uint64_t sequence = 0;
  Hash previous{};
  while (offset < size_) {
    std::array<std::uint8_t, 4> prefix{};
    if (size_ - offset < prefix.size() ||
        !read_exact(log_, offset, prefix))
      return Error{"session-commitment-corrupt"};
    std::uint32_t length = 0;
    for (auto byte : prefix)
      length = (length << 8) | byte;
    offset += prefix.size();
    if (length == 0 || length > max_local_record ||
        size_ - offset < std::uint64_t(length) + 32)
      return Error{"session-commitment-corrupt"};

    Bytes payload(length);
    Hash recorded_hash{};
    if (!read_exact(log_, offset, payload) ||
        !read_exact(log_, offset + length, recorded_hash))
      return Error{"session-commitment-corrupt"};
    if (sequence == std::numeric_limits<std::uint64_t>::max())
      return Error{"session-commitment-sequence"};
    auto expected_hash =
        next_record_hash(previous, sequence + 1, payload);
    if (!expected_hash.ok())
      return expected_hash.error();
    if (expected_hash.value() != recorded_hash)
      return Error{"session-commitment-hash"};

    auto decoded = decode_commitment(payload);
    if (!decoded.ok())
      return decoded.error();
    if (entries_.contains(decoded.value().session_id))
      return Error{"session-commitment-duplicate"};
    entries_.emplace(
        decoded.value().session_id,
        Entry{offset, length});

    previous = recorded_hash;
    ++sequence;
    offset += std::uint64_t(length) + 32;
  }
  if (offset != size_)
    return Error{"session-commitment-corrupt"};

  auto disk_frontier = read_frontier(frontier_);
  if (!disk_frontier.ok())
    return disk_frontier.error();
  if (disk_frontier.value().first != sequence ||
      disk_frontier.value().second != previous)
    return Error{"session-commitment-frontier"};

  frontier_sequence_ = sequence;
  frontier_hash_ = previous;
  return true;
}

Result<NativeSessionCommitment>
NativeSessionCommitmentStore::read_entry(const Entry& entry) const {
  Bytes payload(entry.payload_size);
  if (!read_exact(log_, entry.payload_offset, payload))
    return Error{"session-commitment-corrupt"};
  return decode_commitment(payload);
}

Result<bool> NativeSessionCommitmentStore::write_frontier(
    std::uint64_t sequence, const Hash& hash) {
  Writer writer;
  writer.bytes(frontier_header);
  writer.integer(sequence);
  writer.bytes(hash);
  if (!writer.ok() || writer.data.size() != frontier_size)
    return Error{"session-commitment-frontier"};
  if (!write_exact(frontier_, 0, writer.data) ||
      frontier_.sync().is_error())
    return Error{"session-commitment-storage"};
  return true;
}

Result<bool> NativeSessionCommitmentStore::record_new(
    const NativeSessionCommitment& commitment) {
  if (stopped_)
    return Error{"session-commitment-storage"};
  if (entries_.contains(commitment.session_id))
    return Error{"session-commitment-exists"};
  auto payload = encode_commitment(commitment);
  if (!payload.ok())
    return payload.error();
  if (frontier_sequence_ == std::numeric_limits<std::uint64_t>::max())
    return Error{"session-commitment-sequence"};
  auto record_hash = next_record_hash(
      frontier_hash_, frontier_sequence_ + 1, payload.value());
  if (!record_hash.ok())
    return record_hash.error();

  Writer frame;
  frame.length(payload.value().size(), 4);
  frame.bytes(payload.value());
  frame.bytes(record_hash.value());
  if (!frame.ok())
    return Error{frame.error};
  if (size_ > limit_ || frame.data.size() > limit_ - size_)
    return Error{"session-commitment-limit"};

  stopped_ = true;
  const auto payload_offset = size_ + 4;
  if (!write_exact(log_, size_, frame.data) || log_.sync().is_error())
    return Error{"session-commitment-storage"};

  auto frontier_written =
      write_frontier(frontier_sequence_ + 1, record_hash.value());
  if (!frontier_written.ok())
    return frontier_written.error();

  size_ += frame.data.size();
  ++frontier_sequence_;
  frontier_hash_ = record_hash.value();
  entries_.emplace(
      commitment.session_id,
      Entry{payload_offset,
            static_cast<std::uint32_t>(payload.value().size())});
  stopped_ = false;
  return true;
}

NativeSessionCommitmentStore::~NativeSessionCommitmentStore() {
  if (!locked_)
    return;
  // The platform layer aborts if asked to unlock a path it does not hold, so
  // this runs only for the instance that actually acquired the lock.
  log_.lock(td::FileFd::LockFlags::Unlock, path_, 1).ignore();
}

Result<bool> NativeSessionCommitmentStore::verify(
    const NativeSessionCommitment& commitment) const {
  auto found = entries_.find(commitment.session_id);
  if (found == entries_.end())
    return Error{"session-commitment-missing"};
  auto recorded = read_entry(found->second);
  if (!recorded.ok())
    return recorded.error();
  if (recorded.value() != commitment)
    return Error{"session-commitment-conflict"};
  return true;
}

Result<std::shared_ptr<CommittedNativeSession>>
CommittedNativeSession::commit_new(
    NativeSessionCommitmentStore& store,
    std::shared_ptr<const NativeSessionCommitteeContext> context,
    const ChainContext& chain) {
  if (!context)
    return Error{"session-context-missing"};
  auto commitment = make_native_session_commitment(*context, chain);
  if (!commitment.ok())
    return commitment.error();
  // Every fallible pure computation is completed before the durable append, so a
  // later failure can never leave a commitment recorded for a session this call
  // then refuses to construct. record_new is the irreversible step and stays last.
  const auto& selected = context->birth().selected();
  auto p0_session_id = derive_p0_session_id(*context, chain, selected.epoch);
  if (!p0_session_id.ok())
    return p0_session_id.error();

  auto recorded = store.record_new(commitment.value());
  if (!recorded.ok())
    return recorded.error();
  return std::shared_ptr<CommittedNativeSession>(
      new CommittedNativeSession(
          std::move(context), chain, selected.epoch.native_session_id,
          p0_session_id.value(), selected.epoch, selected.block));
}

Result<std::shared_ptr<CommittedNativeSession>>
CommittedNativeSession::restart(
    NativeSessionCommitmentStore& store,
    std::shared_ptr<const NativeSessionCommitteeContext> context,
    const ChainContext& chain) {
  if (!context)
    return Error{"session-context-missing"};
  auto commitment = make_native_session_commitment(*context, chain);
  if (!commitment.ok())
    return commitment.error();
  auto verified = store.verify(commitment.value());
  if (!verified.ok())
    return verified.error();

  const auto& selected = context->birth().selected();
  auto p0_session_id = derive_p0_session_id(*context, chain, selected.epoch);
  if (!p0_session_id.ok())
    return p0_session_id.error();
  return std::shared_ptr<CommittedNativeSession>(
      new CommittedNativeSession(
          std::move(context), chain, selected.epoch.native_session_id,
          p0_session_id.value(), selected.epoch, selected.block));
}

Result<VerifiedCertificate> CommittedNativeSession::verify(
    const Certificate& certificate,
    const Duty& independently_derived_duty) const {
  if (!context_)
    return Error{"session-context-released"};
  return context_->committee().snapshot().verify(
      certificate, independently_derived_duty);
}

Result<std::uint64_t> CommittedNativeSession::verify(
    const Envelope& envelope,
    const Duty& independently_derived_duty) const {
  if (!context_)
    return Error{"session-context-released"};
  return context_->committee().snapshot().verify(
      envelope, independently_derived_duty);
}

Result<NativeSessionMemberAuthority>
CommittedNativeSession::member_authority(const Hash& identity) {
  if (!context_)
    return Error{"session-context-released"};
  const auto& members =
      context_->committee().snapshot().committee().members_;
  auto found = std::find_if(
      members.begin(), members.end(),
      [&identity](const Member& member) {
        return member.identity_ == identity;
      });
  if (identity == Hash{} || found == members.end())
    return Error{"session-member-nonmember"};

  const auto duplicate = std::find_if(
      std::next(found), members.end(),
      [&identity](const Member& member) {
        return member.identity_ == identity;
      });
  if (duplicate != members.end())
    return Error{"session-member-nonmember"};

  auto index = static_cast<std::size_t>(
      std::distance(members.begin(), found));
  return NativeSessionMemberAuthority{
      weak_from_this(), identity, index};
}

Result<Duty> CommittedNativeSession::make_member_duty(
    const Hash& identity, std::size_t member_index,
    std::uint8_t role, std::uint64_t position,
    std::span<const std::uint8_t> payload) const {
  if (!context_)
    return Error{"session-context-released"};
  const auto& snapshot = context_->committee().snapshot();
  const auto& members = snapshot.committee().members_;
  if (member_index >= members.size() ||
      members[member_index].identity_ != identity)
    return Error{"session-member-nonmember"};
  return make_duty(
      chain_, snapshot, p0_session_id_, role, position, payload);
}

Result<Duty> NativeSessionMemberAuthority::make_duty(
    std::uint8_t role, std::uint64_t position,
    std::span<const std::uint8_t> payload) const {
  auto owner = owner_.lock();
  if (!owner)
    return Error{"session-context-released"};
  return owner->make_member_duty(
      identity_, member_index_, role, position, payload);
}

Result<NativeSessionReleaseObservation>
CommittedNativeSession::release_if_terminated(
    td::Ref<vm::Cell> finalized_state,
    const Anchor& independently_finalized,
    const NativeSessionIdInput& identity_input) {
  if (!context_)
    return Error{"session-context-released"};
  if (identity_input.workchain != epoch_.workchain ||
      identity_input.shard != epoch_.shard)
    return Error{"session-termination-coordinate"};
  if (independently_finalized.seqno_ < birth_.seqno)
    return Error{"session-termination-before-birth"};
  if (independently_finalized.seqno_ == birth_.seqno &&
      session_block(independently_finalized) != birth_)
    return Error{"session-termination-anchor-conflict"};

  auto current = derive_native_session_epoch(
      std::move(finalized_state), independently_finalized,
      chain_, identity_input);
  if (!current.ok())
    return current.error();

  if (current.value() &&
      current.value()->native_session_id == native_session_id_) {
    if (*current.value() != epoch_)
      return Error{"session-termination-epoch-conflict"};
    return NativeSessionReleaseObservation{
        false, true, release_count_, independently_finalized};
  }

  if (release_count_ == std::numeric_limits<std::uint64_t>::max())
    return Error{"session-release-counter"};
  context_.reset();
  ++release_count_;
  released_at_ = independently_finalized;
  return NativeSessionReleaseObservation{
      true, false, release_count_, independently_finalized};
}

}  // namespace tos::auth
