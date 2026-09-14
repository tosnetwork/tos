#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>

#include "td/utils/port/FileFd.h"

#include "crypto.h"
#include "native-session-committee.h"

namespace tos::auth {

// A local continuity commitment. It is never a source of chain authority and it
// deliberately cannot reconstruct a committee: restart must authenticate and
// derive the committee again, then compare these commitments exactly.
struct NativeSessionCommitment {
  ChainContext chain;
  Hash session_id{};
  SessionBirthEpoch epoch;
  SessionBirthBlock birth;
  Hash committee_hash{};
  Hash transport_order_hash{};
  bool operator==(const NativeSessionCommitment&) const = default;
};

Result<NativeSessionCommitment> make_native_session_commitment(
    const NativeSessionCommitteeContext&, const ChainContext&);

// Append-only local store for restart continuity.
//
// initialize() is an explicit provisioning operation for a store that never
// existed. open() never creates or repairs files. The log and its independent
// frontier are both required on restart; disagreement is a hard error. Complete
// loss of both files is an operational recovery event, not permission to call
// initialize() from a restart path.
//
// A stored commitment does not grant signing, membership or chain authority.
// Only a freshly authenticated NativeSessionCommitteeContext can be compared
// against it.
class NativeSessionCommitmentStore {
 public:
  static Result<std::unique_ptr<NativeSessionCommitmentStore>> initialize(
      const std::string& path, std::uint64_t limit = 268435456);
  static Result<std::unique_ptr<NativeSessionCommitmentStore>> open(
      const std::string& path, std::uint64_t limit = 268435456);

  // A successful write lock is retained by the platform layer in a process-wide
  // registry and is released only by an explicit unlock, not by closing the
  // file. Without this the path stays locked for the life of the process and a
  // store can never be reopened -- which is restart, the thing this type exists
  // for. Release on destruction, and only if this instance took the lock.
  ~NativeSessionCommitmentStore();
  NativeSessionCommitmentStore(const NativeSessionCommitmentStore&) = delete;
  NativeSessionCommitmentStore& operator=(const NativeSessionCommitmentStore&) = delete;

  Result<bool> record_new(const NativeSessionCommitment&);
  Result<bool> verify(const NativeSessionCommitment&) const;

  std::uint64_t size() const {
    return size_;
  }
  std::uint64_t records() const {
    return frontier_sequence_;
  }

 private:
  struct Entry {
    std::uint64_t payload_offset{};
    std::uint32_t payload_size{};
  };

  NativeSessionCommitmentStore(td::FileFd log, td::FileFd frontier,
                               std::string path, std::uint64_t limit)
      : log_(std::move(log)),
        frontier_(std::move(frontier)),
        path_(std::move(path)),
        limit_(limit) {
  }

  Result<bool> load();
  Result<NativeSessionCommitment> read_entry(const Entry&) const;
  Result<bool> write_frontier(std::uint64_t sequence, const Hash& hash);

  td::FileFd log_;
  td::FileFd frontier_;
  std::string path_;
  bool locked_ = false;
  std::uint64_t limit_{};
  std::uint64_t size_{};
  std::uint64_t frontier_sequence_{};
  Hash frontier_hash_{};
  std::map<Hash, Entry> entries_;
  bool stopped_ = false;
};

class CommittedNativeSession;

// The only capability in this API that can construct a member duty. It holds a
// weak reference so authenticated session release also revokes outstanding
// member-authority handles instead of keeping the committee alive.
class NativeSessionMemberAuthority {
 public:
  Result<Duty> make_duty(std::uint8_t role, std::uint64_t position,
                         std::span<const std::uint8_t> payload) const;

  const Hash& identity() const {
    return identity_;
  }

 private:
  NativeSessionMemberAuthority(std::weak_ptr<CommittedNativeSession> owner,
                               Hash identity, std::size_t member_index)
      : owner_(std::move(owner)),
        identity_(identity),
        member_index_(member_index) {
  }

  std::weak_ptr<CommittedNativeSession> owner_;
  Hash identity_{};
  std::size_t member_index_{};

  friend class CommittedNativeSession;
};

struct NativeSessionReleaseObservation {
  bool released = false;
  bool retained = false;
  std::uint64_t release_count = 0;
  Anchor observed_at;
};

// A session is usable through this API only after the authenticated candidate
// has been durably committed (new session) or compared with an existing durable
// commitment (restart). The durable record is a continuity fence, not authority.
class CommittedNativeSession
    : public std::enable_shared_from_this<CommittedNativeSession> {
 public:
  static Result<std::shared_ptr<CommittedNativeSession>> commit_new(
      NativeSessionCommitmentStore&,
      std::shared_ptr<const NativeSessionCommitteeContext>,
      const ChainContext&);

  static Result<std::shared_ptr<CommittedNativeSession>> restart(
      NativeSessionCommitmentStore&,
      std::shared_ptr<const NativeSessionCommitteeContext>,
      const ChainContext&);

  Result<VerifiedCertificate> verify(const Certificate&,
                                     const Duty& independently_derived_duty) const;
  Result<std::uint64_t> verify(const Envelope&,
                               const Duty& independently_derived_duty) const;

  // Failure to establish exactly one matching identity is a non-member result.
  // No member-authority object is produced on that path.
  Result<NativeSessionMemberAuthority> member_authority(
      const Hash& identity);

  // The caller supplies an independently finalized masterchain state/anchor.
  // The held committee is released only when that authenticated state proves
  // the shard no longer has this native session id. Local time, memory pressure
  // and store contents are not termination conditions.
  Result<NativeSessionReleaseObservation> release_if_terminated(
      td::Ref<vm::Cell> finalized_state, const Anchor& independently_finalized,
      const NativeSessionIdInput& identity_input);

  bool retained() const {
    return static_cast<bool>(context_);
  }
  std::uint64_t release_count() const {
    return release_count_;
  }

 private:
  CommittedNativeSession(
      std::shared_ptr<const NativeSessionCommitteeContext> context,
      ChainContext chain, Hash session_id, SessionBirthEpoch epoch,
      SessionBirthBlock birth)
      : context_(std::move(context)),
        chain_(std::move(chain)),
        session_id_(session_id),
        epoch_(std::move(epoch)),
        birth_(std::move(birth)) {
  }

  Result<Duty> make_member_duty(const Hash& identity,
                                std::size_t member_index,
                                std::uint8_t role,
                                std::uint64_t position,
                                std::span<const std::uint8_t> payload) const;

  std::shared_ptr<const NativeSessionCommitteeContext> context_;
  ChainContext chain_;
  Hash session_id_{};
  SessionBirthEpoch epoch_;
  SessionBirthBlock birth_;
  std::uint64_t release_count_ = 0;
  std::optional<Anchor> released_at_;

  friend class NativeSessionMemberAuthority;
};

}  // namespace tos::auth
