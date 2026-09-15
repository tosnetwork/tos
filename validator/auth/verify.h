#pragma once
#include <map>

#include "crypto.h"
namespace tos::auth {
inline constexpr std::uint64_t max_weight = std::numeric_limits<std::uint64_t>::max() / 3;
Result<Keyref> key_reference(const Key& key);
Result<Bytes> signing_statement(const Duty& duty, const Record& record);
Result<bool> validate_payload(const Duty& duty, const Bytes& payload);
class RegistrySnapshot;
class VerifiedCertificate {
  Hash certificate_id_, policy_id_, committee_id_;
  Duty duty_;
  std::vector<Hash> signers_;
  std::uint64_t weight_;
  VerifiedCertificate(Hash certificate, Hash policy, Hash committee, Duty duty, std::vector<Hash> signers,
                      std::uint64_t weight)
      : certificate_id_(certificate)
      , policy_id_(policy)
      , committee_id_(committee)
      , duty_(std::move(duty))
      , signers_(std::move(signers))
      , weight_(weight) {
  }
  friend class RegistrySnapshot;

 public:
  const Hash& certificate_id() const {
    return certificate_id_;
  }
  const Duty& duty() const {
    return duty_;
  }
  const std::vector<Hash>& signers() const {
    return signers_;
  }
  std::uint64_t weight() const {
    return weight_;
  }
};
class RegistrySnapshot {
  struct Entry {
    Member member;
    std::vector<Keyref> references;
    std::vector<AdmittedKey> keys;
  };
  Committee committee_;
  Policy policy_;
  Hash committee_id_{}, policy_id_{};
  std::map<Hash, Entry> roster_;
  std::uint64_t total_ = 0;
  RegistrySnapshot() = default;

 public:
  // Admission validates the complete roster; native state proofs establish its authority.
  static Result<RegistrySnapshot> compile(const Committee&, const Policy&);
  Result<VerifiedCertificate> verify(const Certificate&, const Duty& independently_derived_duty) const;
  Result<std::uint64_t> verify(const Envelope&, const Duty& independently_derived_duty) const;
  const Committee& committee() const {
    return committee_;
  }
  const Policy& policy() const {
    return policy_;
  }
  const Hash& committee_id() const {
    return committee_id_;
  }
  const Hash& policy_id() const {
    return policy_id_;
  }
  std::uint64_t total_weight() const {
    return total_;
  }

 private:
  Result<std::uint64_t> verify_records(const Duty&, const Bytes&, const std::vector<Record>&, const Duty&,
                                       bool quorum) const;
};
}  // namespace tos::auth
