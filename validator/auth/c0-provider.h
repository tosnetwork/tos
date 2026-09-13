#pragma once
#include "safety-ledger.h"
namespace tos::auth {
struct LocalKeyTemplate {
  Hash identity{};
  std::uint8_t role = 0;
  std::uint64_t epoch = 0;
  std::uint32_t valid_from = 0, valid_until = 0;
};
struct OpaqueKey {
  Key descriptor;
  Hash handle{};
};
class C0SigningProvider {
 public:
  virtual ~C0SigningProvider() = default;
  virtual Result<Key> descriptor(const Hash& handle) const = 0;
  virtual Result<Record> sign(const SignRequest&) = 0;
};
// This provider owns secrets and an exclusive durable file. Its public signing
// entry point accepts only a complete canonical sign request backed by a witness
// reservation; no raw-sign or secret-export operation exists.
class C0Provider final : public C0SigningProvider {
  struct Secret {
    Key key;
    Hash handle{}, seed{};
    ~Secret();
  };
  struct Invocation {
    std::uint64_t fence;
    Hash handle;
    Bytes statement, signature;
  };
  std::unique_ptr<DurableLog> log_;
  MonotonicWitness& witness_;
  std::map<Hash, Secret> keys_;
  std::map<Hash, Invocation> invocations_;
  bool stopped_ = false;
  explicit C0Provider(MonotonicWitness& witness) : witness_(witness) {
  }
  Result<bool> replay(std::span<const std::uint8_t>);

 public:
  // Explicit local provisioning only, never an RPC or peer request. New private
  // material is generated inside the provider and persisted before publication.
  static Result<std::unique_ptr<C0Provider>> provision(const std::string&, MonotonicWitness&,
                                                       const std::vector<LocalKeyTemplate>&);
  static Result<std::unique_ptr<C0Provider>> open(const std::string&, MonotonicWitness&);
  std::vector<OpaqueKey> public_keys() const;
  Result<Key> descriptor(const Hash& handle) const override;
  Result<Record> sign(const SignRequest&) override;
};
}  // namespace tos::auth
