#pragma once
#include "c0-provider.h"
#include "local-channel.h"
namespace tos::auth {
// The host serializes witness generation changes and the actual primitive in
// one process. No asynchronous primitive escapes that fenced dispatch boundary.
class ProviderHost {
  FileWitness& witness_;
  C0Provider& provider_;

 public:
  ProviderHost(FileWitness& witness, C0Provider& provider) : witness_(witness), provider_(provider) {
  }
  Result<Bytes> dispatch(std::span<const std::uint8_t>);
};
class RemoteWitness final : public MonotonicWitness {
  std::string path_;
  uid_t uid_;

 public:
  RemoteWitness(std::string path, uid_t uid) : path_(std::move(path)), uid_(uid) {
  }
  Result<std::uint64_t> acquire() override;
  Result<bool> check(std::uint64_t, const LogFrontier&) const override;
  Result<bool> advance(std::uint64_t, const LogFrontier&, const WitnessMark&) override;
  Result<bool> contains(std::uint64_t, const Hash&) const override;
  Result<bool> check_fence(std::uint64_t) const override;
  Result<bool> claim_primitive(std::uint64_t, const Hash&) override;
  Result<bool> primitive_allowed(std::uint64_t, const Hash&) const override;
};
class RemoteProvider final : public C0SigningProvider {
  std::string path_;
  uid_t uid_;

 public:
  RemoteProvider(std::string path, uid_t uid) : path_(std::move(path)), uid_(uid) {
  }
  Result<std::vector<OpaqueKey>> public_keys() const;
  Result<Key> descriptor(const Hash&) const override;
  Result<Record> sign(const SignRequest&) override;
};
}  // namespace tos::auth
