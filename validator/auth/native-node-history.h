#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <utility>

#include "native-rpc.h"
#include "native-session-history.h"

namespace tos::auth {

using NativeNodeStateReader =
    std::function<Result<td::Ref<vm::Cell>>(const Anchor&)>;
using NativeNodeArchiveReader =
    std::function<Result<Bytes>(const Anchor&, const Hash&, std::size_t)>;


// Local archive record, not a protocol or wire type. The payload is retained so
// role-specific permission and role-5 administration session can be re-derived.
struct NativeDutyHistoryRecord {
  Duty duty;
  Bytes payload;
};

Result<Bytes> encode_native_duty_history_record(
    const NativeDutyHistoryRecord&);
Result<NativeDutyHistoryRecord> decode_native_duty_history_record(
    std::span<const std::uint8_t>);

struct NativeNodeHistoryReaders {
  NativeBlockReader block;
  NativeNodeStateReader state;
  NativeSessionIdentityInputReader identity;
  NativeNodeArchiveReader duty;
  NativeNodeArchiveReader certificate;
};

struct NativeNodeHistoryBudget {
  HistoryReadBudget finalized{4096, 268435456};
  HistoryReadBudget session_blocks{4096, 268435456};
  std::size_t state_reads = 4096;
  std::size_t identity_reads = 4096;
  std::size_t duty_reads = 4096;
  std::size_t duty_bytes = 16777216;
  std::size_t certificate_reads = 4096;
  std::size_t certificate_bytes = 268435456;
};

// Read-only adapter over an independently finalized native head. Injected
// readers provide storage only; they do not select a fork or confer authority.
// Returned closures borrow this object and share cumulative read budgets.
class NativeNodeHistoryAdapter final : public NativeStateSource,
                                       public FinalizedAnchorSource {
 public:
  static Result<std::unique_ptr<NativeNodeHistoryAdapter>> open(
      td::Ref<vm::Cell> finalized_head_state,
      Anchor independently_finalized_head, ChainContext chain,
      NativeNodeHistoryReaders readers,
      NativeNodeHistoryBudget budget = {});

  Result<Anchor> finalized_anchor(std::uint32_t coordinate) const override;
  Result<td::Ref<vm::Cell>> state(const Anchor&) const override;
  Result<ChainContext> chain_context() const override;
  Result<Duty> expected_duty(const Anchor&, const Duty&) const override;
  Result<Certificate> certificate(const Anchor&, const Hash&) const override;

  NativeBlockReader block_reader() const;
  NativeSessionStateReader state_reader() const;
  NativeSessionIdentityInputReader identity_reader() const;

 private:
  NativeNodeHistoryAdapter(NativeFinalizedHistory history, Anchor head,
                           ChainContext chain, NativeNodeHistoryReaders readers,
                           NativeNodeHistoryBudget budget)
      : history_(std::move(history)),
        head_(std::move(head)),
        chain_(std::move(chain)),
        readers_(std::move(readers)),
        budget_(budget) {
  }

  Result<Anchor> authenticate(const Anchor&) const;
  Result<td::Ref<vm::Cell>> load_state(const Anchor&) const;
  Result<NativeSessionIdInput> load_identity(
      const Anchor&, td::Ref<vm::Cell>, tos::ShardIdFull) const;
  Result<Bytes> load_archive(const NativeNodeArchiveReader&, const Anchor&,
                             const Hash&, std::size_t per_object_limit,
                             std::size_t& reads, std::size_t& bytes) const;
  Result<Bytes> read_session_block(const tos::BlockIdExt&,
                                   std::size_t maximum) const;

  NativeFinalizedHistory history_;
  Anchor head_;
  ChainContext chain_;
  NativeNodeHistoryReaders readers_;
  mutable NativeNodeHistoryBudget budget_;
};

}  // namespace tos::auth
