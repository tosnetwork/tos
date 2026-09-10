#pragma once

#include <optional>
#include <vector>
#include "block/workchain-batch-scan.h"
#include "block/workchain-native-materialization.h"

namespace block {

// Representation acquisition and ownership of the checked claim are independent.
// A fully readable acquired candidate view can prove a candidate mismatch.
using WorkchainCoverageSource = WorkchainBatchScanSource;
enum class WorkchainCoverageObject { AuthenticatedState, CandidateClaim, HostRebuilt };
enum class WorkchainCoverageReason {
  None, MissingContent, Malformed, ForbiddenPruning, BudgetExceeded,
  KeyBound, AllocationFailure, DeltaMismatch, ParticipantMismatch, WriteOrder
};
struct WorkchainCoverageFailure {
  WorkchainBatchScanDisposition disposition;
  WorkchainCoverageReason reason;
};
using WorkchainCoverageKeys = std::variant<std::vector<td::Bits256>, WorkchainCoverageFailure>;

namespace coverage_detail {
// Thrown only by the explicit predicates below, with the source still attached.
// No generic parser exception is used to infer which side of a diff failed.
struct Stop { WorkchainCoverageFailure failure; };
[[noreturn]] inline void local_failure(WorkchainCoverageReason reason) {
  throw Stop{{WorkchainBatchScanDisposition::LocalUnavailable, reason}};
}
[[noreturn]] inline void fail(WorkchainCoverageObject object, WorkchainCoverageReason reason) {
  throw Stop{{object == WorkchainCoverageObject::CandidateClaim
                  ? WorkchainBatchScanDisposition::CandidateInvalid
                  : WorkchainBatchScanDisposition::LocalUnavailable, reason}};
}
struct Reader {
  WorkchainCoverageSource source;
  WorkchainCoverageObject object;
  WorkchainCoverageObject work_object;
  NativeStateReadMeter& meter;
  td::Ref<vm::CellSlice> load(const td::Ref<vm::Cell>& cell) {
    NativeMeteredRead result;
    try {
      result = meter.load_encoded(cell);
    } catch (const vm::VmVirtError&) {
      fail(source == WorkchainCoverageSource::ReceivedCandidate ? object : WorkchainCoverageObject::AuthenticatedState,
           WorkchainCoverageReason::ForbiddenPruning);
    } catch (const vm::VmError&) {
      local_failure(WorkchainCoverageReason::MissingContent);
    } catch (const vm::VmNoGas&) {
      local_failure(WorkchainCoverageReason::MissingContent);
    } catch (const vm::VmFatal&) {
      local_failure(WorkchainCoverageReason::MissingContent);
    } catch (const vm::CellBuilder::CellCreateError&) {
      local_failure(WorkchainCoverageReason::MissingContent);
    } catch (const vm::CellBuilder::CellWriteError&) {
      local_failure(WorkchainCoverageReason::MissingContent);
    }
    if (auto* slice = std::get_if<td::Ref<vm::CellSlice>>(&result)) {
      if ((*slice)->is_special()) {
        if ((*slice)->special_type() == vm::Cell::SpecialType::PrunnedBranch) {
          fail(source == WorkchainCoverageSource::ReceivedCandidate ? object : WorkchainCoverageObject::AuthenticatedState,
               WorkchainCoverageReason::ForbiddenPruning);
        }
        fail(object, WorkchainCoverageReason::Malformed);
      }
      return *slice;
    }
    if (std::holds_alternative<NativeClosureLimit>(result)) {
      // The caller supplies the shared authenticated admission meter. This is
      // not an allocation failure and does not reset a prior phase's charges.
      fail(work_object, WorkchainCoverageReason::BudgetExceeded);
    }
    local_failure(WorkchainCoverageReason::MissingContent);
  }
};

// A cursor expands one compressed Native dictionary edge lazily. Branching is
// binary and key depth is 256; recursion never follows account-body references.
// Native augmentation arithmetic is a separate prerequisite, not reimplemented.
struct Edge {
  td::Ref<vm::Cell> root;
  td::Ref<vm::CellSlice> value;
  td::Ref<vm::CellSlice> whole_value;
  td::Bits256 label = td::Bits256::zero();
  int length = 0;
  int consumed = 0;
  bool loaded = false;

  void open(Reader& reader, int remaining, bool accounts) {
    if (loaded || root.is_null()) return;
    auto slice = reader.load(root);
    vm::dict::LabelParser parsed{std::move(slice), remaining, 0};
    if (!parsed.is_valid()) fail(reader.object, WorkchainCoverageReason::Malformed);
    // parse_label (also in chk_none mode) bounds l_bits by remaining and
    // verifies encoded availability; is_valid rejects every failed parse.
    length = parsed.l_bits;
    parsed.extract_label_to(label.bits());
    value = std::move(parsed.remainder);
    whole_value = value;  // Preserve leaf augmentation for Native-equivalent comparison.
    if (length == remaining) {
      bool valid = accounts ? tlb::aug_ShardAccounts.skip_extra(value.write())
                            : tlb::t_CurrencyCollection.skip(value.write());
      if (!valid) fail(reader.object, WorkchainCoverageReason::Malformed);
      if (accounts) {
        auto entry = *value;
        gen::ShardAccount::Record record;
        if (!gen::t_ShardAccount.unpack(entry, record) || !entry.empty_ext()) {
          fail(reader.object, WorkchainCoverageReason::Malformed);
        }
      }
    } else {
      auto tail = *value;
      if (!tail.advance_refs(2) ||
          !(accounts ? tlb::aug_ShardAccounts.skip_extra(tail) : tlb::t_CurrencyCollection.skip(tail)) ||
          !tail.empty_ext()) fail(reader.object, WorkchainCoverageReason::Malformed);
    }
    loaded = true;
  }
  Edge child(bool bit, Reader& reader) const {
    if (root.is_null()) return {};
    if (consumed < length) {
      if (label.bits()[consumed] != bit) return {};
      auto next = *this;
      ++next.consumed;  // consumed < length <= remaining key width.
      return next;
    }
    if (value.is_null() || value->size_refs() < 2) fail(reader.object, WorkchainCoverageReason::Malformed);
    return {value->prefetch_ref(bit ? 1 : 0)};
  }
};

inline Edge outer(const td::Ref<vm::Cell>& root, Reader& reader, bool accounts) {
  auto slice = reader.load(root);
  auto& cs = slice.write();
  if (!cs.have(1)) fail(reader.object, WorkchainCoverageReason::Malformed);
  bool present = cs.fetch_ulong(1);
  td::Ref<vm::Cell> edge;
  if (present && !cs.fetch_ref_to(edge)) fail(reader.object, WorkchainCoverageReason::Malformed);
  if (!(accounts ? tlb::aug_ShardAccounts.skip_extra(cs) : tlb::t_CurrencyCollection.skip(cs)) ||
      !cs.empty_ext()) fail(reader.object, WorkchainCoverageReason::Malformed);
  return {std::move(edge)};
}
inline void append(std::vector<td::Bits256>& keys, const td::Bits256& key, std::uint64_t limit,
                   WorkchainCoverageObject object) {
  if (keys.size() >= limit) {
    fail(object, WorkchainCoverageReason::KeyBound);
  }
  keys.push_back(key);
}
inline void delta(Edge old, Edge next, Reader& before, Reader& after, int depth,
                  td::Bits256& key, std::uint64_t limit, std::vector<td::Bits256>& keys) {
  if (old.root.is_null() && next.root.is_null()) return;
  // Same position and remaining compressed prefix: equal commitments establish
  // equality without loading an untouched body, including a pruned subtree.
  if (old.root.not_null() && next.root.not_null() && old.consumed == next.consumed &&
      old.root->get_hash() == next.root->get_hash()) return;
  old.open(before, 256 - depth, true);
  next.open(after, 256 - depth, true);
  if (depth == 256) {
    if (old.root.is_null() || next.root.is_null() || !old.whole_value->contents_equal(*next.whole_value)) {
      append(keys, key, limit, after.work_object);
    }
    return;
  }
  key.bits()[depth] = false;
  delta(old.child(false, before), next.child(false, after), before, after, depth + 1, key, limit, keys);
  key.bits()[depth] = true;
  delta(old.child(true, before), next.child(true, after), before, after, depth + 1, key, limit, keys);
}
inline void participants(Edge edge, Reader& reader, int depth, td::Bits256& key,
                         std::uint64_t limit, std::vector<td::Bits256>& keys) {
  if (edge.root.is_null()) return;
  edge.open(reader, 256 - depth, false);
  if (depth == 256) {
    if (keys.size() >= limit) fail(reader.work_object, WorkchainCoverageReason::KeyBound);
    gen::AccountBlock::Record record;
    if (!gen::t_AccountBlock.unpack(edge.value.write(), record) || !edge.value->empty_ext() ||
        record.account_addr != key) fail(reader.object, WorkchainCoverageReason::Malformed);
    append(keys, record.account_addr, limit, reader.work_object);
    return;
  }
  key.bits()[depth] = false;
  participants(edge.child(false, reader), reader, depth + 1, key, limit, keys);
  key.bits()[depth] = true;
  participants(edge.child(true, reader), reader, depth + 1, key, limit, keys);
}
template <class Function> WorkchainCoverageKeys collect(Function&& function) {
  try {
    std::vector<td::Bits256> keys;
    function(keys);
    return keys;  // No vector escapes on partial traversal.
  } catch (const Stop& error) {
    return error.failure;
  } catch (const std::bad_alloc&) {
    return WorkchainCoverageFailure{WorkchainBatchScanDisposition::LocalUnavailable,
                                     WorkchainCoverageReason::AllocationFailure};
  } catch (const std::length_error&) {
    return WorkchainCoverageFailure{WorkchainBatchScanDisposition::LocalUnavailable,
                                     WorkchainCoverageReason::AllocationFailure};
  }
}
}  // namespace coverage_detail

// Private structural mechanism. Callers retain immutable authenticated root
// binding, shared phase meters, and prior Native augmentation validation.
// This does not validate transactions, batch identities, or old Account bodies.
inline WorkchainCoverageKeys rebuild_workchain_account_delta(
    const td::Ref<vm::Cell>& old_root, const td::Ref<vm::Cell>& new_root,
    const ResolvedBatchInputPolicy& policy, NativeStateReadMeter& old_meter,
    NativeStateReadMeter& new_meter, WorkchainCoverageSource new_source, WorkchainCoverageObject object) {
  return coverage_detail::collect([&](auto& keys) {
    // Old framing is authenticated state; resource demand belongs to the
    // candidate operation or host reconstruction currently being audited.
    coverage_detail::Reader before{WorkchainCoverageSource::AcquiredView, WorkchainCoverageObject::AuthenticatedState,
                                   object, old_meter};
    coverage_detail::Reader after{new_source, object, object, new_meter};
    auto old = coverage_detail::outer(old_root, before, true);
    auto next = coverage_detail::outer(new_root, after, true);
    auto key = td::Bits256::zero();
    coverage_detail::delta(std::move(old), std::move(next), before, after, 0, key,
                           policy.resources().input.max_writes, keys);
  });
}
inline WorkchainCoverageKeys extract_workchain_physical_participants(
    const td::Ref<vm::Cell>& blocks, const ResolvedBatchInputPolicy& policy,
    NativeStateReadMeter& meter, WorkchainCoverageSource source, WorkchainCoverageObject object) {
  return coverage_detail::collect([&](auto& keys) {
    coverage_detail::Reader reader{source, object, object, meter};
    auto edge = coverage_detail::outer(blocks, reader, false);
    auto key = td::Bits256::zero();
    coverage_detail::participants(std::move(edge), reader, 0, key,
                                  policy.resources().input.max_writes, keys);
  });
}

// Only completed collections can enter this comparison. The caller must not
// recover a partial vector from a failed traversal or use a claimed count here.
inline std::optional<WorkchainCoverageFailure> compare_workchain_coverage(
    const std::vector<td::Bits256>& delta, const std::vector<td::Bits256>& participants,
    const std::vector<td::Bits256>& writes, WorkchainCoverageObject delta_object,
    WorkchainCoverageObject participant_object) {
  auto failure = [&](WorkchainCoverageObject object, WorkchainCoverageReason reason) {
    return WorkchainCoverageFailure{object == WorkchainCoverageObject::CandidateClaim
        ? WorkchainBatchScanDisposition::CandidateInvalid : WorkchainBatchScanDisposition::LocalUnavailable, reason};
  };
  // writes is the admitted candidate declaration, never a host-generated list.
  for (std::size_t i = 1; i < writes.size(); ++i) {
    if (!(writes[i - 1] < writes[i])) {
      return WorkchainCoverageFailure{WorkchainBatchScanDisposition::CandidateInvalid, WorkchainCoverageReason::WriteOrder};
    }
  }
  if (delta != writes) return failure(delta_object, WorkchainCoverageReason::DeltaMismatch);
  if (participants != writes) return failure(participant_object, WorkchainCoverageReason::ParticipantMismatch);
  return std::nullopt;
}

struct WorkchainCoverageReport {
  std::vector<td::Bits256> changed_accounts;
  std::vector<td::Bits256> physical_participants;
};
using WorkchainCoverageResult = std::variant<WorkchainCoverageReport, WorkchainCoverageFailure>;

// The final audit takes immutable artifacts, not cached sets from an earlier
// successful audit. It independently computes both sets on every invocation.
// Meters belong to the caller's authenticated admission context and remain
// charged across phases. Native framing/augmentation and transaction validation
// remain independent prerequisites; this certificate is coverage only.
inline WorkchainCoverageResult check_workchain_coverage(
    const td::Ref<vm::Cell>& old_root, const td::Ref<vm::Cell>& new_root,
    const td::Ref<vm::Cell>& account_blocks, const std::vector<td::Bits256>& writes,
    const ResolvedBatchInputPolicy& policy, NativeStateReadMeter& old_meter,
    NativeStateReadMeter& new_meter, NativeStateReadMeter& block_meter,
    WorkchainCoverageSource source, WorkchainCoverageObject object,
    WorkchainCoverageSource block_source, WorkchainCoverageObject block_object) {
  if (writes.size() > policy.resources().input.max_writes) {
    return WorkchainCoverageFailure{WorkchainBatchScanDisposition::CandidateInvalid, WorkchainCoverageReason::KeyBound};
  }
  auto delta = rebuild_workchain_account_delta(old_root, new_root, policy, old_meter, new_meter, source, object);
  if (auto* failure = std::get_if<WorkchainCoverageFailure>(&delta)) return *failure;
  auto physical = extract_workchain_physical_participants(account_blocks, policy, block_meter, block_source, block_object);
  if (auto* failure = std::get_if<WorkchainCoverageFailure>(&physical)) return *failure;
  auto& changed = std::get<std::vector<td::Bits256>>(delta);
  auto& participants = std::get<std::vector<td::Bits256>>(physical);
  if (auto failure = compare_workchain_coverage(changed, participants, writes, object, block_object)) return *failure;
  return WorkchainCoverageReport{std::move(changed), std::move(participants)};
}
}  // namespace block
