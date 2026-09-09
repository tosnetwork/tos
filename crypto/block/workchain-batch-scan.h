#pragma once

#include <set>
#include <optional>
#include "block/block-parse.h"
#include "block/workchain-resource-policy.h"
#include "vm/dict.h"

namespace block {

// No new wire identity: all three restricted descriptors commit this pair in
// UnoV2HostRecord. account_id/effect_index select a participant, not a batch.
struct WorkchainBatchIdentity {
  td::Bits256 input_hash;
  td::Bits256 effects_hash;
  bool operator<(const WorkchainBatchIdentity& other) const {
    return input_hash < other.input_hash ||
           (input_hash == other.input_hash && effects_hash < other.effects_hash);
  }
};
enum class WorkchainBatchScanDisposition { Accepted, CandidateInvalid, LocalUnavailable };
// Representation provenance, NOT logical ownership of the data. ReceivedCandidate
// means the unmodified representation delivered in the candidate block bytes.
// AcquiredView includes local storage and locally virtualized/pruned proof views,
// even when their logical content belongs to that same candidate.
// ValidateQuery obtains AccountBlocks directly from block_candidate.data via
// block_root_/BlockExtra; collated_data Merkle proofs follow a separate virtualize
// path. A future proof-backed scan MUST select AcquiredView, not infer provenance
// from get_level(), is_virtualized(), or the logical owner. No default is allowed.
enum class WorkchainBatchScanSource { ReceivedCandidate, AcquiredView };
enum class WorkchainBatchScanReason {
  None, AccountBound, Malformed, ParticipantBinding, EntryCommitment,
  RecordMultiplicity, CountMismatch, BatchMultiplicity, EntryMultiplicity,
  MissingContent, AllocationFailure, ForbiddenPrunedRepresentation
};
struct WorkchainBatchScanResult {
  WorkchainBatchScanDisposition disposition = WorkchainBatchScanDisposition::Accepted;
  WorkchainBatchScanReason reason = WorkchainBatchScanReason::None;
  std::uint64_t accounts_seen = 0;
  std::uint64_t records_seen = 0;
  std::uint64_t distinct_batches = 0;
  std::uint64_t entries_seen = 0;
  bool scan_complete = false;
  // Published only on acceptance, never a partial-scan identity.
  std::optional<WorkchainBatchIdentity> identity;
};

namespace batch_scan_detail {
template <class Allocator = std::allocator<WorkchainBatchIdentity>>
class Scanner {
 public:
  // Single invocation only: the public run wrapper constructs a fresh scanner.
  // Keeping progress after failure is solely for reporting a partial traversal.
  explicit Scanner(const ResolvedBatchInputPolicy& policy, WorkchainBatchScanSource source,
                   const Allocator& allocator = Allocator{})
      : account_limit_(policy.resources().input.max_writes), source_(source),
        identities_(std::less<WorkchainBatchIdentity>{}, allocator) {}

  WorkchainBatchScanResult run(const td::Ref<vm::Cell>& root, std::uint64_t claimed_count) {
    auto outer = load(root);
    if (outer.is_null()) return result_;
    auto& cs = outer.write();
    if (!cs.have(1)) return invalid(WorkchainBatchScanReason::Malformed);
    const bool present = cs.fetch_ulong(1);
    td::Ref<vm::Cell> dictionary;
    if (present && !cs.fetch_ref_to(dictionary)) return invalid(WorkchainBatchScanReason::Malformed);
    if (!tlb::t_CurrencyCollection.skip(cs) || !cs.empty_ext()) {
      return invalid(WorkchainBatchScanReason::Malformed);
    }
    td::Bits256 key = td::Bits256::zero();
    auto account = [&](td::Ref<vm::CellSlice> value, const td::Bits256& address) {
      return scan_account(std::move(value), address);
    };
    if (present && !walk(load(dictionary), 256, 0, key, account)) return result_;
    result_.scan_complete = true;
    // Only complete traversal may decide identity/count validity. In particular,
    // a later unavailable branch is not hidden by an earlier distinct identity.
    if (claimed_count != result_.distinct_batches) return invalid(WorkchainBatchScanReason::CountMismatch);
    if (result_.distinct_batches != 1) return invalid(WorkchainBatchScanReason::BatchMultiplicity);
    if (result_.entries_seen != 1) return invalid(WorkchainBatchScanReason::EntryMultiplicity);
    result_.identity = *identities_.begin();  // Exactly one identity was checked above.
    return result_;
  }
  WorkchainBatchScanResult allocation_failure() {
    result_.disposition = WorkchainBatchScanDisposition::LocalUnavailable;
    result_.reason = WorkchainBatchScanReason::AllocationFailure;
    return result_;
  }

 private:
  WorkchainBatchScanResult invalid(WorkchainBatchScanReason reason) {
    result_.disposition = WorkchainBatchScanDisposition::CandidateInvalid;
    result_.reason = reason;
    return result_;
  }
  bool fail(WorkchainBatchScanReason reason) { invalid(reason); return false; }
  td::Ref<vm::CellSlice> unavailable() {
    result_.disposition = WorkchainBatchScanDisposition::LocalUnavailable;
    result_.reason = WorkchainBatchScanReason::MissingContent;
    return {};
  }
  td::Ref<vm::CellSlice> pruned_representation() {
    switch (source_) {
      case WorkchainBatchScanSource::ReceivedCandidate:
        invalid(WorkchainBatchScanReason::ForbiddenPrunedRepresentation);
        return {};
      case WorkchainBatchScanSource::AcquiredView:
        return unavailable();
    }
    // Invalid enum values are a host contract failure, not candidate evidence.
    return unavailable();
  }
  td::Ref<vm::CellSlice> load(const td::Ref<vm::Cell>& cell) {
    if (cell.is_null()) return unavailable();
    // Only the load is inside this boundary. Candidate parsing below uses an
    // already loaded slice and explicit boolean checks, not quiet cell unpack.
    try {
      bool special = false;
      auto slice = vm::load_cell_slice_special(cell, special);
      if (special) {
        if (slice.special_type() == vm::Cell::SpecialType::PrunnedBranch) return pruned_representation();
        invalid(WorkchainBatchScanReason::Malformed);
        return {};
      }
      return td::make_ref<vm::CellSlice>(std::move(slice));
    } catch (const vm::VmError&) {
      return unavailable();
    } catch (const vm::VmVirtError&) {
      return pruned_representation();
    } catch (const vm::VmNoGas&) {
      return unavailable();
    } catch (const vm::VmFatal&) {
      return unavailable();
    }
  }

  // Native HashmapAug traversal without recursive generated validation or a
  // pre-collected array. LabelParser receives a loaded slice, so bad labels are
  // candidate structure errors, not confused with a cell loader exception.
  template <class Leaf>
  bool walk(td::Ref<vm::CellSlice> slice, int remaining, int offset,
            td::Bits256& key, Leaf& leaf) {
    if (slice.is_null()) return false;
    vm::dict::LabelParser label{std::move(slice), remaining, 0};
    // parse_label already bounds length by remaining. On failure l_bits may be
    // uninitialized, so do not inspect it before this validity check.
    if (!label.is_valid()) return fail(WorkchainBatchScanReason::Malformed);
    const int length = label.l_bits;
    label.extract_label_to(key.bits() + offset);
    auto value = std::move(label.remainder);
    if (length == remaining) {
      if (!tlb::t_CurrencyCollection.skip(value.write())) return fail(WorkchainBatchScanReason::Malformed);
      return leaf(std::move(value), key);
    }
    // 0 <= length < remaining: the child width decreases, and key offsets fit
    // the fixed 256/64-bit keys. At most 257 + 65 active dictionary frames.
    auto& cs = value.write();
    td::Ref<vm::Cell> left, right;
    if (!cs.fetch_ref_to(left) || !cs.fetch_ref_to(right) ||
        !tlb::t_CurrencyCollection.skip(cs) || !cs.empty_ext()) {
      return fail(WorkchainBatchScanReason::Malformed);
    }
    const int next = offset + length;
    key.bits()[next] = false;
    if (!walk(load(left), remaining - length - 1, next + 1, key, leaf)) return false;
    key.bits()[next] = true;
    return walk(load(right), remaining - length - 1, next + 1, key, leaf);
  }

  bool scan_account(td::Ref<vm::CellSlice> value, const td::Bits256& address) {
    // One restricted record per modified account is the installed batch shape.
    // Its authenticated write bound therefore also bounds AccountBlocks. Do not
    // allocate an identity node or decode this account after exceeding it.
    if (result_.accounts_seen >= account_limit_) return fail(WorkchainBatchScanReason::AccountBound);
    ++result_.accounts_seen;  // Prior check bounds this by the uint32 policy field.
    gen::AccountBlock::Record account;
    if (!gen::t_AccountBlock.unpack(value.write(), account) || !value->empty_ext() ||
        account.account_addr != address) return fail(WorkchainBatchScanReason::Malformed);
    unsigned records = 0;
    td::Bits256 key = td::Bits256::zero();
    auto transaction = [&](td::Ref<vm::CellSlice> item, const td::Bits256& lt) {
      if (records != 0) return fail(WorkchainBatchScanReason::RecordMultiplicity);
      ++records;
      if (item->size_ext() != 0x10000) return fail(WorkchainBatchScanReason::Malformed);
      return scan_transaction(load(item->prefetch_ref()), address, lt.bits().get_uint(64));
    };
    return walk(std::move(account.transactions), 64, 0, key, transaction);
  }

  bool scan_transaction(td::Ref<vm::CellSlice> value, const td::Bits256& address, std::uint64_t lt) {
    if (value.is_null()) return false;
    auto& cs = value.write();
    td::Bits256 transaction_address;
    // Shallow fixed Transaction framing. Do not invoke its generated unpack:
    // that quietly loads Transaction_aux, which is unrelated to batch identity.
    if (!cs.have(695) || cs.fetch_ulong(4) != 7 ||
        !cs.fetch_bits_to(transaction_address) || transaction_address != address ||
        cs.fetch_ulong(64) != lt || !cs.advance(371) || !cs.advance_refs(1) ||
        !tlb::t_CurrencyCollection.skip(cs) || !cs.advance_refs(1)) {
      return fail(WorkchainBatchScanReason::Malformed);
    }
    td::Ref<vm::Cell> description;
    if (!cs.fetch_ref_to(description) || !cs.empty_ext()) return fail(WorkchainBatchScanReason::Malformed);
    auto loaded = load(description);
    if (loaded.is_null()) return false;
    auto& desc = loaded.write();
    if (!desc.have(4)) return fail(WorkchainBatchScanReason::Malformed);
    auto tag = desc.fetch_ulong(4);
    const bool entry = tag == tlb::TransactionDescr::trans_workchain_entry_v3;
    if (!entry && tag != tlb::TransactionDescr::trans_workchain_storage_participant_v3 &&
        tag != tlb::TransactionDescr::trans_workchain_settlement_participant_v3) {
      return fail(WorkchainBatchScanReason::Malformed);
    }
    td::Ref<vm::Cell> binding, input, effects;
    if (!desc.fetch_ref_to(binding) ||
        (entry && (!desc.fetch_ref_to(input) || !desc.fetch_ref_to(effects))) || !desc.empty_ext()) {
      return fail(WorkchainBatchScanReason::Malformed);
    }
    auto record_slice = load(binding);
    if (record_slice.is_null()) return false;
    gen::UnoV2HostRecord::Record record;
    if (!gen::t_UnoV2HostRecord.unpack(record_slice.write(), record) || !record_slice->empty_ext()) {
      return fail(WorkchainBatchScanReason::Malformed);
    }
    if (record.account_id != address) return fail(WorkchainBatchScanReason::ParticipantBinding);
    if (entry && (load(input).is_null() || load(effects).is_null())) return false;
    // Admission's ordinary-only traversal covers candidate/declarations, not
    // the complete finality/inbox closure (workchain-host-input.h, Visit::ordinary).
    // Ordinary parents can therefore still contain pruned descendants. Check
    // representation before comparing the producer's default-level commitment.
    if (entry && (input->get_level() != 0 || effects->get_level() != 0)) {
      pruned_representation();
      return false;
    }
    if (entry && (record.input_hash != input->get_hash().bits() ||
                  record.effects_hash != effects->get_hash().bits())) {
      return fail(WorkchainBatchScanReason::EntryCommitment);
    }
    // account_id and effect_index deliberately do not enter the batch key.
    // Canonical index/write-set agreement belongs to independent replay (I13c).
    identities_.insert({record.input_hash, record.effects_hash});
    result_.distinct_batches = identities_.size();  // Observed count, partial until scan_complete.
    ++result_.records_seen;  // At most one record per admitted AccountBlock.
    if (entry) ++result_.entries_seen;
    return true;
  }

  const std::uint32_t account_limit_;
  const WorkchainBatchScanSource source_;
  WorkchainBatchScanResult result_;
  std::set<WorkchainBatchIdentity, std::less<WorkchainBatchIdentity>, Allocator> identities_;
};
template <class Allocator>
WorkchainBatchScanResult run(const td::Ref<vm::Cell>& root, const ResolvedBatchInputPolicy& policy,
                            std::uint64_t count, WorkchainBatchScanSource source, const Allocator& allocator) {
  Scanner<Allocator> scanner(policy, source, allocator);
  try {
    return scanner.run(root, count);
  } catch (const std::bad_alloc&) {
    return scanner.allocation_failure();
  }
}
}  // namespace batch_scan_detail

// Private mechanism, not live validation or activation. The caller selects the
// wc=2 candidate AccountBlocks and the authenticated policy cut. No independent
// limit argument or claimed-count allocation is accepted. Logical traversal is
// O((max_writes + 1) * (256 + 64)); identity storage is O(max_writes), with no
// up-front reserve. This does not validate fees, augmentation sums, full payload
// closures, participant roles, or independent settlement/write-set reconstruction.
inline WorkchainBatchScanResult scan_workchain_batch_account_blocks(
    const td::Ref<vm::Cell>& account_blocks, const ResolvedBatchInputPolicy& policy,
    std::uint64_t claimed_batch_count, WorkchainBatchScanSource source) {
  return batch_scan_detail::run(account_blocks, policy, claimed_batch_count, source,
                                std::allocator<WorkchainBatchIdentity>{});
}

}  // namespace block
