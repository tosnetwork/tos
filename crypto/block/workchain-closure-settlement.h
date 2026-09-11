#pragma once

#include "block/workchain-allocation-overlay.h"
#include "block/workchain-account-effects.h"
#include "block/workchain-possession-replay.h"

namespace block {

// Input is the admitted permanent block entry, not a wallet proof file. Both
// hosts independently load old Native accounts, rebuild/verify closure and only
// then materialize its result. No candidate-provided effects are accepted.
// Returns private roots plus actual serialized outgoing messages. The enclosing
// host must publish the entire result atomically through Native queue admission
// (encode_native_new_export), never publish a bucket debit alone.
namespace closure_settlement_detail {
template <class Authorize>
inline td::Result<WorkchainInboundAllocationOverlay> build(
    td::Ref<vm::Cell> old_accounts, const WorkchainHostIdentity& identity, td::Ref<vm::Cell> input,
    const td::Bits256& closing_account, const td::Bits256& coordinator, const td::Bits256& custody,
    std::uint64_t max_reads, std::uint64_t max_writes,
    int extra_validation_cells, const SerializeConfig& cfg, const ActionPhaseConfig& messages,
    const Authorize& authorize) {
  auto local = [](td::Slice message) { return td::Status::Error(-7201, message); };
  try {
    if (old_accounts.is_null() || input.is_null() || identity.workchain_id != 2 ||
        closing_account == coordinator || closing_account == custody || coordinator == custody)
      return local("closure settlement context unavailable");
    gen::UnoV2HostInput::Record decoded;
    if (!tlb::unpack_cell(input, decoded)) return local("admitted closure entry unavailable");
    TRY_RESULT(access, decode_workchain_account_declarations(decoded.access, max_reads, max_writes));
    std::vector<td::Bits256> keys{closing_account, coordinator};
    std::sort(keys.begin(), keys.end());
    if (access.writes != keys || decoded.inbox->prefetch_ulong(1) != 0)
      return td::Status::Error(-7200, "closure requires exactly two accounts and no Native imports");
    vm::AugmentedDictionary old(vm::load_cell_slice_ref(old_accounts), 256, tlb::aug_ShardAccounts);
    Account account(2, closing_account.bits()), budget(2, coordinator.bits());
    auto account_leaf = old.lookup(closing_account);
    if (account_leaf.is_null()) return td::Status::Error(-7200, "closing account absent from authenticated state");
    if (!account.unpack(account_leaf, identity.gen_utime, false) ||
        !budget.unpack(old.lookup(coordinator), identity.gen_utime, false))
      return local("closure authenticated Native account unavailable");
    auto confidential = decode_workchain_confidential_account(account.data);
    auto system = decode_workchain_coordinator_state(budget.data);
    if (confidential.is_error() || system.is_error()) return local("closure authenticated records unavailable");
    if (confidential.ok().address.account != closing_account || confidential.ok().address.workchain_id != 2)
      return local("closure authenticated account identity differs from dictionary key");
    // Authorization is separate from Native conservation. This consumes the
    // metered DLEQ and reconstructs operationID/context from authenticated state.
    TRY_RESULT(transition, authorize(confidential.ok(), system.ok(), account.data, budget.data,
                                    decoded.candidate));
    WorkchainAccountEffects effects;
    effects.updates = {{closing_account, transition.account_data}, {coordinator, transition.coordinator_data}};
    std::sort(effects.updates.begin(), effects.updates.end(),
              [](const auto& a, const auto& b) { return a.account < b.account; });
    TRY_RESULT(encoded, encode_workchain_account_effects(effects, max_writes, 0, extra_validation_cells));
    allocation_overlay_detail::RefundMessageContext refund{confidential.ok().funding, messages};
    auto built = allocation_overlay_detail::build(old_accounts, identity, input, encoded, coordinator, custody,
        max_reads, max_writes, 0, 0, extra_validation_cells, cfg, nullptr, nullptr, &refund);
    if (built.is_error() && built.error().code() != -7200) return local(built.error().message());
    return built;
  } catch (const vm::VmVirtError&) { return local("closure settlement view incomplete");
  } catch (const vm::VmError&) { return local("closure settlement view unavailable");
  } catch (const vm::CellBuilder::CellCreateError&) { return local("closure settlement allocation failure");
  } catch (const vm::CellBuilder::CellWriteError&) { return local("closure settlement construction failure");
  } catch (const std::bad_alloc&) { return local("closure settlement allocation failure"); }
}
}  // namespace closure_settlement_detail

inline td::Result<WorkchainInboundAllocationOverlay> settle_workchain_closure(
    td::Ref<vm::Cell> old_accounts, const WorkchainHostIdentity& identity, td::Ref<vm::Cell> input,
    const td::Bits256& closing_account, const td::Bits256& coordinator, const td::Bits256& custody,
    const WorkchainPossessionPolicy& policy, const std::array<unsigned char, 80>& domain,
    WorkchainProofVerifier& verifier, std::uint64_t max_reads, std::uint64_t max_writes,
    int extra_validation_cells, const SerializeConfig& cfg, const ActionPhaseConfig& messages) {
  return closure_settlement_detail::build(old_accounts, identity, input, closing_account, coordinator, custody,
      max_reads, max_writes, extra_validation_cells, cfg, messages,
      [&](const auto& account, const auto& system, const auto&, const auto&, const auto& candidate) {
        return replay_workchain_account_closure(account, system, policy, domain, candidate, verifier);
      });
}

// Continuation of the admitted engine invocation: DLEQ has already consumed the
// invocation's verifier. Do not create a second allowance or verify twice. This
// overload is NEVER given a result from wire decoding or from the other host.
inline td::Result<WorkchainInboundAllocationOverlay> settle_workchain_executed_closure(
    td::Ref<vm::Cell> old_accounts, const WorkchainHostIdentity& identity, td::Ref<vm::Cell> input,
    const WorkchainAccountClosureExecution& executed, const td::Bits256& coordinator,
    const td::Bits256& custody, std::uint64_t max_reads, std::uint64_t max_writes,
    int extra_validation_cells, const SerializeConfig& cfg, const ActionPhaseConfig& messages) {
  return closure_settlement_detail::build(old_accounts, identity, input, executed.account, coordinator, custody,
      max_reads, max_writes, extra_validation_cells, cfg, messages,
      [&](const auto&, const auto&, const auto& account, const auto& system, const auto&)
          -> td::Result<WorkchainAccountClosureTransition> {
        if (executed.old_account_data_hash != account->get_hash().bits() ||
            executed.old_coordinator_data_hash != system->get_hash().bits())
          return td::Status::Error(-7201, "closure execution belongs to another state snapshot");
        return executed.transition;
      });
}
}  // namespace block
