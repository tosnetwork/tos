// TEST SUPPORT ONLY. Wallet secrets and decrypted values must never enter node state.
#pragma once
#include <array>
#include <cstring>
#include <map>
#include <optional>
#include <sodium/crypto_scalarmult_ristretto255.h>

#include "block/block-parse.h"
#include "block/transaction.h"
#include "block/workchain-confidential-input.h"
#include "block/workchain-coordinator-state.h"

namespace block::m3_test {
using Root = td::Ref<vm::Cell>;
using Point = std::array<unsigned char, 32>;
inline td::Status alarm(const char* message) {
  return td::Status::Error(td::Slice(message));
}
inline Point point(const td::Bits256& value) {
  Point out{};
  std::memcpy(out.data(), value.as_slice().data(), out.size());
  return out;
}
inline td::Result<std::uint64_t> checked_sum(std::uint64_t a, std::uint64_t b) {
  if (b > UINT64_MAX - a)
    return alarm("acceptance arithmetic overflow");
  return a + b;
}
// This is the ONE numerical verdict used by both real checks and the wrong-value control.
inline td::Status assert_balance(std::uint64_t actual, std::uint64_t expected) {
  return actual == expected ? td::Status::OK() : alarm("decrypted balance mismatch");
}
// Bounded test-wallet discrete log: C - sD = value*G. G is the fixed Ristretto
// basepoint used by the kernel, not a caller-supplied generator. BSGS avoids a
// linear scan of the test balance range. No production decryption API is added.
inline td::Result<std::uint64_t> decrypt(const WorkchainCiphertext& ciphertext, const Point& secret,
                                         std::uint64_t bound) {
  if (bound > 1000000000ULL)
    return alarm("test decryption bound too large");
  if (!confidential_state_detail::canonical_ciphertext(ciphertext))
    return alarm("noncanonical ciphertext");
  unsigned char wide[64]{};
  std::memcpy(wide, secret.data(), 32);
  Point reduced{};
  crypto_core_ristretto255_scalar_reduce(reduced.data(), wide);
  if (reduced != secret || secret == Point{})
    return alarm("noncanonical or zero wallet secret");
  Point sd{}, clear{}, one{};
  one[0] = 1;
  auto d = point(ciphertext.handle), c = point(ciphertext.commitment);
  if (d != Point{} && crypto_scalarmult_ristretto255(sd.data(), secret.data(), d.data()) != 0)
    return alarm("ciphertext multiplication failed");
  if (crypto_core_ristretto255_sub(clear.data(), c.data(), sd.data()) != 0)
    return alarm("ciphertext subtraction failed");
  Point g{};
  if (crypto_scalarmult_ristretto255_base(g.data(), one.data()) != 0)
    return alarm("basepoint failed");
  std::uint64_t width = 1;
  while (width * width <= bound)
    ++width;  // width <= 31623, checked bound above.
  std::map<Point, std::uint64_t> baby;
  Point cursor{};
  for (std::uint64_t j = 0; j < width; ++j) {
    baby.emplace(cursor, j);
    Point next{};
    if (crypto_core_ristretto255_add(next.data(), cursor.data(), g.data()) != 0)
      return alarm("point addition failed");
    cursor = next;
  }
  // cursor is width*G. These index products are bounded by bound + 2*width.
  for (std::uint64_t i = 0; i <= bound / width; ++i) {
    auto found = baby.find(clear);
    if (found != baby.end()) {
      auto value = i * width + found->second;
      if (value <= bound)
        return value;
    }
    Point next{};
    if (crypto_core_ristretto255_sub(next.data(), clear.data(), cursor.data()) != 0)
      return alarm("point subtraction failed");
    clear = next;
  }
  return alarm("wallet decryption outside expected range or wrong key");
}
// Structural privacy, not an entropy/covert-channel proof: exact schemas have
// ciphertext points and no plaintext confidential-amount field. Public fees,
// nonces and deposits may numerically equal a transfer; scanning for that integer
// would misclassify them (and random proof bytes). Extra bits/refs are rejected.
inline td::Status assert_private_account(const Root& root) {
  auto decoded = decode_workchain_confidential_account(root);
  if (decoded.is_error())
    return alarm("plaintext/noncanonical account layout alarm");
  return td::Status::OK();
}
inline td::Status assert_private_input(const Root& root) {
  auto decoded = decode_workchain_transfer_input(root);
  if (decoded.is_error())
    return alarm("plaintext/noncanonical replay input layout alarm");
  return td::Status::OK();
}
// Extract from the permanent Block -> AccountBlock -> Transaction -> entry.input
// path. The caller selects the observed transaction, never a detached candidate.
// This checks the confidential replay payload, not all unrelated public block
// metadata or an arbitrary application's payload. It does not replace validation.
inline td::Result<Root> input_from_block(const Root& block_root, const td::Bits256& account_id,
                                         std::uint64_t logical_time) {
  using confidential_state_detail::unpack;
  TRY_RESULT(block, unpack<gen::Block::Record>(block_root));
  TRY_RESULT(extra, unpack<gen::BlockExtra::Record>(block.extra));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(extra.account_blocks), 256, tlb::aug_ShardAccountBlocks);
  auto leaf = accounts.lookup(account_id);
  gen::AccountBlock::Record account;
  if (leaf.is_null() || !gen::t_AccountBlock.unpack(leaf.write(), account) || !leaf->empty() ||
      account.account_addr != account_id)
    return alarm("missing or malformed observed AccountBlock");
  vm::AugmentedDictionary transactions(vm::DictNonEmpty(), account.transactions, 64, tlb::aug_AccountTransactions);
  td::BitArray<64> key;
  key.bits().store_uint(logical_time, 64);
  TRY_RESULT(tx, unpack<gen::Transaction::Record>(transactions.lookup_ref(key)));
  if (tx.account_addr != account_id || tx.lt != logical_time)
    return alarm("observed transaction identity mismatch");
  TRY_RESULT(entry, unpack<gen::TransactionDescr::Record_trans_workchain_entry_v3>(tx.description));
  TRY_RESULT(host, unpack<gen::UnoV2HostInput::Record>(entry.input));
  TRY_RESULT(binding, unpack<gen::UnoV2HostRecord::Record>(entry.binding));
  if (binding.input_hash != td::Bits256(entry.input->get_hash().bits()))
    return alarm("entry input commitment mismatch");
  TRY_STATUS(assert_private_input(host.candidate));
  return host.candidate;
}
inline td::Status same_identity(const WorkchainConfidentialAccount& before, const WorkchainConfidentialAccount& after) {
  if (before.address.workchain_id != after.address.workchain_id || before.address.account != after.address.account ||
      before.address.instance != after.address.instance || before.public_key != after.public_key)
    return alarm("account identity changed");
  return td::Status::OK();
}
inline td::Result<std::map<td::Bits256, td::Bits256>> receipt_hashes(const WorkchainConfidentialAccount& account) {
  std::map<td::Bits256, td::Bits256> hashes;
  for (const auto& receipt : account.pending) {
    TRY_RESULT(root, encode_workchain_pending_receipt(receipt));
    if (!hashes.emplace(receipt.receipt_id, td::Bits256(root->get_hash().bits())).second)
      return alarm("duplicate receipt");
  }
  return hashes;
}
struct TransferBalances {
  std::uint64_t before, after, transferred;
  std::size_t retained_pending;
};
// Roots are read back from the caller's persisted result, not predicted effects.
// SEND recipient available is unchanged: value enters a full pending receipt.
inline td::Result<TransferBalances> assert_transfer(const Root& candidate, const Root& before_root,
                                                    const Root& after_root, const Point& owner_secret,
                                                    std::uint64_t bound, std::uint64_t expected_before,
                                                    std::uint64_t expected_after, const Root& destination_before = {},
                                                    const Root& destination_after = {},
                                                    const std::optional<Point>& receiver_secret = std::nullopt) {
  TRY_STATUS(assert_private_input(candidate));
  TRY_STATUS(assert_private_account(before_root));
  TRY_STATUS(assert_private_account(after_root));
  TRY_RESULT(input, decode_workchain_transfer_input(candidate));
  TRY_RESULT(before, decode_workchain_confidential_account(before_root));
  TRY_RESULT(after, decode_workchain_confidential_account(after_root));
  TRY_STATUS(same_identity(before, after));
  const auto& claims = workchain_transfer_claims(input.data);
  if (claims.source.account != before.address.account || claims.source.instance != before.address.instance ||
      claims.source.workchain_id != before.address.workchain_id)
    return alarm("transfer source mismatch");
  TRY_RESULT(old_value, decrypt(before.available, owner_secret, bound));
  TRY_RESULT(new_value, decrypt(after.available, owner_secret, bound));
  TRY_STATUS(assert_balance(old_value, expected_before));
  TRY_STATUS(assert_balance(new_value, expected_after));
  TRY_RESULT(old_receipts, receipt_hashes(before));
  TRY_RESULT(new_receipts, receipt_hashes(after));
  std::uint64_t moved = 0;
  if (const auto* collect = std::get_if<WorkchainCollectData>(&input.data)) {
    for (const auto& selected : collect->selected) {
      auto it = old_receipts.find(selected.receipt_id);
      if (it == old_receipts.end() || new_receipts.count(selected.receipt_id))
        return alarm("selected receipt not consumed exactly once");
      for (const auto& receipt : before.pending)
        if (receipt.receipt_id == selected.receipt_id) {
          TRY_RESULT(value, decrypt(receipt.ciphertext, owner_secret, bound));
          TRY_RESULT(sum, checked_sum(moved, value));
          moved = sum;
        }
      old_receipts.erase(it);
    }
    if (old_receipts != new_receipts)
      return alarm("unselected pending changed");
    TRY_RESULT(total, checked_sum(old_value, moved));
    if (claims.authorized_fee > total)
      return alarm("COLLECT fee exceeds funds");
    TRY_STATUS(assert_balance(new_value, total - claims.authorized_fee));
  } else {
    const auto& send = std::get<WorkchainSendData>(input.data);
    TRY_RESULT(value, decrypt({send.transfer.commitment, send.transfer.sender_handle}, owner_secret, bound));
    moved = value;
    TRY_RESULT(debit, checked_sum(moved, claims.authorized_fee));
    if (debit > old_value)
      return alarm("SEND debit exceeds funds");
    TRY_STATUS(assert_balance(new_value, old_value - debit));
    if (!receiver_secret)
      return alarm("missing receiver test key");
    bool self = send.destination.workchain_id == before.address.workchain_id &&
                send.destination.account == before.address.account &&
                send.destination.instance == before.address.instance;
    Root db = self ? before_root : destination_before, da = self ? after_root : destination_after;
    TRY_STATUS(assert_private_account(db));
    TRY_STATUS(assert_private_account(da));
    TRY_RESULT(receiver_before, decode_workchain_confidential_account(db));
    TRY_RESULT(receiver_after, decode_workchain_confidential_account(da));
    TRY_STATUS(same_identity(receiver_before, receiver_after));
    if (send.destination.account != receiver_after.address.account ||
        send.destination.instance != receiver_after.address.instance ||
        send.destination.workchain_id != receiver_after.address.workchain_id)
      return alarm("SEND destination mismatch");
    if (!self && (receiver_before.available.commitment != receiver_after.available.commitment ||
                  receiver_before.available.handle != receiver_after.available.handle))
      return alarm("SEND credited available instead of pending");
    TRY_RESULT(rb, receipt_hashes(receiver_before));
    TRY_RESULT(ra, receipt_hashes(receiver_after));
    TRY_RESULT(id, derive_workchain_receipt_id(before.address.instance, input.claimed_operation_id, 0));
    if (rb.count(id) || !ra.count(id))
      return alarm("SEND receipt missing or reused");
    for (const auto& receipt : receiver_after.pending)
      if (receipt.receipt_id == id) {
        if (receipt.ciphertext.commitment != send.transfer.commitment ||
            receipt.ciphertext.handle != send.transfer.recipient_handle)
          return alarm("SEND receipt ciphertext mismatch");
        TRY_RESULT(credit, decrypt(receipt.ciphertext, *receiver_secret, bound));
        TRY_STATUS(assert_balance(credit, moved));
      }
    ra.erase(id);
    if (ra != rb)
      return alarm("SEND changed existing pending");
    if (!self && old_receipts != new_receipts)
      return alarm("SEND changed source pending");
  }
  return TransferBalances{old_value, new_value, moved, old_receipts.size()};
}
// One-call live consumer: read the persisted block, then check persisted states.
inline td::Result<TransferBalances> assert_block_transfer(
    const Root& block_root, const td::Bits256& entry_account, std::uint64_t logical_time, const Root& before,
    const Root& after, const Point& owner_secret, std::uint64_t bound, std::uint64_t expected_before,
    std::uint64_t expected_after, const Root& destination_before = {}, const Root& destination_after = {},
    const std::optional<Point>& receiver_secret = std::nullopt) {
  TRY_RESULT(candidate, input_from_block(block_root, entry_account, logical_time));
  return assert_transfer(candidate, before, after, owner_secret, bound, expected_before, expected_after,
                         destination_before, destination_after, receiver_secret);
}
// Actual source-side artifacts only, never a predicted refund or a recipient
// credit. Transaction output materialization is observable here; queue inclusion
// and recipient delivery require separate observations and are not asserted.
struct RefundObserved {
  Root transaction, message, accounts_before, accounts_after;
  td::Bits256 coordinator;
  std::int32_t coordinator_workchain;
  std::uint32_t gen_utime;
};
namespace refund_assertion_detail {
inline CurrencyCollection amount(std::uint64_t value) {
  auto cell = vm::CellBuilder().store_long(value, 64).finalize();
  return CurrencyCollection(vm::load_cell_slice(cell).fetch_int256(64, false));
}
inline td::Status assert_enqueued(const RefundObserved& observed, const Root& data_before, const Root& data_after,
                                  const WorkchainRegistrationFunding& historical,
                                  std::uint64_t bucket_before, std::uint64_t bucket_after) {
  if (observed.transaction.is_null() || observed.message.is_null() || observed.accounts_before.is_null() ||
      observed.accounts_after.is_null()) return alarm("refund enqueue observation missing");
  vm::AugmentedDictionary before_dict(vm::load_cell_slice_ref(observed.accounts_before), 256, tlb::aug_ShardAccounts);
  vm::AugmentedDictionary after_dict(vm::load_cell_slice_ref(observed.accounts_after), 256, tlb::aug_ShardAccounts);
  Account before(observed.coordinator_workchain, observed.coordinator.bits());
  Account after(observed.coordinator_workchain, observed.coordinator.bits());
  if (!before.unpack(before_dict.lookup(observed.coordinator), observed.gen_utime, false) ||
      !after.unpack(after_dict.lookup(observed.coordinator), observed.gen_utime, false) ||
      before.data.is_null() || after.data.is_null() || before.data->get_hash() != data_before->get_hash() ||
      after.data->get_hash() != data_after->get_hash()) return alarm("refund coordinator state observation mismatch");
  TRY_RESULT(tx, confidential_input_detail::unpack<gen::Transaction::Record>(observed.transaction));
  if (tx.account_addr != observed.coordinator || tx.outmsg_cnt != 1 ||
      after.last_trans_hash_ != observed.transaction->get_hash().bits() || after.last_trans_lt_ != tx.lt)
    return alarm("refund transaction not recorded by coordinator");
  auto update = vm::load_cell_slice(tx.state_update);
  td::Bits256 old_hash, new_hash;
  if (update.size() != 520 || update.size_refs() != 0 || update.fetch_ulong(8) != 0x72 ||
      !update.fetch_bits_to(old_hash) || !update.fetch_bits_to(new_hash) ||
      old_hash != before.total_state->get_hash().bits() || new_hash != after.total_state->get_hash().bits())
    return alarm("refund transaction state hashes mismatch");
  vm::Dictionary outgoing(tx.r1.out_msgs, 15);
  unsigned count = 0;
  if (!outgoing.check_for_each([&](td::Ref<vm::CellSlice> entry, td::ConstBitPtr, int width) {
        ++count;
        return width == 15 && entry->size_ext() == 0x10000 &&
               entry->prefetch_ref()->get_hash() == observed.message->get_hash();
      }) || count != 1) return alarm("refund message absent from transaction outputs");
  gen::Message::Record message;
  gen::CommonMsgInfo::Record_int_msg_info info;
  tos::WorkchainId source_wc, destination_wc;
  td::Bits256 source, destination;
  CurrencyCollection value, collected;
  if (!tlb::type_unpack_cell(observed.message, gen::t_Message_Any, message) ||
      !gen::csr_unpack(message.info, info) || !info.ihr_disabled || !info.bounce || info.bounced ||
      !tlb::t_MsgAddressInt.extract_std_address(info.src, source_wc, source) ||
      !tlb::t_MsgAddressInt.extract_std_address(info.dest, destination_wc, destination) ||
      source_wc != observed.coordinator_workchain || source != observed.coordinator ||
      destination_wc != historical.refund_workchain || destination != historical.refund_account ||
      !value.unpack(info.value) || !collected.unpack(tx.total_fees))
    return alarm("refund message address or profile mismatch");
  if (value != amount(historical.paid_deposit)) return alarm("refund outbound value differs from historical deposit");
  auto forward = tlb::t_Tomis.as_integer(info.fwd_fee);
  if (forward.is_null() ||
      !forward->is_valid() || !forward->unsigned_fits_bits(120)) return alarm("refund message forwarding fees malformed");
  CurrencyCollection operating_before, operating_after, fees, expected;
  if (!CurrencyCollection::sub(before.balance, amount(bucket_before), operating_before) ||
      !CurrencyCollection::sub(after.balance, amount(bucket_after), operating_after))
    return alarm("refund Native balance does not cover locked deposits");
  // Mode 1: total_fees is the already-collected action share; fwd_fee is the
  // remaining forwarding share in the message. IHR is disabled. Count each once.
  if (!CurrencyCollection::add(collected, CurrencyCollection(forward), fees) ||
      !CurrencyCollection::add(operating_after, fees, expected) || expected != operating_before)
    return alarm("refund fees were not paid by operating budget");
  return td::Status::OK();
}
}  // namespace refund_assertion_detail
inline td::Status assert_registration(const Root& coordinator_before, const Root& coordinator_after,
                                      const Root& registered_account) {
  TRY_RESULT(before, decode_workchain_coordinator_state(coordinator_before));
  TRY_RESULT(after, decode_workchain_coordinator_state(coordinator_after));
  TRY_RESULT(account, decode_workchain_confidential_account(registered_account));
  TRY_RESULT(count, checked_sum(before.system.registered_accounts, 1));
  TRY_STATUS(assert_balance(after.system.registered_accounts, count));
  TRY_RESULT(bucket, checked_sum(before.refundable_deposits, account.funding.paid_deposit));
  TRY_STATUS(assert_balance(after.refundable_deposits, bucket));
  if (!std::holds_alternative<WorkchainAccountActive>(account.lifecycle))
    return alarm("registration did not produce active account");
  return td::Status::OK();
}
inline td::Status assert_closure(const Root& coordinator_before, const Root& coordinator_after,
                                 const Root& account_before, const Root& account_after, const Point& secret,
                                 std::uint64_t bound, const RefundObserved& enqueued_refund) {
  TRY_RESULT(before, decode_workchain_coordinator_state(coordinator_before));
  TRY_RESULT(after, decode_workchain_coordinator_state(coordinator_after));
  TRY_RESULT(old, decode_workchain_confidential_account(account_before));
  TRY_RESULT(closed, decode_workchain_confidential_account(account_after));
  TRY_STATUS(same_identity(old, closed));
  TRY_STATUS(assert_balance(after.system.registered_accounts, before.system.registered_accounts));
  if (!std::holds_alternative<WorkchainAccountClosed>(closed.lifecycle) || !closed.pending.empty())
    return alarm("closure lifecycle/pending mismatch");
  if (old.funding.paid_deposit != closed.funding.paid_deposit ||
      old.funding.refund_workchain != closed.funding.refund_workchain ||
      old.funding.refund_account != closed.funding.refund_account)
    return alarm("closed historical record changed");
  TRY_RESULT(value, decrypt(closed.available, secret, bound));
  TRY_STATUS(assert_balance(value, 0));
  if (old.funding.paid_deposit > before.refundable_deposits)
    return alarm("refund bucket underflow");
  TRY_STATUS(assert_balance(after.refundable_deposits, before.refundable_deposits - old.funding.paid_deposit));
  TRY_STATUS(refund_assertion_detail::assert_enqueued(enqueued_refund, coordinator_before, coordinator_after,
      old.funding, before.refundable_deposits, after.refundable_deposits));
  return td::Status::OK();
}
// Each optional is populated by an actual observer. Missing observation is NEVER
// zero. The caller identifies the exact activation site, not merely code -7201.
struct ClosedObservation {
  bool delivered;
  std::string refusal_site;
  std::optional<std::uint64_t> transactions, candidate_exports;
};
inline td::Result<std::string> assert_closed(const ClosedObservation& observed, td::Slice expected_activation_site) {
  if (!observed.delivered || expected_activation_site.empty() ||
      observed.refusal_site != expected_activation_site.str() || !observed.transactions || !observed.candidate_exports)
    return alarm("closed observation missing or wrong refusal site");
  if (*observed.transactions != 0 || *observed.candidate_exports != 0)
    return alarm("closed path produced transactions or candidate");
  return std::string(
      "CONFIRMED_CLOSED: observation delivered; exact activation refusal; transactions=0; candidate_exports=0");
}
}  // namespace block::m3_test
