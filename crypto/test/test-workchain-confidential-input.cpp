#include "block/workchain-confidential-input.h"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include "block/block-parse.h"
#include <fstream>
#include <iostream>
#include <sstream>

TEST(ConfidentialInput, AuthorizationChain) {
  using namespace block::confidential_input_detail;
  for (std::size_t size : {1u, 126u, 127u, 128u, 1312u, 3392u, 4096u}) {
    std::string bytes(size, '\0');
    for (std::size_t i = 0; i < size; ++i) bytes[i] = static_cast<char>(i % 251);
    auto root = encode_bytes(bytes, size);
    ASSERT_TRUE(root.is_ok());
    auto decoded = decode_bytes(root.ok(), size);
    ASSERT_TRUE(decoded.is_ok());
    ASSERT_EQ(decoded.ok(), bytes);
    ASSERT_EQ(encode_bytes(decoded.ok(), size).move_as_ok()->get_hash(), root.ok()->get_hash());
    auto missing = decode_bytes(root.ok(), size + 1);
    ASSERT_TRUE(missing.is_error());
  }
  ASSERT_TRUE(encode_bytes("", 0).is_error());
  ASSERT_TRUE(decode_bytes({}, 4097).is_error());

  // Correct total bytes, wrong segmentation: accepting this would give one
  // authorization multiple cell encodings. The failure is not missing bytes.
  vm::CellBuilder tail;
  tail.store_bytes(std::string(2, 'x'));
  vm::CellBuilder head;
  head.store_bytes(std::string(126, 'x')).store_ref(tail.finalize());
  auto malformed = decode_bytes(head.finalize(), 128);
  ASSERT_TRUE(malformed.is_error());
  ASSERT_EQ(malformed.error().message(), "noncanonical confidential authorization chain");

  vm::CellBuilder extra;
  extra.store_bytes("x", 1).store_ref(vm::CellBuilder().finalize());
  auto trailing = decode_bytes(extra.finalize(), 1);
  ASSERT_TRUE(trailing.is_error());
  ASSERT_EQ(trailing.error().message(), "noncanonical confidential authorization chain");
}

namespace {
td::Bits256 number(unsigned value) {
  auto result = td::Bits256::zero(); result.as_slice()[31] = static_cast<char>(value); return result;
}
std::vector<td::Bits256> words(const std::string& hex) {
  auto bytes = td::hex_decode(hex).move_as_ok();
  CHECK(bytes.size() % 32 == 0);
  td::Slice cursor(bytes);
  std::vector<td::Bits256> result;
  while (!cursor.empty()) result.push_back(block::confidential_input_detail::read_word(cursor));
  return result;
}
block::WorkchainTransferInput vector_input(const std::vector<std::string>& f) {
  auto p = words(f[5]); auto ids = words(f[6]);
  block::WorkchainTransferClaims claims{{2, number(1), number(2)}, 7, 8, 9, 100, 3};
  block::WorkchainTransferData data;
  if (f[0] == "1") {
    data = block::WorkchainSendData{claims, {2, number(3), number(4)}, 10,
                                  {p[4], p[5]}, {p[6], p[7], p[8]}, p[9]};
  } else {
    std::vector<block::WorkchainCollectItem> selected;
    for (std::size_t i = 0; i < ids.size(); ++i) selected.push_back({ids[i], p[8 + i * 3]});
    data = block::WorkchainCollectData{claims, {p[3], p[4]}, p[5], selected};
  }
  auto id = block::derive_workchain_operation_id({3, number(5), number(6)}, claims.source,
                                                block::workchain_transfer_kind(data), claims.auth_nonce).move_as_ok();
  return {id, data, {words(f[7]), words(f[8]), td::hex_decode(f[9]).move_as_ok()}};
}
std::vector<block::WorkchainTransferInput> vectors() {
  std::ifstream file(UNO_BALANCE_VECTOR_FILE);
  CHECK(file.good());
  std::vector<block::WorkchainTransferInput> out;
  std::string line;
  while (std::getline(file, line)) {
    if (line.empty()) continue;
    std::vector<std::string> fields;
    std::stringstream stream(line); std::string field;
    while (std::getline(stream, field, '|')) fields.push_back(field);
    CHECK(fields.size() == 12);
    out.push_back(vector_input(fields));
  }
  CHECK(out.size() == 9);
  return out;
}

template <class R> td::Ref<vm::Cell> pack(const R& value) {
  auto result = block::confidential_state_detail::pack(value);
  if (result.is_error()) std::cerr << "pack failure: " << typeid(R).name() << std::endl;
  return result.move_as_ok();
}
// Structural DA commitment through the EXISTING persistent transaction path.
// This is a hash/serialization test, not a valid execution/candidate claim:
// unrelated BlockInfo/ValueFlow/state-update and host execution fields are stubs.
td::Ref<vm::Cell> structural_block(const td::Ref<vm::Cell>& candidate) {
  using namespace block;
  auto empty = vm::CellBuilder().finalize();
  auto absent = vm::CellBuilder().store_long(0, 1).as_cellslice_ref();
  auto fees = vm::CellBuilder().store_zeroes(5).as_cellslice_ref();
  auto domain = pack(gen::UnoV2HostDomain::Record{3, number(1), number(2), 2, 0x8000000000000000ULL});
  auto policy = pack(gen::UnoV2HostPolicy::Record{number(3), false, 0x554e4f32, 0, 1, 4});
  auto context = pack(gen::UnoV2HostContext::Record{number(4), 1, 1, 1, empty});
  auto identity = pack(gen::UnoV2HostIdentity::Record{domain, policy, context});
  auto access = pack(gen::UnoV2HostAccess::Record{absent, absent});
  auto input = pack(gen::UnoV2HostInput::Record{identity, access, candidate, absent});
  auto native = pack(gen::UnoV2NativeEffects::Record_uno_v2_native_effects{absent, absent});
  auto effects = pack(gen::UnoV2HostEffects::Record{absent, native, absent, absent, 0, 0, 0});
  auto binding = pack(gen::UnoV2HostRecord::Record{input->get_hash().bits(), effects->get_hash().bits(), number(1), 0});
  auto descr = pack(gen::TransactionDescr::Record_trans_workchain_entry_v3{binding, input, effects});
  auto update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
  gen::Transaction::Record tx;
  tx.account_addr = number(1); tx.lt = 1; tx.prev_trans_hash = number(0); tx.prev_trans_lt = 0;
  tx.now = 1; tx.outmsg_cnt = 0; tx.orig_status = 0; tx.end_status = 0;
  tx.r1.in_msg = absent;
  tx.r1.out_msgs = absent;
  tx.total_fees = fees; tx.state_update = update; tx.description = descr;
  vm::AugmentedDictionary transactions(64, block::tlb::aug_AccountTransactions);
  CHECK(transactions.set_ref(td::BitArray<64>{1LL}, pack(tx)));
  auto account = pack(gen::AccountBlock::Record{number(1), vm::load_cell_slice_ref(transactions.get_root_cell()), update});
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccountBlocks);
  CHECK(accounts.set(number(1), vm::load_cell_slice(account)));
  auto extra = pack(gen::BlockExtra::Record{empty, empty, accounts.get_wrapped_dict_root(), number(0), number(0), absent});
  return pack(gen::Block::Record{3, empty, empty, empty, extra});
}
td::Ref<vm::Cell> recover_input(const td::Ref<vm::Cell>& block_cell) {
  using namespace block;
  auto root = confidential_input_detail::unpack<gen::Block::Record>(block_cell).move_as_ok();
  auto extra = confidential_input_detail::unpack<gen::BlockExtra::Record>(root.extra).move_as_ok();
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(extra.account_blocks), 256, block::tlb::aug_ShardAccountBlocks);
  gen::AccountBlock::Record account;
  auto account_slice = accounts.lookup(number(1));
  CHECK(account_slice.not_null());
  CHECK(gen::t_AccountBlock.unpack(account_slice.write(), account));
  vm::AugmentedDictionary transactions(vm::DictNonEmpty(), account.transactions, 64, block::tlb::aug_AccountTransactions);
  auto tx = confidential_input_detail::unpack<gen::Transaction::Record>(transactions.lookup_ref(td::BitArray<64>{1LL})).move_as_ok();
  auto descr = confidential_input_detail::unpack<gen::TransactionDescr::Record_trans_workchain_entry_v3>(tx.description).move_as_ok();
  auto host = confidential_input_detail::unpack<gen::UnoV2HostInput::Record>(descr.input).move_as_ok();
  return host.candidate;
}
}

TEST(ConfidentialInput, FormalVectorsAndSizes) {
  unsigned row = 0;
  for (const auto& input : vectors()) {
    auto encoded = block::encode_workchain_transfer_input(input).move_as_ok();
    auto decoded = block::decode_workchain_transfer_input(encoded).move_as_ok();
    ASSERT_EQ(decoded.claimed_operation_id, input.claimed_operation_id);
    ASSERT_EQ(decoded.authorization.range_proof, input.authorization.range_proof);
    ASSERT_EQ(decoded.authorization.commitments, input.authorization.commitments);
    ASSERT_EQ(decoded.authorization.responses, input.authorization.responses);
    ASSERT_EQ(block::encode_workchain_transfer_input(decoded).move_as_ok()->get_hash(), encoded->get_hash());
    ASSERT_EQ(block::workchain_transfer_claims(decoded.data).expiry_height, 100u);
    ASSERT_EQ(block::workchain_transfer_claims(decoded.data).key_epoch, 9u);
    auto boc = vm::std_boc_serialize(encoded, 0).move_as_ok();
    auto restored = vm::std_boc_deserialize(boc).move_as_ok();
    ASSERT_EQ(block::decode_workchain_transfer_input(restored).move_as_ok().authorization.range_proof,
              input.authorization.range_proof);
    std::cout << "vector=" << ++row << " kind=" << block::workchain_transfer_kind(input.data)
              << " input_boc_bytes=" << boc.size() << std::endl;
  }
}

TEST(ConfidentialInput, ProofIsPermanentlyCommittedButNotIdentity) {
  auto input = vectors()[0];
  auto original_data = block::encode_workchain_transfer_data(input.data).move_as_ok();
  auto original = block::encode_workchain_transfer_input(input).move_as_ok();
  auto block_root = structural_block(original);
  auto bytes = vm::std_boc_serialize(block_root, 0).move_as_ok();
  auto disk_block = vm::std_boc_deserialize(bytes).move_as_ok();
  auto recovered = block::decode_workchain_transfer_input(recover_input(disk_block)).move_as_ok();
  ASSERT_EQ(recovered.authorization.range_proof, input.authorization.range_proof);
  ASSERT_EQ(recovered.authorization.commitments, input.authorization.commitments);
  ASSERT_EQ(recovered.authorization.responses, input.authorization.responses);
  auto empty_bytes = vm::std_boc_serialize(structural_block(vm::CellBuilder().finalize()), 0).move_as_ok();
  ASSERT_TRUE(bytes.size() > empty_bytes.size());
  std::cout << "structural_block_bytes=" << bytes.size() << " empty_candidate_block_bytes="
            << empty_bytes.size() << " input_delta_bytes=" << bytes.size() - empty_bytes.size() << std::endl;
  // Change each authorization byte, not merely one representative segment.
  auto wire = block::confidential_input_detail::unpack<block::gen::UnoV2TransferInputV1::Record>(original).move_as_ok();
  auto auth = block::confidential_input_detail::decode_bytes(wire.authorization, 1312).move_as_ok();
  for (std::size_t i = 0; i < auth.size(); ++i) {
    auto changed = auth; changed[i] ^= 1;
    auto changed_wire = wire;
    changed_wire.authorization = block::confidential_input_detail::encode_bytes(changed, changed.size()).move_as_ok();
    auto candidate = pack(changed_wire);
    ASSERT_TRUE(candidate->get_hash() != original->get_hash());
    ASSERT_TRUE(structural_block(candidate)->get_hash() != block_root->get_hash());
    auto decoded = block::decode_workchain_transfer_input(candidate).move_as_ok();
    ASSERT_EQ(block::encode_workchain_transfer_data(decoded.data).move_as_ok()->get_hash(), original_data->get_hash());
    ASSERT_EQ(decoded.claimed_operation_id, input.claimed_operation_id);
  }
  auto mismatch = input; mismatch.claimed_operation_id = number(99);
  auto status = block::check_workchain_claimed_operation_id(mismatch, input.claimed_operation_id);
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(status.code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  ASSERT_EQ(status.message(), "claimed operationID mismatch");
  ASSERT_TRUE(block::check_workchain_claimed_operation_id(input, input.claimed_operation_id).is_ok());
}

TEST(ConfidentialInput, ExactFramingAndFixedContext) {
  auto input = vectors()[0];
  auto encoded = block::encode_workchain_transfer_input(input).move_as_ok();
  auto unknown = vm::CellBuilder().store_long(0, 32).store_zeroes(256)
      .store_ref(encoded).store_ref(encoded).finalize();
  auto rejected = block::decode_workchain_transfer_input(unknown);
  ASSERT_TRUE(rejected.is_error());
  ASSERT_EQ(rejected.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  auto truncated = vm::CellBuilder().append_cellslice(vm::load_cell_slice(encoded)).store_long(1, 1).finalize();
  ASSERT_TRUE(block::decode_workchain_transfer_input(truncated).is_error());
  input.authorization.responses.pop_back();
  auto missing = block::encode_workchain_transfer_input(input);
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().message(), "confidential proof shape mismatch");

  block::WorkchainTransferContext context{
    {2, 1, 1, 2, 1, 3, 2, number(1), number(2)},
    {number(3), number(4), number(5)}, {number(6), number(7), number(8)},
    {number(9), number(10), number(11)}, number(12), 100};
  auto bytes = block::encode_workchain_transfer_context(context).move_as_ok();
  ASSERT_EQ(bytes.size(), 427u);
  context.profiles.generator_profile = number(13);
  ASSERT_TRUE(block::encode_workchain_transfer_context(context).move_as_ok() != bytes);
  context.protocol.wire_version = 0;
  ASSERT_TRUE(block::encode_workchain_transfer_context(context).is_error());
}
