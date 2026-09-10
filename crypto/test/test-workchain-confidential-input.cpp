#include "block/workchain-confidential-input.h"
#include "workchain-m3-business-config.h"
#include <limits>
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
  auto wire = block::confidential_input_detail::unpack<block::gen::UnoV2TransferInputV1::Record_uno_v2_transfer_input_v1>(original).move_as_ok();
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

namespace {
block::WorkchainReplayContext replay_context() {
  return {{2, 1, 1, 1, 37, 2, number(1), number(2)},
          {number(3), number(4), number(5)}, {number(6), number(7), number(8)},
          number(9), 100, {2, number(10), number(11)}, 12, 13, 14};
}
}
TEST(ConfidentialInput, PermanentRegistrationAndClosure) {
  using namespace block;
  WorkchainRegistrationReplayInput registration{number(21), replay_context(), {}};
  WorkchainClosureReplayInput closure{number(22), replay_context(), {}};
  for (unsigned i = 0; i < registration.proof.size(); ++i) registration.proof[i] = static_cast<unsigned char>(i);
  for (unsigned i = 0; i < closure.proof.size(); ++i) closure.proof[i] = static_cast<unsigned char>(i + 1);
  for (const WorkchainReplayInput& input : {WorkchainReplayInput{registration}, WorkchainReplayInput{closure}}) {
    auto root = encode_workchain_replay_input(input).move_as_ok();
    auto context = encode_workchain_replay_context(input).move_as_ok();
    ASSERT_EQ(context.size(), 426u);
    auto bytes = vm::std_boc_serialize(root, 0).move_as_ok();
    auto decoded = decode_workchain_replay_input(vm::std_boc_deserialize(bytes).move_as_ok()).move_as_ok();
    ASSERT_EQ(decoded.index(), input.index());
    ASSERT_EQ(encode_workchain_replay_input(decoded).move_as_ok()->get_hash(), root->get_hash());
    ASSERT_EQ(encode_workchain_replay_context(decoded).move_as_ok(), context);
    ASSERT_TRUE(decode_workchain_transfer_input(root).is_error());
    auto block_root = structural_block(root);
    auto block_bytes = vm::std_boc_serialize(block_root, 0).move_as_ok();
    auto persisted = recover_input(vm::std_boc_deserialize(block_bytes).move_as_ok());
    ASSERT_EQ(encode_workchain_replay_input(decode_workchain_replay_input(persisted).move_as_ok())
                  .move_as_ok()->get_hash(), root->get_hash());
    std::cout << "replay_variant=" << input.index() << " input_boc_bytes=" << bytes.size()
              << " structural_block_bytes=" << block_bytes.size() << std::endl;
    std::visit([&](const auto& value) {
      using T = std::decay_t<decltype(value)>;
      if constexpr (!std::is_same_v<T, WorkchainTransferInput>) {
        ASSERT_TRUE(check_workchain_claimed_operation_id(input, value.claimed_operation_id).is_ok());
        auto mismatch = check_workchain_claimed_operation_id(input, number(99));
        ASSERT_TRUE(mismatch.is_error());
        ASSERT_EQ(mismatch.code(), -7200);
        ASSERT_EQ(mismatch.message(), "claimed operationID mismatch");
        // Each byte survives extraction from the permanent transaction path and
        // is committed by the enclosing block, not merely by a sidecar/file.
        for (std::size_t i = 0; i < value.proof.size(); ++i) {
          auto changed = value; changed.proof[i] ^= 1;
          auto changed_root = encode_workchain_replay_input(WorkchainReplayInput{changed}).move_as_ok();
          ASSERT_TRUE(structural_block(changed_root)->get_hash() != block_root->get_hash());
          auto round = decode_workchain_replay_input(recover_input(structural_block(changed_root))).move_as_ok();
          ASSERT_EQ(std::get<T>(round).proof[i], changed.proof[i]);
          ASSERT_EQ(encode_workchain_replay_context(WorkchainReplayInput{changed}).move_as_ok(), context);
          ASSERT_EQ(std::get<T>(round).claimed_operation_id, value.claimed_operation_id);
        }
        auto changed = value;
        ++changed.context.available_revision;
        ASSERT_TRUE(encode_workchain_replay_context(WorkchainReplayInput{changed}).move_as_ok() != context);
      }
    }, input);
    // Old non-family tag with otherwise identical framing: tag, not truncation.
    auto old = vm::load_cell_slice(root);
    old.advance(32);
    auto unknown = vm::CellBuilder().store_long(0x55534e31, 32).append_cellslice(old).finalize();
    auto bad_tag = decode_workchain_replay_input(unknown);
    ASSERT_TRUE(bad_tag.is_error());
    ASSERT_EQ(bad_tag.error().message(), "unknown confidential replay tag");
    auto extra = vm::CellBuilder().append_cellslice(vm::load_cell_slice(root))
        .store_ref(vm::CellBuilder().finalize()).finalize();
    ASSERT_TRUE(decode_workchain_replay_input(extra).is_error());
    auto slice = vm::load_cell_slice(root);
    auto context_ref = slice.fetch_ref();
    auto auth_ref = slice.fetch_ref();
    auto missing = vm::CellBuilder().append_cellslice(slice).store_ref(context_ref).finalize();
    ASSERT_TRUE(decode_workchain_replay_input(missing).is_error());
    auto proof_slice = vm::load_cell_slice(auth_ref);
    proof_slice.advance(8);
    auto short_proof = vm::CellBuilder().append_cellslice(proof_slice).finalize();
    auto short_input = vm::CellBuilder().append_cellslice(slice)
        .store_ref(context_ref).store_ref(short_proof).finalize();
    auto bad_proof = decode_workchain_replay_input(short_input);
    ASSERT_TRUE(bad_proof.is_error());
    ASSERT_EQ(bad_proof.error().message(), "noncanonical confidential authorization chain");
    // Revision must physically exist, even when a caller would prefer zero.
    auto ctx = confidential_input_detail::unpack<gen::UnoV2ReplayContextV1::Record>(context_ref).move_as_ok();
    auto subject = confidential_input_detail::unpack<gen::UnoV2ReplaySubjectV1::Record>(ctx.subject).move_as_ok();
    auto sub_slice = vm::load_cell_slice(ctx.subject);
    const auto sub_tag = sub_slice.fetch_ulong(32);
    ctx.subject = vm::CellBuilder().store_long(sub_tag, 32).store_long(subject.auth_nonce, 64)
        .store_long(subject.key_epoch, 32).store_ref(subject.address).finalize();
    auto missing_revision = vm::CellBuilder().append_cellslice(slice)
        .store_ref(pack(ctx)).store_ref(auth_ref).finalize();
    auto bad_revision = decode_workchain_replay_input(missing_revision);
    ASSERT_TRUE(bad_revision.is_error());
    ASSERT_EQ(bad_revision.error().message(), "malformed confidential input record");
  }
  // Existing SEND/COLLECT encodings remain accepted with identical bytes by
  // the unified entry; their crypto relation IDs have not been extended.
  for (const auto& transfer : vectors()) {
    auto before = encode_workchain_transfer_input(transfer).move_as_ok();
    auto after = encode_workchain_replay_input(decode_workchain_replay_input(before).move_as_ok()).move_as_ok();
    ASSERT_EQ(before->get_hash(), after->get_hash());
  }
}

TEST(ConfidentialInput, ClosureIdentityRecomputedFromAuthenticatedInputs) {
  using namespace block;
  const gen::UnoV2OperationNetworkV1::Record authenticated_network{37, number(31), number(32)};
  const WorkchainConfidentialAddress authenticated_source{2, number(33), number(34)};
  const std::uint64_t consumed_nonce = 19;
  const auto recomputed = derive_workchain_closure_operation_id(
      authenticated_network, authenticated_source, consumed_nonce).move_as_ok();
  WorkchainClosureReplayInput closure{recomputed, replay_context(), {}};
  closure.context.subject = authenticated_source;
  closure.context.auth_nonce = consumed_nonce;
  closure.context.protocol.global_id = authenticated_network.global_id;
  closure.context.protocol.genesis_hash = authenticated_network.genesis_hash;
  closure.context.protocol.workchain_instance = authenticated_network.workchain_instance;
  auto persisted = encode_workchain_replay_input(WorkchainReplayInput{closure}).move_as_ok();
  auto decoded = decode_workchain_replay_input(recover_input(structural_block(persisted))).move_as_ok();
  ASSERT_TRUE(check_workchain_claimed_operation_id(decoded, recomputed).is_ok());
  closure.claimed_operation_id = number(99);
  auto forged = decode_workchain_replay_input(encode_workchain_replay_input(WorkchainReplayInput{closure})
      .move_as_ok()).move_as_ok();
  // The claimed digest is decoded, but never becomes any derivation input.
  auto rejected = check_workchain_claimed_operation_id(forged,
      derive_workchain_closure_operation_id(authenticated_network, authenticated_source, consumed_nonce).move_as_ok());
  ASSERT_TRUE(rejected.is_error());
  ASSERT_EQ(rejected.code(), static_cast<int>(WorkchainExecutionFailure::CandidateInvalid));
  ASSERT_EQ(rejected.message(), "claimed operationID mismatch");

  ASSERT_TRUE(derive_workchain_operation_id(authenticated_network, authenticated_source, 1, consumed_nonce)
      .move_as_ok() != recomputed);
  ASSERT_TRUE(derive_workchain_operation_id(authenticated_network, authenticated_source, 2, consumed_nonce)
      .move_as_ok() != recomputed);
  ASSERT_TRUE(derive_workchain_closure_operation_id(authenticated_network, authenticated_source, consumed_nonce + 1)
      .move_as_ok() != recomputed);
  auto network = authenticated_network; network.workchain_instance = number(35);
  ASSERT_TRUE(derive_workchain_closure_operation_id(network, authenticated_source, consumed_nonce).move_as_ok() != recomputed);
  auto source = authenticated_source; source.instance = number(36);
  ASSERT_TRUE(derive_workchain_closure_operation_id(authenticated_network, source, consumed_nonce).move_as_ok() != recomputed);
  source = authenticated_source; source.account = number(37);
  ASSERT_TRUE(derive_workchain_closure_operation_id(authenticated_network, source, consumed_nonce).move_as_ok() != recomputed);
  auto before = encode_workchain_replay_context(closure.context, WorkchainReplayOperation::Closure).move_as_ok();
  ++closure.context.available_revision;
  ASSERT_TRUE(encode_workchain_replay_context(closure.context, WorkchainReplayOperation::Closure).move_as_ok() != before);
  ASSERT_EQ(derive_workchain_closure_operation_id(authenticated_network, authenticated_source, consumed_nonce)
      .move_as_ok(), recomputed);
}


TEST(ConfidentialInput, TestBusinessParametersExactCodec) {
  using namespace block;
  using namespace block::m3_test;
  static_assert(!std::is_default_constructible_v<M3TestBusinessParameters>);
  std::array<unsigned char, 80> domain;
  domain.fill(0x2a);
  M3TestBusinessParameters value{{1000000, 10000, 8, 1024, 4096}, domain, 11, 17,
      {number(1), number(2), number(3)}, number(4), number(5), number(6), 100, 2, 1, 2};
  auto root = encode_m3_test_business_parameters(value).move_as_ok();
  auto bytes = vm::std_boc_serialize(root, 0).move_as_ok();
  auto decoded = decode_m3_test_business_parameters(vm::std_boc_deserialize(bytes).move_as_ok()).move_as_ok();
  ASSERT_EQ(decoded.limits.max_balance, 1000000u);
  ASSERT_EQ(decoded.limits.max_value, 10000u);
  ASSERT_EQ(decoded.limits.max_collect, 8u);
  ASSERT_EQ(decoded.limits.max_context_bytes, 1024u);
  ASSERT_EQ(decoded.limits.max_proof_bytes, 4096u);
  ASSERT_EQ(decoded.domain, domain);
  ASSERT_EQ(decoded.send_fee, 11u); ASSERT_EQ(decoded.collect_fee, 17u);
  ASSERT_EQ(decoded.rules.asset, number(1)); ASSERT_EQ(decoded.rules.custody, number(2));
  ASSERT_EQ(decoded.rules.policy, number(3));
  ASSERT_EQ(decoded.generator_profile, number(4)); ASSERT_EQ(decoded.range_profile, number(5));
  ASSERT_EQ(decoded.fee_profile, number(6)); ASSERT_EQ(decoded.fee_effective_height, 100u);
  ASSERT_EQ(decoded.account_schema, 2u); ASSERT_EQ(decoded.relation_profile, 1u); ASSERT_EQ(decoded.proof_profile, 2u);
  ASSERT_EQ(encode_m3_test_business_parameters(decoded).move_as_ok()->get_hash(), root->get_hash());
  // Each explicit field contributes to the parameter cell. The host separately
  // tests its authenticated enclosing-config binding into the proof statement.
  std::vector<M3TestBusinessParameters> changed;
  auto alter = [&](auto f) { auto copy = value; f(copy); changed.push_back(copy); };
  alter([](auto& x) { ++x.limits.max_balance; });
  alter([](auto& x) { ++x.limits.max_value; });
  alter([](auto& x) { ++x.limits.max_collect; });
  alter([](auto& x) { ++x.limits.max_context_bytes; });
  alter([](auto& x) { ++x.limits.max_proof_bytes; });
  alter([](auto& x) { x.domain[79] ^= 1; });
  alter([](auto& x) { ++x.send_fee; }); alter([](auto& x) { ++x.collect_fee; });
  alter([](auto& x) { x.rules.asset = number(20); });
  alter([](auto& x) { x.rules.custody = number(20); });
  alter([](auto& x) { x.rules.policy = number(20); });
  alter([](auto& x) { x.generator_profile = number(20); });
  alter([](auto& x) { x.range_profile = number(20); });
  alter([](auto& x) { x.fee_profile = number(20); });
  alter([](auto& x) { ++x.fee_effective_height; });
  alter([](auto& x) { ++x.account_schema; });
  alter([](auto& x) { ++x.relation_profile; });
  alter([](auto& x) { ++x.proof_profile; });
  for (const auto& copy : changed)
    ASSERT_TRUE(encode_m3_test_business_parameters(copy).move_as_ok()->get_hash() != root->get_hash());

  auto slice = vm::load_cell_slice(root);
  std::array<td::Ref<vm::Cell>, 4> refs;
  for (auto& ref : refs) ref = slice.fetch_ref();
  auto rebuild = [&](const vm::CellSlice& bits, const auto& children) {
    vm::CellBuilder b; b.append_cellslice(bits);
    for (const auto& ref : children) b.store_ref(ref);
    return td::Ref<vm::Cell>{b.finalize()};
  };
  auto tail = slice; tail.advance(32);
  auto unknown_bits = vm::CellBuilder().store_long(0, 32).append_cellslice(tail).finalize();
  auto unknown = decode_m3_test_business_parameters(rebuild(vm::load_cell_slice(unknown_bits), refs));
  ASSERT_TRUE(unknown.is_error()); ASSERT_EQ(unknown.error().message(), "unknown M3 test business tag");
  tail = slice; tail.advance(48);
  auto version_bits = vm::CellBuilder().store_long(business_config_detail::tag, 32).store_long(2, 16)
      .append_cellslice(tail).finalize();
  auto version = decode_m3_test_business_parameters(rebuild(vm::load_cell_slice(version_bits), refs));
  ASSERT_TRUE(version.is_error()); ASSERT_EQ(version.error().message(), "unsupported M3 test business version");
  std::vector<td::Ref<vm::Cell>> missing{refs[0], refs[1], refs[2]};
  ASSERT_TRUE(decode_m3_test_business_parameters(rebuild(slice, missing)).is_error());
  auto truncated_bits = slice; truncated_bits.advance(16);
  ASSERT_TRUE(decode_m3_test_business_parameters(rebuild(truncated_bits, refs)).is_error());
  for (unsigned i = 0; i < refs.size(); ++i) {
    auto bad = refs;
    bad[i] = vm::CellBuilder().append_cellslice(vm::load_cell_slice(refs[i]))
        .store_ref(vm::CellBuilder().finalize()).finalize();
    ASSERT_TRUE(decode_m3_test_business_parameters(rebuild(slice, bad)).is_error());
    bad = refs;
    auto short_cell = vm::load_cell_slice(refs[i]); short_cell.advance(8);
    bad[i] = vm::CellBuilder().append_cellslice(short_cell).finalize();
    ASSERT_TRUE(decode_m3_test_business_parameters(rebuild(slice, bad)).is_error());
  }
  value.send_fee = UINT64_MAX; value.limits.max_balance = UINT64_MAX;
  value.limits.max_collect = std::numeric_limits<std::size_t>::max();
  auto wide = decode_m3_test_business_parameters(encode_m3_test_business_parameters(value).move_as_ok()).move_as_ok();
  ASSERT_EQ(wide.send_fee, UINT64_MAX); ASSERT_EQ(wide.limits.max_balance, UINT64_MAX);
  ASSERT_EQ(wide.limits.max_collect, std::numeric_limits<std::size_t>::max());
}
