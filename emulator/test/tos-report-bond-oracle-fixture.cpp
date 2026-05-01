/*
    TosReportBondOracle receive-context fixture.

    This fixture covers the production handler properties that tol-tester cannot
    inject: inbound value, sender address, and blockchain.now().
*/

#include "crypto/vm/boc.h"
#include "smc-envelope/SmartContract.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "vm/cells.h"

namespace {

#ifndef TOS_REPORT_BOND_ORACLE_BOC
#error "TOS_REPORT_BOND_ORACLE_BOC must be defined by CMake"
#endif

constexpr td::uint32 kOpDeploy = 0x424f5200;
constexpr td::uint32 kOpStartRound = 0x424f5201;
constexpr td::uint32 kOpSubmitReport = 0x424f5202;
constexpr td::uint32 kOpFinalize = 0x424f5203;

constexpr int kThrowUnauthorized = 4865;
constexpr int kThrowInsufficientBond = 4866;
constexpr int kThrowStaleRound = 3332;
constexpr int kThrowUnauthorizedStarter = 3338;

constexpr td::uint64 kMinBond = 1'000'000'000;
constexpr td::uint64 kBelowMinBond = 999'999'999;
constexpr td::uint64 kAccountBalance = 100'000'000'000ULL;

block::StdAddress std_address(unsigned char byte) {
  block::StdAddress address;
  address.workchain = 0;
  address.addr.as_slice().fill(byte);
  return address;
}

block::StdAddress reporter1_address() {
  return std_address(0x11);
}

block::StdAddress reporter2_address() {
  return std_address(0x22);
}

block::StdAddress reporter3_address() {
  return std_address(0x33);
}

block::StdAddress starter_address() {
  return std_address(0x77);
}

block::StdAddress attacker_address() {
  return std_address(0x88);
}

void store_std_address(vm::CellBuilder& cb, const block::StdAddress& address) {
  td::BigInt256 addr;
  addr.import_bits(address.addr.as_bitslice());
  cb.store_ones(1).store_zeroes(2).store_long(address.workchain, 8).store_int256(addr, 256);
}

td::Ref<vm::Cell> load_code_boc(const char* path) {
  auto buf = td::read_file(td::CSlice{path});
  CHECK(buf.is_ok());
  auto cell = vm::std_boc_deserialize(buf.move_as_ok().as_slice());
  CHECK(cell.is_ok());
  return cell.move_as_ok();
}

td::Ref<vm::Cell> empty_storage() {
  vm::CellBuilder cb;
  return cb.finalize();
}

td::Ref<vm::Cell> build_reporter_addresses() {
  vm::CellBuilder cb;
  store_std_address(cb, reporter1_address());
  store_std_address(cb, reporter2_address());
  store_std_address(cb, reporter3_address());
  return cb.finalize();
}

td::Ref<vm::Cell> build_deploy_body() {
  vm::CellBuilder cb;
  cb.store_long(kOpDeploy, 32);
  cb.store_ref(build_reporter_addresses());
  store_std_address(cb, starter_address());
  cb.store_long(2, 16);
  cb.store_long(60, 32);
  cb.store_long(200, 64);
  return cb.finalize();
}

td::Ref<vm::Cell> build_start_round_body(td::uint64 query_id, td::uint64 round_id) {
  vm::CellBuilder cb;
  cb.store_long(kOpStartRound, 32);
  cb.store_long(static_cast<long long>(query_id), 64);
  cb.store_long(static_cast<long long>(round_id), 64);
  return cb.finalize();
}

td::Ref<vm::Cell> build_submit_report_body(td::uint64 query_id, td::uint64 round_id, td::uint64 value) {
  vm::CellBuilder cb;
  cb.store_long(kOpSubmitReport, 32);
  cb.store_long(static_cast<long long>(query_id), 64);
  cb.store_long(static_cast<long long>(round_id), 64);
  cb.store_long(static_cast<long long>(value), 64);
  return cb.finalize();
}

td::Ref<vm::Cell> build_finalize_body(td::uint64 query_id, td::uint64 round_id) {
  vm::CellBuilder cb;
  cb.store_long(kOpFinalize, 32);
  cb.store_long(static_cast<long long>(query_id), 64);
  cb.store_long(static_cast<long long>(round_id), 64);
  return cb.finalize();
}

td::Ref<tos::SmartContract> make_contract() {
  tos::SmartContract::State state{load_code_boc(TOS_REPORT_BOND_ORACLE_BOC), empty_storage()};
  return tos::SmartContract::create(std::move(state));
}

tos::SmartContract::Args context_args(const tos::SmartContract& contract, block::StdAddress sender, td::uint64 value,
                                      int now) {
  return tos::SmartContract::Args()
      .set_amount(value)
      .set_balance(kAccountBalance)
      .set_address(contract.get_address(tos::basechainId))
      .set_sender_address(sender)
      .set_now(now);
}

void deploy_contract(tos::SmartContract& contract) {
  auto answer = contract.send_internal_message(build_deploy_body(), context_args(contract, starter_address(), kMinBond, 1));
  CHECK(answer.code == 0);
}

void start_round(tos::SmartContract& contract, td::uint64 round_id = 1, int now = 10) {
  auto answer =
      contract.send_internal_message(build_start_round_body(2, round_id), context_args(contract, starter_address(), kMinBond, now));
  CHECK(answer.code == 0);
}

long long get_int(const tos::SmartContract& contract, td::int32 method_id) {
  auto answer = contract.run_get_method(tos::SmartContract::Args().set_method_id(method_id));
  CHECK(answer.code == 0);
  CHECK(answer.stack->depth() == 1);
  return answer.stack.write().pop_int()->to_long();
}

bool get_bool(const tos::SmartContract& contract, td::int32 method_id) {
  return get_int(contract, method_id) != 0;
}

long long get_bond(const tos::SmartContract& contract, td::uint64 reporter_key) {
  auto answer = contract.run_get_method(
      tos::SmartContract::Args({td::make_refint(reporter_key)}).set_method_id(0x4b03));
  CHECK(answer.code == 0);
  CHECK(answer.stack->depth() == 1);
  return answer.stack.write().pop_int()->to_long();
}

}  // namespace

TEST(TosReportBondOracle, DeployAndStartUseTrustedSenderAndNow) {
  auto contract = make_contract();
  deploy_contract(contract.write());

  auto unauthorized = contract.write().send_internal_message(build_start_round_body(2, 1),
                                                            context_args(contract.write(), attacker_address(), kMinBond,
                                                                         10));
  CHECK(unauthorized.code == kThrowUnauthorizedStarter);

  start_round(contract.write());
  CHECK(get_int(contract.write(), 0x4b02) == 1);
  CHECK(get_bool(contract.write(), 0x4b04));
}

TEST(TosReportBondOracle, ValueCoinsGateReportSubmission) {
  auto contract = make_contract();
  deploy_contract(contract.write());
  start_round(contract.write());

  auto below_min = contract.write().send_internal_message(build_submit_report_body(3, 1, 1000),
                                                          context_args(contract.write(), reporter1_address(),
                                                                       kBelowMinBond, 20));
  CHECK(below_min.code == kThrowInsufficientBond);
  CHECK(get_bond(contract.write(), 1) == 0);

  auto accepted = contract.write().send_internal_message(build_submit_report_body(4, 1, 1000),
                                                         context_args(contract.write(), reporter1_address(), kMinBond,
                                                                      21));
  CHECK(accepted.code == 0);
  CHECK(get_bond(contract.write(), 1) == static_cast<long long>(kMinBond));
}

TEST(TosReportBondOracle, SenderAddressIsReporterIdentity) {
  auto contract = make_contract();
  deploy_contract(contract.write());
  start_round(contract.write());

  auto unauthorized = contract.write().send_internal_message(build_submit_report_body(3, 1, 1000),
                                                            context_args(contract.write(), attacker_address(), kMinBond,
                                                                         20));
  CHECK(unauthorized.code == kThrowUnauthorized);

  auto accepted = contract.write().send_internal_message(build_submit_report_body(4, 1, 1000),
                                                         context_args(contract.write(), reporter2_address(), kMinBond,
                                                                      21));
  CHECK(accepted.code == 0);
  CHECK(get_bond(contract.write(), 2) == static_cast<long long>(kMinBond));
}

TEST(TosReportBondOracle, BlockchainNowControlsFreshness) {
  auto contract = make_contract();
  deploy_contract(contract.write());
  start_round(contract.write(), 1, 10);

  auto in_window = contract.write().send_internal_message(build_submit_report_body(3, 1, 1000),
                                                          context_args(contract.write(), reporter1_address(), kMinBond,
                                                                       69));
  CHECK(in_window.code == 0);

  auto stale = contract.write().send_internal_message(build_submit_report_body(4, 1, 1100),
                                                      context_args(contract.write(), reporter2_address(), kMinBond,
                                                                   70));
  CHECK(stale.code == kThrowStaleRound);
}

TEST(TosReportBondOracle, FinalizeClearsBondsAfterQuorum) {
  auto contract = make_contract();
  deploy_contract(contract.write());
  start_round(contract.write(), 1, 10);

  auto r1 = contract.write().send_internal_message(build_submit_report_body(3, 1, 1000),
                                                   context_args(contract.write(), reporter1_address(), kMinBond, 20));
  CHECK(r1.code == 0);
  auto r2 = contract.write().send_internal_message(build_submit_report_body(4, 1, 1100),
                                                   context_args(contract.write(), reporter2_address(), kMinBond, 21));
  CHECK(r2.code == 0);

  auto finalized = contract.write().send_internal_message(build_finalize_body(5, 1),
                                                          context_args(contract.write(), attacker_address(), kMinBond,
                                                                       22));
  CHECK(finalized.code == 0);
  CHECK(get_int(contract.write(), 0x4b01) == 1050);
  CHECK(get_bond(contract.write(), 1) == 0);
  CHECK(!get_bool(contract.write(), 0x4b04));
}
