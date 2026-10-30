/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// The own-decision log (validator/consensus/signing-ledger.h): its conflict rules, its file
// formats and limits, its bindings, and the serialized, failure-safe reservation path.
//
// Every case runs in one process, against real files in a private scratch directory. File
// operations that must fail are replaced through FileOps; a reservation that must be held
// between its check and its write is held through the log's write gate.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "td/actor/actor.h"
#include "td/actor/coro_utils.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "tos/tos-shard.h"
#include "validator/consensus/signing-ledger.h"

using namespace tos;
using namespace tos::validator::consensus::signing;

namespace {

[[noreturn]] void fail(const std::string& what) {
  std::fprintf(stderr, "SIGNING_LEDGER_FAILED: %s\n", what.c_str());
  std::fflush(stderr);
  std::_Exit(1);
}

void require(bool condition, const std::string& what) {
  if (!condition) {
    fail(what);
  }
}

td::Bits256 fill(unsigned char byte) {
  td::Bits256 value;
  std::memset(value.data(), byte, 32);
  return value;
}

Decision notar(std::uint32_t slot, unsigned char candidate) {
  return Decision{DecisionKind::Notarize, slot, fill(candidate)};
}
Decision final_vote(std::uint32_t slot, unsigned char candidate) {
  return Decision{DecisionKind::Finalize, slot, fill(candidate)};
}
Decision skip(std::uint32_t slot) {
  return Decision{DecisionKind::Skip, slot, td::Bits256::zero()};
}
Decision window(std::uint32_t index) {
  return Decision{DecisionKind::LeaderWindow, index, td::Bits256::zero()};
}

std::string scratch() {
  std::string pattern = "/tmp/tos-signing-ledger-XXXXXX";
  char* made = ::mkdtemp(pattern.data());
  require(made != nullptr, "mkdtemp");
  return made;
}

// ===== The conflict rules, without files =====

void test_index() {
  struct Case {
    std::vector<Decision> before;
    Decision next;
    Check expected;
    const char* what;
  };
  const std::vector<Case> cases = {
      {{}, notar(1, 0xA), Check::New, "a first notarize"},
      {{notar(1, 0xA)}, notar(1, 0xA), Check::Same, "the same notarize"},
      {{notar(1, 0xA)}, notar(1, 0xB), Check::Conflict, "two notarizations"},
      {{final_vote(1, 0xA)}, final_vote(1, 0xB), Check::Conflict, "two finalizations"},
      {{notar(1, 0xA)}, final_vote(1, 0xB), Check::Conflict, "finalize disagrees with notarize"},
      {{final_vote(1, 0xB)}, notar(1, 0xA), Check::Conflict, "notarize disagrees with finalize"},
      {{notar(1, 0xA)}, final_vote(1, 0xA), Check::New, "finalize of the notarized candidate"},
      {{final_vote(1, 0xA)}, skip(1), Check::Conflict, "skip after finalize"},
      {{skip(1)}, final_vote(1, 0xA), Check::Conflict, "finalize after skip"},
      {{notar(1, 0xA)}, skip(1), Check::New, "skip beside notarize"},
      {{skip(1)}, notar(1, 0xA), Check::New, "notarize beside skip"},
      {{skip(1)}, skip(1), Check::Same, "the same skip"},
      {{notar(1, 0xA)}, notar(2, 0xB), Check::New, "another slot"},
      {{window(3)}, window(3), Check::Same, "a leader window again"},
      {{window(3)}, window(4), Check::New, "another leader window"},
      {{window(3)}, skip(3), Check::New, "a vote is not a leader window"},
  };
  for (const auto& c : cases) {
    DecisionIndex index;
    for (const auto& d : c.before) {
      require(index.check(d) == Check::New, std::string("setup of ") + c.what);
      index.apply(d);
    }
    require(index.check(c.next) == c.expected, c.what);
  }
  std::printf("index: %zu cases\n", cases.size());
}

// ===== The unknown-history fence, as a rule =====

void test_fence_rule() {
  const ShardIdFull all{basechainId, shardIdAll};
  const ShardIdFull left{basechainId, shard_child(shardIdAll, true)};
  const ShardIdFull right{basechainId, shard_child(shardIdAll, false)};
  const ShardIdFull left_left{basechainId, shard_child(left.shard, true)};
  const ShardIdFull left_right{basechainId, shard_child(left.shard, false)};
  const ShardIdFull masterchain{masterchainId, shardIdAll};

  // A merge of unequal children: the prospective parent's tentative counter is
  // max(children) + 2, fenced through the larger child's entry.
  {
    const std::vector<FenceEntry> fence = {{basechainId, left.shard, 5}, {basechainId, right.shard, 7}};
    require(fenced_by_history(fence, all, 9), "the merged parent's tentative counter max + 2 is fenced");
    require(!fenced_by_history(fence, all, 10), "the merged parent above max + 2 is admitted");
  }
  // Descendants after further splits inherit the lineage.
  {
    const std::vector<FenceEntry> fence = {{basechainId, shardIdAll, 20}, {masterchainId, shardIdAll, 30}};
    require(fenced_by_history(fence, left_left, 21), "a grandchild at +1 is fenced");
    require(fenced_by_history(fence, left_right, 22), "a grandchild at +2 is fenced");
    require(!fenced_by_history(fence, left_left, 23), "a grandchild at +3 is admitted");
  }
  // The first admitted counter of each lineage is +3.
  {
    const std::vector<FenceEntry> fence = {{masterchainId, shardIdAll, 100}, {basechainId, shardIdAll, 40}};
    for (std::uint32_t d = 0; d <= 2; ++d) {
      require(fenced_by_history(fence, masterchain, 100 + d), "the masterchain up to +2 is fenced");
      require(fenced_by_history(fence, all, 40 + d), "the basechain up to +2 is fenced");
    }
    require(!fenced_by_history(fence, masterchain, 103), "the masterchain at +3 is admitted");
    require(!fenced_by_history(fence, all, 43), "the basechain at +3 is admitted");
    require(fenced_by_history(fence, masterchain, 5), "an old masterchain counter is fenced too");
  }
  // Near the top of the counter range: no wrap.
  {
    const std::uint32_t top = std::numeric_limits<std::uint32_t>::max();
    const std::vector<FenceEntry> fence = {{masterchainId, shardIdAll, top - 2}};
    require(fenced_by_history(fence, masterchain, top - 1), "a counter just below the top is fenced");
    require(fenced_by_history(fence, masterchain, 0), "a small counter is fenced, not admitted by a wrap");
    require(fenced_by_history(fence, masterchain, 1), "a small counter is fenced, not admitted by a wrap");
    require(fenced_by_history(fence, masterchain, kCounterSentinel), "the sentinel is fenced");
    // An entry whose counter + 2 passes the top of the 32-bit range.
    const std::vector<FenceEntry> wrapping = {{masterchainId, shardIdAll, top - 1}};
    require(fenced_by_history(wrapping, masterchain, top - 1), "counter + 2 past the top does not wrap");
    require(fenced_by_history(wrapping, masterchain, 5), "a small counter under a wrapping entry is fenced");
    const std::vector<FenceEntry> low = {{masterchainId, shardIdAll, 3}};
    require(fenced_by_history(low, masterchain, kCounterSentinel), "the sentinel is fenced whatever the entry");
  }
  // A workchain absent at the fence block is fenced, whatever its configuration says.
  {
    const std::vector<FenceEntry> fence = {{masterchainId, shardIdAll, 10}, {basechainId, shardIdAll, 10}};
    require(fenced_by_history(fence, ShardIdFull{7, shardIdAll}, 1000), "an absent workchain is fenced");
    require(fenced_by_history({}, all, 1000), "an empty fence fences everything");
  }
  // A split child not yet in the configuration reads its parent's counter (the ancestor
  // branch), so the parent's entry fences the child's tentative session at parent + 2.
  {
    const std::vector<FenceEntry> fence = {{masterchainId, shardIdAll, 10}, {basechainId, shardIdAll, 5}};
    require(fenced_by_history(fence, left, 5), "a split child at the parent's counter is fenced");
    require(fenced_by_history(fence, right, 7), "a split child's tentative parent + 2 is fenced");
    require(!fenced_by_history(fence, right, 8), "a split child at parent + 3 is admitted");
  }
  std::printf("fence rule: ok\n");
}

// ===== Which block may be the fence block, and t0 =====

void test_fence_block_rule() {
  const BlockIdExt id{masterchainId, shardIdAll, 7, fill(0x07), fill(0x5f)};
  const std::vector<FenceEntry> two = {{masterchainId, shardIdAll, 50}, {basechainId, shardIdAll, 70}};
  // t0 is rounded up from a fractional clock: 1000.4 is 1001, and the block must be generated
  // at 1092 or later. The times are written out, not derived from the constant.
  require(custody_time(1000.4) == 1001, "a fractional custody time is rounded up");
  require(custody_time(1000.0) == 1000, "a whole custody time stays");
  const auto t0 = custody_time(1000.4);
  require(fence_block_refusal(FenceBlock{id, 1091, two}, t0).has_value(), "t0 + 90 is refused");
  require(!fence_block_refusal(FenceBlock{id, 1092, two}, t0).has_value(), "t0 + 91 is accepted");
  // Exactly kMaxFenceEntries lineages are accepted, one more is refused.
  std::vector<FenceEntry> at_cap;
  for (std::size_t i = 0; i < kMaxFenceEntries; ++i) {
    at_cap.push_back({basechainId, static_cast<std::uint64_t>(i) * 2 + 1, 70});
  }
  require(at_cap.size() == 256, "the cap is 256 lineages");
  require(!fence_block_refusal(FenceBlock{id, 2000, at_cap}, t0).has_value(), "256 lineages are accepted");
  at_cap.push_back({basechainId, 0x8000000000000000ULL, 70});
  require(fence_block_refusal(FenceBlock{id, 2000, at_cap}, t0).has_value(), "257 lineages are refused");
  require(fence_block_refusal(FenceBlock{id, 2000, {}}, t0).has_value(), "an empty fence is refused");
  require(fence_block_refusal(FenceBlock{id, 2000, {{masterchainId, shardIdAll, kCounterSentinel}}}, t0).has_value(),
          "a lineage without a counter is refused");
  // No admission is never "sign without a record".
  auto fenced = admission_for_validator_group(nullptr, fill(0x31));
  require(fenced != nullptr && fenced->fenced && fenced->signing_stopped(),
          "a validator group built without an admission signs nothing");
  auto given = Admission::fence(fill(0x32), "given");
  require(admission_for_validator_group(given, fill(0x32)) == given, "a given admission is kept");
  std::printf("fence block rule: ok\n");
}

// ===== Records and logs =====

void write_all(int fd, const std::string& bytes) {
  require(::pwrite(fd, bytes.data(), bytes.size(), 0) == static_cast<ssize_t>(bytes.size()), "pwrite");
}

std::string records(const td::Bits256& session, const std::vector<Decision>& decisions) {
  std::string out;
  auto chain = chain_start(session);
  std::int64_t seq = 0;
  for (const auto& d : decisions) {
    std::array<unsigned char, 16> next{};
    out += encode_record(d, seq++, chain, next);
    chain = next;
  }
  return out;
}

int fresh_file(const std::string& path, const std::string& bytes) {
  const int fd = ::open(path.c_str(), O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
  require(fd >= 0, "create " + path);
  write_all(fd, bytes);
  return fd;
}

void test_log_format(const std::string& dir) {
  const auto session = fill(0x42);
  const std::vector<Decision> decisions = {notar(1, 0xA), final_vote(1, 0xA), skip(2), window(0)};
  const auto bytes = records(session, decisions);
  {
    const int fd = fresh_file(dir + "/round", bytes);
    auto loaded = load_log(fd, session);
    require(loaded.is_ok(), "round trip loads");
    require(loaded.ok().decisions.size() == decisions.size() && !loaded.ok().torn_tail, "round trip is whole");
    for (std::size_t i = 0; i < decisions.size(); ++i) {
      require(loaded.ok().decisions[i].second == decisions[i], "round trip keeps the decisions");
    }
    // The chain binds the session: the same bytes are not another session's log.
    require(load_log(fd, fill(0x43)).is_error(), "another session's log is refused");
    ::close(fd);
  }
  {
    const int fd = fresh_file(dir + "/torn", bytes + std::string(10, '\x55'));
    auto loaded = load_log(fd, session);
    require(loaded.is_ok() && loaded.ok().torn_tail && loaded.ok().decisions.size() == decisions.size(),
            "a partial last record is a torn tail, not an error");
    ::close(fd);
  }
  {
    auto damaged = bytes;
    damaged[kRecordBytes + 5] ^= 1;  // inside the second record's body
    const int fd = fresh_file(dir + "/damaged", damaged);
    require(load_log(fd, session).is_error(), "a damaged record breaks the chain");
    ::close(fd);
  }
  {
    const int fd = fresh_file(dir + "/conflict", records(session, {notar(1, 0xA), notar(1, 0xB)}));
    require(load_log(fd, session).is_error(), "a log holding two conflicting decisions is refused");
    ::close(fd);
  }
  {
    // Refused from its size alone, before it is read: the file is sparse.
    const int fd = ::open((dir + "/huge").c_str(), O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    require(fd >= 0 && ::ftruncate(fd, static_cast<off_t>(kMaxLogBytes + 2 * kRecordBytes)) == 0, "huge log");
    require(load_log(fd, session).is_error(), "a log above the limit is refused");
    ::close(fd);
  }
  {
    // At the limit it loads; one record more is refused.
    std::vector<Decision> many;
    for (std::uint32_t i = 0; i < kMaxLogRecords; ++i) {
      many.push_back(skip(i));
    }
    auto full = records(session, many);
    const int fd = fresh_file(dir + "/full", full);
    auto loaded = load_log(fd, session);
    require(loaded.is_ok() && loaded.ok().decisions.size() == kMaxLogRecords, "a log at the limit loads");
    many.push_back(skip(kMaxLogRecords));
    write_all(fd, records(session, many));
    require(load_log(fd, session).is_error(), "a log one record above the limit is refused");
    ::close(fd);
  }
  std::printf("log format: ok\n");
}

// ===== The normal-progress estimate, without files =====

void test_capacity_estimate() {
  // Production: 250 s at 400 ms is 625 slots and 157 windows of 4.
  auto production = estimate_session_records(250, 400, 4);
  require(production.verdict == CapacityVerdict::Fits && production.estimate == 3 * 625 + 157,
          "the production lifetime fits");
  // Development: 100,000 s is 250,000 slots, 812,500 records: above half of the ceiling.
  auto development = estimate_session_records(100'000, 400, 4);
  require(development.verdict == CapacityVerdict::Warn && development.estimate == 812'500,
          "the development lifetime is admitted with a warning");
  auto too_long = estimate_session_records(200'000, 400, 4);
  require(too_long.verdict == CapacityVerdict::Refuse && too_long.estimate == 1'625'000 &&
              too_long.reason.find("exceeds") != std::string::npos,
          "a lifetime above the ceiling is refused");
  // Rounded up: 4 s at 1,000 ms is 4 slots and 1 window, 13 records.
  require(estimate_session_records(4, 1000, 4, 26).verdict == CapacityVerdict::Fits, "13 of 26 fits");
  require(estimate_session_records(4, 1000, 4, 25).verdict == CapacityVerdict::Warn, "13 of 25 warns");
  require(estimate_session_records(4, 1000, 4, 13).verdict == CapacityVerdict::Warn, "13 of 13 is admitted");
  require(estimate_session_records(4, 1000, 4, 12).verdict == CapacityVerdict::Refuse, "13 of 12 is refused");
  require(estimate_session_records(4, 1500, 4, 100).estimate == 3 * 3 + 1, "partial slots round up");
  require(estimate_session_records(0, 400, 4).verdict == CapacityVerdict::Fits, "no lifetime records nothing");
  // Zero, negative and overflowing inputs are refused, never estimated.
  auto zero_rate = estimate_session_records(250, 0, 4);
  require(zero_rate.verdict == CapacityVerdict::Refuse && zero_rate.reason.find("target rate") != std::string::npos,
          "a zero target rate is refused");
  require(estimate_session_records(250, -400, 4).verdict == CapacityVerdict::Refuse,
          "a negative target rate is refused");
  auto zero_window = estimate_session_records(250, 400, 0);
  require(zero_window.verdict == CapacityVerdict::Refuse && zero_window.reason.find("no slots") != std::string::npos,
          "a zero leader window is refused");
  auto overflow = estimate_session_records(std::numeric_limits<std::uint64_t>::max(), 400, 4);
  require(overflow.verdict == CapacityVerdict::Refuse && overflow.reason.find("overflows") != std::string::npos,
          "a lifetime whose milliseconds overflow is refused");
  auto overflow_records = estimate_session_records(std::numeric_limits<std::uint64_t>::max() / 1000, 1, 1);
  require(overflow_records.verdict == CapacityVerdict::Refuse &&
              overflow_records.reason.find("overflows") != std::string::npos,
          "an estimate that overflows is refused");
  std::printf("capacity estimate: ok\n");
}

void test_header_format() {
  Header header;
  header.validator = fill(0x11);
  header.dir = Binding{7, 1700000000, 5};
  header.floor = BlockIdExt{masterchainId, shardIdAll, 99, fill(0x21), fill(0x22)};
  header.entries.push_back(HeaderEntry{fill(0x31), Binding{8, 1700000001, 6}});
  header.entries.push_back(HeaderEntry{fill(0x32), Binding{}});
  auto bytes = encode_header(header);
  auto decoded = decode_header(bytes);
  require(decoded.is_ok(), "header round trip");
  require(decoded.ok().validator == header.validator && decoded.ok().dir == header.dir &&
              decoded.ok().floor == header.floor && decoded.ok().entries.size() == 2 &&
              decoded.ok().entries[0].log == header.entries[0].log && decoded.ok().entries[1].log.empty(),
          "header round trip keeps every field");
  auto damaged = bytes;
  damaged[20] ^= 1;
  require(decode_header(damaged).is_error(), "a damaged header fails its checksum");
  require(decode_header(std::string(kMaxHeaderBytes + 1, 'x')).is_error(), "an oversized header is refused");
  // An entry count larger than what follows is refused before anything is allocated.
  Header many;
  many.validator = fill(0x11);
  for (std::size_t i = 0; i <= kMaxEntries; ++i) {
    td::Bits256 session = td::Bits256::zero();
    std::memcpy(session.data(), &i, sizeof(i));
    many.entries.push_back(HeaderEntry{session, Binding{}});
  }
  require(decode_header(encode_header(many)).is_error(), "a header above the entry limit is refused");
  many.entries.pop_back();
  require(decode_header(encode_header(many)).is_ok(), "a header at the entry limit loads");
  std::printf("header format: ok\n");
}

// ===== File operations that fail on request =====

class FaultyOps : public FileOps {
 public:
  std::atomic<int> partial_writes{0};    // the next N writes stop half way
  std::atomic<int> failed_syncs{0};      // the next N data syncs fail
  std::atomic<int> failed_truncates{0};  // the next N truncations fail

  long pwrite(int fd, const void* data, std::size_t size, long offset) override {
    if (partial_writes.load() > 0) {
      --partial_writes;
      return FileOps::pwrite(fd, data, size / 2, offset);
    }
    return FileOps::pwrite(fd, data, size, offset);
  }
  int fdatasync(int fd) override {
    if (failed_syncs.load() > 0) {
      --failed_syncs;
      errno = EIO;
      return -1;
    }
    return FileOps::fdatasync(fd);
  }
  int ftruncate(int fd, long length) override {
    if (failed_truncates.load() > 0) {
      --failed_truncates;
      errno = EIO;
      return -1;
    }
    return FileOps::ftruncate(fd, length);
  }
};

// Real writes without data syncs, for tests that record many decisions.
class UnsyncedOps : public FileOps {
 public:
  int fdatasync(int) override {
    return 0;
  }
};

// ===== The ledger and the logs, through their actors =====

using GatePromise = decltype(td::actor::StartedTask<>::make_bridge().second);

struct Gate {
  std::atomic<bool> hold{false};
  std::atomic<int> held_count{0};
  std::vector<GatePromise> held;
};

class Driver : public td::actor::Actor {
 public:
  td::actor::Task<> run() {
    auto result = co_await run_inner().wrap();
    if (result.is_error()) {
      fail("harness: " + result.error().to_string());
    }
    std::printf("SIGNING_LEDGER_OK\n");
    std::fflush(stdout);
    std::_Exit(0);
  }

 private:
  const td::Bits256 validator_ = fill(0x77);

  template <typename F>
  td::actor::Task<bool> wait_until(F condition, double timeout = 10.0) {
    auto deadline = td::Timestamp::in(timeout);
    while (!condition()) {
      if (deadline.is_in_past()) {
        co_return false;
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
    }
    co_return true;
  }

  td::actor::Task<std::shared_ptr<const Admission>> admit(td::actor::ActorId<SigningLedger> ledger, td::Bits256 session,
                                                          ShardIdFull shard = ShardIdFull{masterchainId, shardIdAll},
                                                          std::uint32_t cc = 1) {
    co_return co_await td::actor::ask(ledger, &SigningLedger::admit, validator_, session, shard, cc, IdentityHistory{});
  }

  td::actor::Task<Reservation> reserve(const std::shared_ptr<const Admission>& admission, Decision d) {
    co_return co_await td::actor::ask(admission->log, &SessionDecisionLog::reserve, d);
  }

  td::actor::Task<> run_inner() {
    co_await test_absent_and_untrusted();
    co_await test_admission_and_restart();
    co_await test_replaced_log();
    co_await test_serialized_reservations();
    co_await test_failed_appends();
    co_await test_prune_and_floor();
    co_await test_unknown_history();
    co_await test_identity_history();
    co_await test_bound_identity();
    co_await test_untrusted_becomes_pending();
    co_await test_genesis_ledger();
    co_await test_persistent_creation_failure();
    co_await test_long_session();
    co_await test_ceiling_and_warnings();
    co_return td::Unit{};
  }

  // A long session: 20,000 new decisions are all recorded. The ceiling was 16,384, after
  // which the session signed nothing more. Data syncs are skipped to keep it fast.
  td::actor::Task<> test_long_session() {
    const auto dir = scratch() + "/signing-ledger";
    require(create_ledger(dir, validator_).is_ok(), "create a ledger");
    auto ledger = td::actor::create_actor<SigningLedger>("long", dir, std::make_shared<UnsyncedOps>());
    auto admission = co_await admit(ledger.get(), fill(0x0A));
    constexpr std::uint32_t kSlots = 10'000;
    for (std::uint32_t slot = 0; slot < kSlots; ++slot) {
      const unsigned char candidate = static_cast<unsigned char>(slot % 251 + 1);
      require((co_await reserve(admission, notar(slot, candidate))).result == ReserveResult::Reserved,
              PSTRING() << "notarize of slot " << slot << " is recorded");
      require((co_await reserve(admission, final_vote(slot, candidate))).result == ReserveResult::Reserved,
              PSTRING() << "finalize of slot " << slot << " is recorded");
    }
    require(!admission->signing_stopped(), "a long session keeps signing");
    require(co_await td::actor::ask(admission->log, &SessionDecisionLog::durable_records) == 2 * kSlots,
            "every decision of the long session is durable");
    std::printf("long session: ok\n");
    co_return td::Unit{};
  }

  // The ceiling, lowered to 64 for the test: a warning at 32 and at 48 records, each once;
  // the 65th decision is refused and the session stops; a restart loads the full log.
  td::actor::Task<> test_ceiling_and_warnings() {
    constexpr std::size_t kCeiling = 64;
    const auto dir = scratch() + "/signing-ledger";
    require(create_ledger(dir, validator_).is_ok(), "create a ledger");
    const auto session = fill(0x0B);
    {
      auto ledger = td::actor::create_actor<SigningLedger>("ceiling", dir, std::make_shared<UnsyncedOps>(), nullptr,
                                                           nullptr, std::nullopt, kCeiling);
      auto admission = co_await admit(ledger.get(), session);
      auto warnings = [&]() { return td::actor::ask(admission->log, &SessionDecisionLog::fill_warnings); };
      for (std::uint32_t slot = 0; slot < kCeiling; ++slot) {
        require((co_await reserve(admission, skip(slot))).result == ReserveResult::Reserved,
                PSTRING() << "record " << slot << " below the ceiling");
        const auto recorded = slot + 1;
        const int expected = recorded < kCeiling / 2 ? 0 : recorded < kCeiling / 4 * 3 ? 1 : 2;
        require(co_await warnings() == expected, PSTRING() << "the warnings after " << recorded << " records");
      }
      require(!admission->signing_stopped(), "a log at its ceiling has not stopped yet");
      require((co_await reserve(admission, skip(0))).result == ReserveResult::AlreadyDecided,
              "a decision already recorded is still answered at the ceiling");
      require((co_await reserve(admission, skip(kCeiling))).result == ReserveResult::Failed,
              "a new decision above the ceiling is refused");
      require(admission->signing_stopped(), "a full log stops its session");
      require((co_await reserve(admission, skip(0))).result == ReserveResult::Failed, "a stopped log answers nothing");
      require(co_await td::actor::ask(admission->log, &SessionDecisionLog::durable_records) == kCeiling,
              "the full log holds exactly the ceiling");
    }
    {
      auto ledger = td::actor::create_actor<SigningLedger>("ceiling-restart", dir, std::make_shared<UnsyncedOps>(),
                                                           nullptr, nullptr, std::nullopt, kCeiling);
      auto admission = co_await admit(ledger.get(), session);
      require(!admission->fenced && admission->decisions.size() == kCeiling, "a log at its ceiling reloads");
      require(co_await td::actor::ask(admission->log, &SessionDecisionLog::fill_warnings) == 2,
              "a reloaded full log has warned");
      require((co_await reserve(admission, skip(kCeiling))).result == ReserveResult::Failed,
              "the reloaded full log refuses a new decision");
    }
    {
      // A ceiling below the log's records refuses to load it: the size check is the ceiling.
      auto ledger = td::actor::create_actor<SigningLedger>("ceiling-lower", dir, std::make_shared<UnsyncedOps>(),
                                                           nullptr, nullptr, std::nullopt, kCeiling - 1);
      auto admission = co_await admit(ledger.get(), session);
      require(admission->fenced, "a log above the ceiling fences its session");
    }
    std::printf("ceiling and warnings: ok\n");
    co_return td::Unit{};
  }

  static std::function<double()> clock_at(double t) {
    return [t] { return t; };
  }

  td::actor::Task<> test_bound_identity() {
    const auto dir = scratch() + "/signing-ledger";
    const auto other = fill(0x88);
    const auto session = fill(0xA3);
    const ShardIdFull mc{masterchainId, shardIdAll};
    const auto m = fence_block(40, 1691, {{masterchainId, shardIdAll, 50}});
    require(create_ledger(dir, validator_).is_ok(), "original identity ledger");
    {
      auto ledger = td::actor::create_actor<SigningLedger>("original", dir);
      auto a = co_await admit(ledger.get(), session);
      require((co_await reserve(a, notar(1, 0xA))).result == ReserveResult::Reserved, "original decision");
    }
    {
      auto ledger =
          td::actor::create_actor<SigningLedger>("rebound", dir, default_file_ops(), nullptr, clock_at(1600), other);
      require(!(co_await td::actor::ask(ledger.get(), &SigningLedger::floor)).has_value(),
              "the previous identity's floor is not inherited");
      auto pending = co_await td::actor::ask(ledger.get(), &SigningLedger::admit, other, session, mc, std::uint32_t{53},
                                             IdentityHistory{1600, std::nullopt});
      require(pending->fenced && pending->history_unknown, "a rebound identity must establish its own history");
      auto a = co_await td::actor::ask(ledger.get(), &SigningLedger::admit, other, session, mc, std::uint32_t{53},
                                       IdentityHistory{1600, m});
      require(!a->fenced, "a rebound identity above its own fence signs");
      require((co_await reserve(a, notar(1, 0xB))).result == ReserveResult::Reserved,
              "a different identity does not reuse the previous identity's decisions");
      auto wrong = co_await admit(ledger.get(), session);
      require(wrong->fenced, "a cached admission cannot cross the bound identity");
    }
    require(::rename(dir.c_str(), (dir + ".parked").c_str()) == 0, "temporarily remove the original directory");
    {
      auto ledger = td::actor::create_actor<SigningLedger>("rebound-restart", dir, default_file_ops(), nullptr,
                                                           clock_at(1800), other);
      auto a = co_await td::actor::ask(ledger.get(), &SigningLedger::admit, other, session, mc, std::uint32_t{53},
                                       IdentityHistory{1800, std::nullopt});
      require(!a->fenced && a->decisions.size() == 1, "restart finds the identity's ledger without the original");
      require((co_await reserve(a, notar(1, 0xC))).result == ReserveResult::Conflict, "rebound decisions survive");
    }
    require(::rename((dir + ".parked").c_str(), dir.c_str()) == 0, "restore original directory");
    {
      auto ledger = td::actor::create_actor<SigningLedger>("original-return", dir, default_file_ops(), nullptr,
                                                           clock_at(1800), validator_);
      auto a = co_await admit(ledger.get(), session);
      require(!a->fenced && a->decisions.size() == 1, "return to the original identity preserves its log");
      require((co_await reserve(a, notar(1, 0xB))).result == ReserveResult::Conflict, "original decision is preserved");
    }
    for (std::size_t i = 1; i < kMaxIdentityLedgers; ++i) {
      const auto id = fill(static_cast<unsigned char>(0x90 + i));
      require(create_ledger(dir + "." + id.to_hex(), id).is_ok(), "fill retained identity limit");
    }
    const auto extra = fill(0x99);
    auto full = td::actor::create_actor<SigningLedger>("identity-limit", dir, default_file_ops(), nullptr,
                                                       clock_at(1600), extra);
    auto refused = co_await td::actor::ask(full.get(), &SigningLedger::admit, extra, session, mc, std::uint32_t{53},
                                           IdentityHistory{1600, m});
    require(refused->fenced && refused->reason.find("retained identity ledger limit") != std::string::npos,
            "one past the identity limit is refused for that reason");
    require(!std::filesystem::exists(dir + "." + extra.to_hex()), "no directory beyond the identity bound");
    std::printf("bound identity and retained directory limit: ok\n");
    co_return td::Unit{};
  }

  td::actor::Task<bool> offer(td::actor::ActorId<SigningLedger> ledger, std::uint32_t seqno, std::uint32_t gen_utime,
                              std::vector<FenceEntry> lineages) {
    co_return co_await td::actor::ask(ledger, &SigningLedger::offer_fence_block, validator_, std::uint64_t{0},
                                      fence_block(seqno, gen_utime, std::move(lineages)));
  }

  static FenceBlock fence_block(std::uint32_t seqno, std::uint32_t gen_utime, std::vector<FenceEntry> lineages) {
    return FenceBlock{BlockIdExt{masterchainId, shardIdAll, seqno, fill(static_cast<unsigned char>(seqno)), fill(0x5f)},
                      gen_utime, std::move(lineages)};
  }

  td::actor::Task<std::shared_ptr<const Admission>> admit_with(td::actor::ActorId<SigningLedger> ledger,
                                                               td::Bits256 session, std::uint32_t cc,
                                                               IdentityHistory history) {
    co_return co_await td::actor::ask(ledger, &SigningLedger::admit, validator_, session,
                                      ShardIdFull{masterchainId, shardIdAll}, cc, std::move(history));
  }

  // The identity's history as the manager passes it: its custody time t0, and the fence block
  // it applied after t0, recorded before any ledger existed.
  td::actor::Task<> test_identity_history() {
    const std::vector<FenceEntry> at_m = {{masterchainId, shardIdAll, 50}, {basechainId, shardIdAll, 70}};
    {
      // A fence block recorded before the first admission establishes the new ledger at once:
      // the elected identity signs in its first session above the fence.
      const auto dir = scratch() + "/signing-ledger";
      auto ledger = td::actor::create_actor<SigningLedger>("early-m", dir, default_file_ops(), nullptr, clock_at(1000));
      IdentityHistory history{1000, fence_block(20, 1091, at_m)};
      auto first = co_await admit_with(ledger.get(), fill(0x40), 53, history);
      require(!first->fenced, "the first session above a fence recorded before admission signs");
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Established,
              "established at its creation");
      require((co_await admit_with(ledger.get(), fill(0x41), 52, history))->fenced, "+2 stays fenced");
      auto floor = co_await td::actor::ask(ledger.get(), &SigningLedger::floor);
      require(floor.has_value() && floor->seqno() == 20, "the fence block is the floor");
    }
    {
      // t0 is the custody time when it is later than this actor's start: a block that
      // qualifies against the start does not against custody (late custody).
      const auto dir = scratch() + "/signing-ledger";
      auto ledger = td::actor::create_actor<SigningLedger>("late", dir, default_file_ops(), nullptr, clock_at(1000));
      auto early =
          co_await admit_with(ledger.get(), fill(0x42), 53, IdentityHistory{1600, fence_block(20, 1690, at_m)});
      require(early->fenced && early->history_unknown, "a block before custody + 91 leaves the history pending");
      require(early->reason.find("1691") != std::string::npos, "the wait is measured from custody");
    }
    {
      // The stored custody t0 survives a restart: a process whose own custody time reads
      // earlier (a clock stepped back) still waits from the stored one.
      const auto dir = scratch() + "/signing-ledger";
      {
        auto ledger =
            td::actor::create_actor<SigningLedger>("stored", dir, default_file_ops(), nullptr, clock_at(1000));
        require((co_await admit_with(ledger.get(), fill(0x47), 53, IdentityHistory{1600, std::nullopt}))->fenced,
                "pending from custody at 1600");
      }
      auto ledger =
          td::actor::create_actor<SigningLedger>("stored-restart", dir, default_file_ops(), nullptr, clock_at(1000));
      require(
          co_await td::actor::ask(ledger.get(), &SigningLedger::history_start, validator_, std::uint64_t{1580}) == 1600,
          "the manager reads the persisted custody lower bound before choosing a fence block");
      require(
          co_await td::actor::ask(ledger.get(), &SigningLedger::history_start, validator_, std::uint64_t{1700}) == 1700,
          "later process custody still wins");
      auto early =
          co_await admit_with(ledger.get(), fill(0x48), 53, IdentityHistory{1000, fence_block(24, 1100, at_m)});
      require(early->fenced, "a block before the stored custody t0 + 91 does not settle it after a restart");
      require(!co_await td::actor::ask(ledger.get(), &SigningLedger::offer_fence_block, validator_, std::uint64_t{1000},
                                       fence_block(25, 1690, at_m)),
              "nor does an offer measured from the earlier clock");
    }
    {
      const auto dir = scratch() + "/signing-ledger";
      auto ledger = td::actor::create_actor<SigningLedger>("late-2", dir, default_file_ops(), nullptr, clock_at(1000));
      auto early =
          co_await admit_with(ledger.get(), fill(0x42), 53, IdentityHistory{1600, fence_block(20, 1690, at_m)});
      require(early->fenced, "pending");
      require(!co_await td::actor::ask(ledger.get(), &SigningLedger::offer_fence_block, validator_, std::uint64_t{1600},
                                       fence_block(21, 1690, at_m)),
              "custody + 90 does not settle it");
      require(!co_await td::actor::ask(ledger.get(), &SigningLedger::offer_fence_block, fill(0x99), std::uint64_t{1600},
                                       fence_block(22, 1691, at_m)),
              "another identity's fence block does not settle it");
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Pending, "still pending");
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::offer_fence_block, validator_, std::uint64_t{1600},
                                      fence_block(23, 1691, at_m)),
              "custody + 91 settles it");
      require(!(co_await admit_with(ledger.get(), fill(0x43), 53, IdentityHistory{1600, std::nullopt}))->fenced,
              "+3 signs once settled");
    }
    {
      // A pending ledger of an earlier process: this process's fence block settles it at the
      // first admission, measured from the later of the stored t0 and this custody.
      const auto dir = scratch() + "/signing-ledger";
      {
        auto ledger = td::actor::create_actor<SigningLedger>("first", dir, default_file_ops(), nullptr, clock_at(9000));
        require((co_await admit_with(ledger.get(), fill(0x44), 1, IdentityHistory{}))->fenced, "pending");
      }
      auto ledger = td::actor::create_actor<SigningLedger>("second", dir, default_file_ops(), nullptr, clock_at(3000));
      auto refused =
          co_await admit_with(ledger.get(), fill(0x45), 53, IdentityHistory{3000, fence_block(30, 3091, at_m)});
      require(refused->fenced, "a block before the stored t0 + 91 does not settle a stored pending history");
      auto admitted =
          co_await admit_with(ledger.get(), fill(0x46), 53, IdentityHistory{3000, fence_block(31, 9091, at_m)});
      require(!admitted->fenced, "a block after both waits settles it at admission");
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Established, "established");
    }
    std::printf("identity history: ok\n");
    co_return td::Unit{};
  }

  td::actor::Task<> test_unknown_history() {
    const auto dir = scratch() + "/signing-ledger";
    const ShardIdFull mc{masterchainId, shardIdAll};
    const std::vector<FenceEntry> at_m = {{masterchainId, shardIdAll, 50}, {basechainId, shardIdAll, 70}};
    {
      // Started at t0 = 1000.4, rounded up to 1001.
      auto ledger =
          td::actor::create_actor<SigningLedger>("unknown", dir, default_file_ops(), nullptr, clock_at(1000.4));
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Complete,
              "nothing on disk yet");
      require((co_await admit(ledger.get(), fill(0x10), mc, 999))->fenced, "pending: fenced");
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Pending, "pending");
      // The fence block must be generated at t0 + 91 or later. The times are written out, not
      // derived from the constant, so a changed margin fails here.
      require(!co_await offer(ledger.get(), 10, 1091, at_m), "t0 + 90 is too early");
      // The fence refuses what it cannot record.
      std::vector<FenceEntry> too_many;
      for (std::size_t i = 0; i <= kMaxFenceEntries; ++i) {
        too_many.push_back({basechainId, shardIdAll, static_cast<std::uint32_t>(i)});
      }
      require(!co_await offer(ledger.get(), 11, 2000, too_many), "257 lineages are not recorded");
      require(!co_await offer(ledger.get(), 11, 2000, {{masterchainId, shardIdAll, kCounterSentinel}}),
              "a lineage without a counter is not recorded");
      require(!co_await offer(ledger.get(), 11, 2000, {}), "an empty fence is not recorded");
      require((co_await admit(ledger.get(), fill(0x11), mc, 2000))->fenced, "still pending: fenced");
    }
    {
      // A restart while pending keeps the stored t0, even though this process starts later.
      auto ledger =
          td::actor::create_actor<SigningLedger>("unknown-restart", dir, default_file_ops(), nullptr, clock_at(5000.0));
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Pending,
              "still pending after a restart");
      std::vector<FenceEntry> at_cap;
      for (std::size_t i = 0; i + 1 < kMaxFenceEntries; ++i) {
        at_cap.push_back({basechainId, static_cast<std::uint64_t>(i) * 2 + 1, 70});
      }
      at_cap.push_back(at_m.front());
      require(at_cap.size() == kMaxFenceEntries, "a fence at the cap");
      require(co_await offer(ledger.get(), 12, 1092, at_cap),
              "t0 + 91, with the stored t0, establishes the fence; 256 lineages are recorded");
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Established, "established");
      auto floor = co_await td::actor::ask(ledger.get(), &SigningLedger::floor);
      require(floor.has_value() && floor->seqno() == 12, "the fence block is the floor");
    }
    {
      auto ledger = td::actor::create_actor<SigningLedger>("established", dir);
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Established,
              "the fence is durable");
      require((co_await admit(ledger.get(), fill(0x12), mc, 52))->fenced, "the masterchain at +2 is fenced");
      auto above = co_await admit(ledger.get(), fill(0x13), mc, 53);
      require(!above->fenced, "the masterchain at +3 is admitted");
      require((co_await reserve(above, skip(1))).result == ReserveResult::Reserved, "and records");
      require((co_await admit(ledger.get(), fill(0x14), ShardIdFull{9, shardIdAll}, 1000))->fenced,
              "a workchain absent at the fence block is fenced");
      require(co_await offer(ledger.get(), 13, 9999, at_m), "a settled history stays settled");
    }
    std::printf("unknown history: ok\n");
    co_return td::Unit{};
  }

  td::actor::Task<> test_untrusted_becomes_pending() {
    const auto dir = scratch() + "/signing-ledger";
    require(create_ledger(dir, validator_).is_ok(), "create a ledger");
    const auto copy = scratch() + "/signing-ledger";
    std::filesystem::copy(dir, copy, std::filesystem::copy_options::recursive);
    {
      auto ledger = td::actor::create_actor<SigningLedger>("copied", copy);
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::status) == LedgerStatus::Untrusted,
              "a copied ledger is untrusted");
      require((co_await admit(ledger.get(), fill(0x20)))->fenced, "and admits nothing");
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Pending,
              "a pending ledger replaces it");
      require(std::filesystem::exists(copy + "/ledger.untrusted.0"), "the untrusted header is kept beside it");
    }
    {
      auto ledger = td::actor::create_actor<SigningLedger>("copied-restart", copy);
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Pending,
              "the pending ledger is trusted after a restart");
    }
    std::printf("untrusted becomes pending: ok\n");
    co_return td::Unit{};
  }

  // A ledger that stays untrusted because no pending ledger can be created (all set-aside
  // slots taken) fences every session; what it keeps, and what each reply carries, does not
  // grow with the number of admissions.
  td::actor::Task<> test_persistent_creation_failure() {
    const auto dir = scratch() + "/signing-ledger";
    require(create_ledger(dir, validator_).is_ok(), "create a ledger");
    const auto copy = scratch() + "/signing-ledger";
    std::filesystem::copy(dir, copy, std::filesystem::copy_options::recursive);
    for (int n = 0; n < 4; ++n) {
      std::ofstream(copy + "/ledger.untrusted." + std::to_string(n)) << "set aside";
    }
    auto ledger = td::actor::create_actor<SigningLedger>("stuck", copy);
    const auto initial = co_await td::actor::ask(ledger.get(), &SigningLedger::untrusted_reason);
    require(!initial.empty(), "the copied ledger is untrusted");
    std::size_t first_reply = 0;
    for (unsigned i = 0; i < 10000; ++i) {
      td::Bits256 session = td::Bits256::zero();
      std::memcpy(session.data(), &i, sizeof(i));
      session.data()[31] = 0xEE;
      auto admission = co_await admit(ledger.get(), session);
      require(admission->fenced, "nothing is admitted while no pending ledger can be created");
      if (i == 0) {
        first_reply = admission->reason.size();
        require(admission->reason.find("set aside") != std::string::npos, "the reply says why");
      }
      require(admission->reason.size() == first_reply, "a reply does not grow with the admissions before it");
    }
    require(co_await td::actor::ask(ledger.get(), &SigningLedger::untrusted_reason) == initial,
            "the retained reason does not grow with the admissions");
    require(std::filesystem::exists(copy + "/ledger"), "the untrusted header stays where it is");
    std::printf("persistent creation failure: ok (reply %zu bytes, retained %zu bytes, 10000 sessions)\n", first_reply,
                initial.size());
    co_return td::Unit{};
  }

  td::actor::Task<> test_genesis_ledger() {
    const auto dir = scratch() + "/signing-ledger";
    const BlockIdExt zerostate{masterchainId, shardIdAll, 0, fill(0x31), fill(0x32)};
    require(create_ledger(dir, validator_, default_file_ops(), zerostate).is_ok(), "the genesis ceremony's ledger");
    require(create_ledger(dir, validator_, default_file_ops(), zerostate).is_error(), "only once");
    auto ledger = td::actor::create_actor<SigningLedger>("genesis", dir);
    require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Complete, "complete");
    auto floor = co_await td::actor::ask(ledger.get(), &SigningLedger::floor);
    require(floor.has_value() && *floor == zerostate, "the history starts at the zerostate");
    require(!(co_await admit(ledger.get(), fill(0x30), ShardIdFull{masterchainId, shardIdAll}, 1))->fenced,
            "a complete ledger admits from the first session");
    require(co_await offer(ledger.get(), 1, 10, {{masterchainId, shardIdAll, 1}}), "nothing to fence");
    std::printf("genesis ledger: ok\n");
    co_return td::Unit{};
  }

  td::actor::Task<> test_absent_and_untrusted() {
    {
      // No ledger: the node's earlier signing is unknown, so a pending one is created and
      // nothing is admitted until its fence block.
      const auto absent = scratch() + "/signing-ledger";
      auto ledger = td::actor::create_actor<SigningLedger>("absent", absent);
      auto admission = co_await admit(ledger.get(), fill(0x01));
      require(admission->fenced, "no ledger: nothing is admitted");
      require(co_await td::actor::ask(ledger.get(), &SigningLedger::history) == History::Pending,
              "no ledger: a pending one replaces it");
    }
    const auto dir = scratch() + "/signing-ledger";
    require(create_ledger(dir, validator_).is_ok(), "create a ledger");
    {
      auto ledger = td::actor::create_actor<SigningLedger>("trusted", dir);
      auto other = co_await td::actor::ask(ledger.get(), &SigningLedger::admit, fill(0x99), fill(0x01),
                                           ShardIdFull{masterchainId, shardIdAll}, std::uint32_t{1}, IdentityHistory{});
      require(other->fenced, "another validator's ledger admits nothing");
    }
    // The directory copied elsewhere (a restore, a migration) is not the one written.
    const auto copy = scratch() + "/signing-ledger";
    std::filesystem::copy(dir, copy, std::filesystem::copy_options::recursive);
    {
      auto ledger = td::actor::create_actor<SigningLedger>("copied", copy);
      auto status = co_await td::actor::ask(ledger.get(), &SigningLedger::status);
      require(status == LedgerStatus::Untrusted, "a copied ledger directory is untrusted");
      auto admission = co_await admit(ledger.get(), fill(0x01));
      require(admission->fenced, "a copied ledger admits nothing");
    }
    std::printf("absent and untrusted: ok\n");
    co_return td::Unit{};
  }

  td::actor::Task<> test_admission_and_restart() {
    const auto dir = scratch() + "/signing-ledger";
    require(create_ledger(dir, validator_).is_ok(), "create a ledger");
    const auto session = fill(0x02);
    {
      auto ledger = td::actor::create_actor<SigningLedger>("first-life", dir);
      auto admission = co_await admit(ledger.get(), session);
      require(!admission->fenced && admission->decisions.empty(), "a new session is admitted with nothing decided");
      require((co_await reserve(admission, notar(5, 0xA))).result == ReserveResult::Reserved, "notarize reserved");
      require((co_await reserve(admission, notar(5, 0xA))).result == ReserveResult::AlreadyDecided,
              "the same notarize is already decided");
      require((co_await reserve(admission, notar(5, 0xB))).result == ReserveResult::Conflict,
              "a different notarize conflicts");
      require((co_await reserve(admission, window(2))).result == ReserveResult::Reserved, "a leader window reserved");
      auto again = co_await admit(ledger.get(), session);
      require(again == admission, "one session has one admission in one process");
    }
    {
      // A restart: everything recorded is there, and still refuses conflicts.
      auto ledger = td::actor::create_actor<SigningLedger>("second-life", dir);
      auto admission = co_await admit(ledger.get(), session);
      require(!admission->fenced && admission->decisions.size() == 2, "the restart sees both decisions");
      require(admission->leader_window_recorded(2) && !admission->leader_window_recorded(3),
              "the restart knows which leader windows were taken");
      require((co_await reserve(admission, notar(5, 0xB))).result == ReserveResult::Conflict,
              "the restart refuses the conflicting notarize");
      auto same = co_await reserve(admission, notar(5, 0xA));
      require(same.result == ReserveResult::AlreadyDecided && same.seq == 0, "the same decision keeps its seq");
      require((co_await reserve(admission, window(2))).result == ReserveResult::AlreadyDecided,
              "a recorded leader window is not granted again");
    }
    std::printf("admission and restart: ok\n");
    co_return td::Unit{};
  }

  td::actor::Task<> test_replaced_log() {
    const auto dir = scratch() + "/signing-ledger";
    require(create_ledger(dir, validator_).is_ok(), "create a ledger");
    const auto session = fill(0x03);
    const auto log = dir + "/log." + session.to_hex();
    {
      auto ledger = td::actor::create_actor<SigningLedger>("before", dir);
      auto admission = co_await admit(ledger.get(), session);
      require((co_await reserve(admission, skip(1))).result == ReserveResult::Reserved, "skip reserved");
    }
    // Replaced by a copy of itself: the same bytes, another file.
    std::filesystem::copy_file(log, log + ".copy");
    std::filesystem::rename(log + ".copy", log);
    {
      auto ledger = td::actor::create_actor<SigningLedger>("after", dir);
      auto admission = co_await admit(ledger.get(), session);
      require(admission->fenced, "a replaced log fences its session");
    }
    std::printf("replaced log: ok\n");
    co_return td::Unit{};
  }

  td::actor::Task<> test_serialized_reservations() {
    const auto dir = scratch() + "/signing-ledger";
    require(create_ledger(dir, validator_).is_ok(), "create a ledger");
    auto gate = std::make_shared<Gate>();
    SessionDecisionLog::WriteGate hook = [gate](const Decision&) {
      auto [task, promise] = td::actor::StartedTask<>::make_bridge();
      if (gate->hold.load()) {
        gate->held.push_back(std::move(promise));
        ++gate->held_count;
      } else {
        promise.set_value(td::Unit{});
      }
      return std::move(task);
    };
    auto ledger = td::actor::create_actor<SigningLedger>("gated", dir, default_file_ops(), hook);
    auto admission = co_await admit(ledger.get(), fill(0x04));
    gate->hold = true;
    // Two conflicting decisions; the first is held after its check and before its write.
    std::atomic<int> first{-1};
    std::atomic<int> second{-1};
    auto ask_into = [&](Decision d, std::atomic<int>* into) -> td::actor::Task<> {
      auto result = co_await td::actor::ask(admission->log, &SessionDecisionLog::reserve, d);
      into->store(static_cast<int>(result.result));
      co_return td::Unit{};
    };
    ask_into(notar(9, 0xA), &first).start().detach();
    require(co_await wait_until([&] { return gate->held_count.load() == 1; }), "the first write is held");
    ask_into(notar(9, 0xB), &second).start().detach();
    co_await td::actor::coro_sleep(td::Timestamp::in(0.3));
    require(second.load() == -1, "the second request is not answered while the first is between check and write");
    require(gate->held_count.load() == 1, "the second request did not reach its write");
    gate->hold = false;
    for (auto& promise : gate->held) {
      promise.set_value(td::Unit{});
    }
    gate->held.clear();
    require(co_await wait_until([&] { return first.load() != -1 && second.load() != -1; }), "both answered");
    require(first.load() == static_cast<int>(ReserveResult::Reserved), "the first is reserved");
    require(second.load() == static_cast<int>(ReserveResult::Conflict),
            "the second, checked after the first was recorded, conflicts");
    std::printf("serialized reservations: ok\n");
    co_return td::Unit{};
  }

  td::actor::Task<> test_failed_appends() {
    const auto dir = scratch() + "/signing-ledger";
    require(create_ledger(dir, validator_).is_ok(), "create a ledger");
    auto ops = std::make_shared<FaultyOps>();
    const auto session = fill(0x05);
    const auto log = dir + "/log." + session.to_hex();
    {
      auto ledger = td::actor::create_actor<SigningLedger>("faulty", dir, ops);
      auto admission = co_await admit(ledger.get(), session);
      require((co_await reserve(admission, skip(1))).result == ReserveResult::Reserved, "a first record");

      // A write that stopped half way: refused, the half record cut away, and the next one
      // recorded right after the first.
      ops->partial_writes = 1;
      require((co_await reserve(admission, skip(2))).result == ReserveResult::Failed, "a partial write is refused");
      require(std::filesystem::file_size(log) == kRecordBytes, "the partial record is cut away");
      require(!admission->signing_stopped(), "a recovered log keeps recording");
      require((co_await reserve(admission, skip(3))).result == ReserveResult::Reserved, "the next decision records");

      // A data sync that failed: refused, and the record it may have left is cut away.
      ops->failed_syncs = 1;
      require((co_await reserve(admission, skip(4))).result == ReserveResult::Failed, "a failed sync is refused");
      require(std::filesystem::file_size(log) == 2 * kRecordBytes, "the unsynced record is cut away");
      require((co_await reserve(admission, skip(5))).result == ReserveResult::Reserved, "and recording goes on");

      // A failure the log cannot recover from: nothing more is recorded or signed.
      ops->partial_writes = 1;
      ops->failed_truncates = 1;
      require((co_await reserve(admission, skip(6))).result == ReserveResult::Failed, "unrecoverable failure");
      require(admission->signing_stopped(), "an unrecoverable log stops its session");
      require((co_await reserve(admission, skip(7))).result == ReserveResult::Failed,
              "a stopped log records nothing more");
    }
    {
      // The restart finds the three acknowledged records, and the half record the failed
      // recovery left behind is a torn tail that is removed.
      auto ledger = td::actor::create_actor<SigningLedger>("faulty-restart", dir);
      auto admission = co_await admit(ledger.get(), session);
      require(!admission->fenced && admission->decisions.size() == 3, "only acknowledged decisions survive");
      require(std::filesystem::file_size(log) == 3 * kRecordBytes, "the torn tail is removed at load");
      require((co_await reserve(admission, skip(6))).result == ReserveResult::Reserved, "the restart records again");
    }
    std::printf("failed appends: ok\n");
    co_return td::Unit{};
  }

  td::actor::Task<> test_prune_and_floor() {
    const auto dir = scratch() + "/signing-ledger";
    require(create_ledger(dir, validator_).is_ok(), "create a ledger");
    const auto kept = fill(0x06);
    const auto pruned = fill(0x07);
    const BlockIdExt floor{masterchainId, shardIdAll, 50, fill(0x51), fill(0x52)};
    {
      auto ledger = td::actor::create_actor<SigningLedger>("prune", dir);
      auto a = co_await admit(ledger.get(), kept);
      auto b = co_await admit(ledger.get(), pruned);
      require((co_await reserve(a, skip(1))).result == ReserveResult::Reserved, "kept records");
      require((co_await reserve(b, skip(1))).result == ReserveResult::Reserved, "pruned records");
      co_await td::actor::ask(ledger.get(), &SigningLedger::prune, std::vector<td::Bits256>{pruned}, floor);
      require(!std::filesystem::exists(dir + "/log." + pruned.to_hex()), "a pruned session's log is gone");
      require(std::filesystem::exists(dir + "/log." + kept.to_hex()), "a kept session's log stays");
    }
    {
      auto ledger = td::actor::create_actor<SigningLedger>("prune-restart", dir);
      auto recorded = co_await td::actor::ask(ledger.get(), &SigningLedger::floor);
      require(recorded.has_value() && *recorded == floor, "the floor is durable");
      auto a = co_await admit(ledger.get(), kept);
      require(!a->fenced && a->decisions.size() == 1, "the kept session keeps its decision");
      // A lower floor never replaces a higher one.
      const BlockIdExt lower{masterchainId, shardIdAll, 10, fill(0x61), fill(0x62)};
      co_await td::actor::ask(ledger.get(), &SigningLedger::prune, std::vector<td::Bits256>{}, lower);
      auto after = co_await td::actor::ask(ledger.get(), &SigningLedger::floor);
      require(after.has_value() && *after == floor, "the floor only moves forward");
    }
    std::printf("prune and floor: ok\n");
    co_return td::Unit{};
  }
};

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  test_index();
  test_fence_rule();
  test_fence_block_rule();
  test_capacity_estimate();
  const auto dir = scratch();
  test_log_format(dir);
  test_header_format();

  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("signing-ledger-driver");
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
  return 0;
}
