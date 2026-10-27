/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// Measurement, not a test: the latency of recording one own decision in the decision log,
// against the session journal's synced RocksDB write it replaces, with several sessions
// (a masterchain and shard groups) recording at once on one disk.
//
//   bench-decision-log <dir> <sessions> <paced-seconds> <burst-per-session>
//
// Paced: every session records one decision every 200 ms, two a 400 ms slot. Burst: every
// session records back to back. Both stores are measured the same way, from the request to
// its acknowledgement, in the same process, on the same filesystem.

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "td/actor/actor.h"
#include "td/actor/coro_utils.h"
#include "td/utils/Time.h"
#include "td/utils/logging.h"
#include "validator/consensus/bus.h"
#include "validator/consensus/signing-ledger.h"

using namespace tos;
using namespace tos::validator::consensus;

namespace {

td::Bits256 fill(unsigned value) {
  td::Bits256 out = td::Bits256::zero();
  std::memcpy(out.data(), &value, sizeof(value));
  return out;
}

void report(const std::string& what, std::vector<double> ms) {
  std::sort(ms.begin(), ms.end());
  auto at = [&](double q) {
    return ms.empty() ? 0.0 : ms[std::min(ms.size() - 1, static_cast<size_t>(q * static_cast<double>(ms.size())))];
  };
  std::printf("%-48s n=%-6zu p50=%7.3f ms  p95=%7.3f ms  p99=%7.3f ms  max=%7.3f ms\n", what.c_str(), ms.size(),
              at(0.50), at(0.95), at(0.99), ms.empty() ? 0.0 : ms.back());
  std::fflush(stdout);
}

class Bench : public td::actor::Actor {
 public:
  Bench(std::string dir, unsigned sessions, double paced_seconds, unsigned burst)
      : dir_(std::move(dir)), sessions_(sessions), paced_seconds_(paced_seconds), burst_(burst) {
  }

  td::actor::Task<> run() {
    CHECK(signing::create_ledger(dir_ + "/signing-ledger", fill(0x77)).is_ok());
    ledger_ = td::actor::create_actor<signing::SigningLedger>("bench-ledger", dir_ + "/signing-ledger");
    for (unsigned i = 0; i < sessions_; ++i) {
      admissions_.push_back(
          co_await td::actor::ask(ledger_.get(), &signing::SigningLedger::admit, fill(0x77), fill(1000 + i)));
      CHECK(!admissions_.back()->fenced);
      journals_.push_back(open_rocksdb_consensus_db(PSTRING() << dir_ << "/journal-" << i));
    }
    for (bool paced : {true, false}) {
      for (bool log : {true, false}) {
        latencies_.clear();
        done_ = 0;
        for (unsigned i = 0; i < sessions_; ++i) {
          drive(i, log, paced).start().detach();
        }
        while (done_.load() < sessions_) {
          co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
        }
        report(PSTRING() << (log ? "decision log fdatasync" : "journal rocksdb synced set") << ", "
                         << (paced ? "paced" : "burst") << ", " << sessions_ << " sess",
               latencies_);
      }
    }
    std::_Exit(0);
  }

 private:
  td::actor::Task<> drive(unsigned session, bool log, bool paced) {
    const unsigned count = paced ? static_cast<unsigned>(paced_seconds_ * 5) : burst_;
    for (unsigned k = 0; k < count; ++k) {
      const auto slot = next_slot_++;
      const double start = td::Time::now();
      if (log) {
        auto r = co_await td::actor::ask(admissions_[session]->log, &signing::SessionDecisionLog::reserve,
                                         signing::Decision{signing::DecisionKind::Skip, slot, td::Bits256::zero()});
        CHECK(r.result == signing::ReserveResult::Reserved);
      } else {
        auto key = td::BufferSlice(PSTRING() << "intent-" << slot);
        auto value = td::BufferSlice(std::string(96, 'v'));
        co_await journals_[session]->set(std::move(key), std::move(value));
      }
      latencies_.push_back((td::Time::now() - start) * 1000.0);
      if (paced) {
        co_await td::actor::coro_sleep(td::Timestamp::at(start + 0.2));
      }
    }
    ++done_;
    co_return td::Unit{};
  }

  std::string dir_;
  unsigned sessions_;
  double paced_seconds_;
  unsigned burst_;
  td::actor::ActorOwn<signing::SigningLedger> ledger_;
  std::vector<std::shared_ptr<const signing::Admission>> admissions_;
  std::vector<std::unique_ptr<Db>> journals_;
  std::vector<double> latencies_;
  std::atomic<unsigned> done_{0};
  std::uint32_t next_slot_ = 0;
};

}  // namespace

int main(int argc, char** argv) {
  if (argc != 5) {
    std::fprintf(stderr, "usage: %s <dir> <sessions> <paced-seconds> <burst-per-session>\n", argv[0]);
    return 2;
  }
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::actor::Scheduler scheduler({4});
  td::actor::ActorOwn<Bench> bench;
  scheduler.run_in_context([&] {
    bench = td::actor::create_actor<Bench>("bench", argv[1], static_cast<unsigned>(std::atoi(argv[2])),
                                           std::atof(argv[3]), static_cast<unsigned>(std::atoi(argv[4])));
    td::actor::ask(bench, &Bench::run).detach();
  });
  while (scheduler.run(1)) {
  }
  return 0;
}
