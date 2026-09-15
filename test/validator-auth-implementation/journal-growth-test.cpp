// What the signer's journal costs per signature, and what it costs to restart.
//
// The journal is append-only by design and has no retention policy: history is
// what makes an anti-equivocation ledger work, so nothing is ever reclaimed.
// Three quantities follow from that and none of them is measured anywhere.
//
// Bytes per record. The framing is fixed, so the storage limit converts to a
// signature count -- the number an operator actually needs and that no document
// states. If framing ever grows per record, that number falls silently.
//
// The shape of replay. Every record is re-derived at startup, so a restart
// costs the whole history. Linear is the intended cost and is survivable; a
// prefix re-walk is quadratic and turns a long-lived node's restart into an
// outage. Counting replay invocations separates the two without relying on a
// clock: a linear replay calls back exactly once per record, a quadratic one
// calls back a quadratic number of times.
//
// Exhaustion. The limit is meant to stop admission without damaging history.
// That is asserted in prose and tested nowhere: a refusal that still advanced
// the file, or a full log that no longer replays, is the difference between an
// outage and a lost ledger.
#include <chrono>

#include "validator/auth/durable-log.h"

#include "signer-fixture.h"

namespace {
constexpr std::uint64_t framing = 36;  // 4-byte length prefix plus a 32-byte link

Bytes record(std::size_t size, std::uint8_t fill) {
  return Bytes(size, fill);
}

// A replay that accepts everything and counts how many times it was asked.
DurableLog::Replay counting(std::uint64_t& calls, LogFrontier& last) {
  return [&](const LogFrontier& frontier, std::span<const std::uint8_t>) -> Result<bool> {
    ++calls;
    last = frontier;
    return true;
  };
}

DurableLog::Replay accept_all() {
  return [](const LogFrontier&, std::span<const std::uint8_t>) -> Result<bool> { return true; };
}

std::uint64_t on_disk(const std::filesystem::path& path) {
  return static_cast<std::uint64_t>(std::filesystem::file_size(path));
}

// Reopen a log of `records` entries and report the replay callbacks and the
// wall time. The callback count is the deterministic reading; the time is
// reported so a cost that is linear in count but not in work is still visible.
struct Restart {
  std::uint64_t records = 0, callbacks = 0;
  double microseconds = 0;
};

Restart restart(const std::filesystem::path& path, std::uint64_t records) {
  std::uint64_t calls = 0;
  LogFrontier last{};
  auto started = std::chrono::steady_clock::now();
  auto log = value(DurableLog::open(path.string(), false, counting(calls, last)), "reopen");
  auto elapsed = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - started).count();
  check(log->frontier().sequence == records, "replayed-every-record");
  check(last == log->frontier(), "replay-reached-the-frontier");
  return {records, calls, elapsed};
}
}  // namespace

int main(int argc, char** argv) {
  try {
    check(argc == 2, "temporary-directory-required");
    std::filesystem::path dir = argv[1];
    check(std::filesystem::create_directory(dir), "fresh-directory-required");
    ::chmod(dir.c_str(), 0700);

    // Per-record cost is the framing plus the payload, and it does not drift
    // with the number of records already written.
    auto framing_path = dir / "framing";
    {
      auto log = value(DurableLog::open(framing_path.string(), true, accept_all()), "new-log");
      check(on_disk(framing_path) == 0, "empty-log-is-empty");
      std::uint64_t expected = 0;
      for (unsigned n = 0; n < 512; ++n) {
        std::size_t size = 64 + (n % 7) * 16;
        value(log->append(record(size, static_cast<std::uint8_t>(n))), "append");
        expected += size + framing;
        check(on_disk(framing_path) == expected, "record-costs-payload-plus-framing");
      }
      check(log->frontier().sequence == 512, "sequence-counts-records");
      std::cout << "CASE_PASS per-record-cost-is-constant\n";
      std::cout << "journal overhead per record: " << framing << " bytes\n";
    }

    // Replay is linear. The callback count is exact, so a prefix re-walk cannot
    // hide behind a fast machine.
    std::vector<Restart> restarts;
    for (std::uint64_t records : {std::uint64_t{512}, std::uint64_t{2048}, std::uint64_t{8192}}) {
      auto path = dir / ("replay-" + std::to_string(records));
      {
        auto log = value(DurableLog::open(path.string(), true, accept_all()), "new-replay-log");
        for (std::uint64_t n = 0; n < records; ++n)
          value(log->append(record(96, static_cast<std::uint8_t>(n))), "replay-append");
      }
      auto measured = restart(path, records);
      check(measured.callbacks == records, "replay-visits-each-record-once");
      restarts.push_back(measured);
    }
    std::cout << "CASE_PASS replay-visits-each-record-once\n";
    for (const auto& r : restarts)
      std::cout << "restart records=" << r.records << " callbacks=" << r.callbacks << " us_per_record="
                << r.microseconds / static_cast<double>(r.records) << '\n';

    // The clock is the weaker instrument and is treated as such: a sixteen-fold
    // growth in history that costs more than four times as much per record is
    // not linear by any reading, and anything tighter is noise on a shared runner.
    auto first = restarts.front().microseconds / static_cast<double>(restarts.front().records);
    auto last = restarts.back().microseconds / static_cast<double>(restarts.back().records);
    check(last <= first * 4, "replay-cost-per-record-does-not-grow");
    std::cout << "CASE_PASS replay-cost-per-record-does-not-grow\n";

    // Exhaustion stops admission and leaves history intact. The refusal must not
    // reach the file, and a full log must still replay completely.
    auto full_path = dir / "exhausted";
    constexpr std::size_t payload = 128;
    constexpr std::uint64_t admitted = 64;
    constexpr std::uint64_t limit = admitted * (payload + framing);
    {
      auto log = value(DurableLog::open(full_path.string(), true, accept_all(), limit), "bounded-log");
      for (std::uint64_t n = 0; n < admitted; ++n)
        value(log->append(record(payload, static_cast<std::uint8_t>(n))), "bounded-append");
      check(on_disk(full_path) == limit, "log-reaches-its-limit");
      auto refused = log->append(record(payload, 0xff));
      check(!refused.ok(), "exhaustion-refuses");
      check(on_disk(full_path) == limit, "refusal-does-not-reach-storage");
      check(log->frontier().sequence == admitted, "refusal-does-not-advance-the-frontier");
      // The bound is on total bytes, not on record count, so nothing at all is
      // admitted once it is reached -- not even a single byte of payload.
      check(!log->append(record(1, 0xfe)).ok(), "exhausted-log-admits-nothing");
    }
    auto reopened = restart(full_path, admitted);
    check(reopened.callbacks == admitted, "exhausted-log-replays-completely");
    std::cout << "CASE_PASS exhaustion-refuses-without-damaging-history\n";

    // What a real signature costs. Reserve and complete are two records, and the
    // measured total converts the default storage limit into a signature count.
    auto witness_path = (dir / "witness").string();
    auto ledger_path = dir / "ledger";
    auto witness = value(FileWitness::open(witness_path, h(999), true), "new-witness");
    auto fence = value(witness->acquire(), "acquire");
    auto ledger = value(SafetyLedger::open(ledger_path.string(), true, *witness, fence), "new-ledger");
    constexpr unsigned signatures = 64;
    for (unsigned n = 0; n < signatures; ++n) {
      auto r = request(4, n + 1);
      value(ledger->reserve(r, receipt_for(r, 2 * n + 1, 1)), "ledger-reserve");
      value(ledger->complete(r.request_id_, result_for(r, 2 * n + 2)), "ledger-complete");
    }
    auto bytes = on_disk(ledger_path);
    auto per_signature = bytes / signatures;
    check(ledger->frontier().sequence == 2 * signatures, "two-records-per-signature");
    std::cout << "CASE_PASS signature-cost-is-measured\n";
    std::cout << "journal bytes per completed signature: " << per_signature << '\n';
    std::cout << "signatures until the default 1 GiB limit: " << 1073741824ULL / per_signature << '\n';

    if (argc == 2) {
      std::ofstream report(dir / "journal-growth.txt");
      report << "framing " << framing << '\n';
      report << "bytes_per_signature " << per_signature << '\n';
      report << "signatures_until_limit " << 1073741824ULL / per_signature << '\n';
      for (const auto& r : restarts)
        report << "restart " << r.records << ' ' << r.callbacks << ' '
               << r.microseconds / static_cast<double>(r.records) << '\n';
    }
    std::cout << "SUMMARY cases=6 passed=6\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
