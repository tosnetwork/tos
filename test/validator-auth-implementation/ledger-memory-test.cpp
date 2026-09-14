// What one signature costs in resident memory, for as long as the process runs.
//
// The safety ledger's durability is on disk and is now measured. Its indexes
// are not: a stored request, its plan, its receipt and its result stay in
// memory for the life of the process, because anti-equivocation answers
// questions about signatures that happened arbitrarily long ago. Nothing
// reclaims them and nothing reports their size, so the heap cost per signature
// has never been a number.
//
// It has to be a number, because it decides which limit a node hits first. The
// journal refuses admission at a byte count; the heap does not refuse anything.
// If a signature costs more in memory than on disk, the operator's real bound
// is the one nobody configured.
//
// The instrument is a replaced global allocator, which counts live bytes
// exactly rather than sampling the process. It is measured as a slope between
// two signature counts so that fixed startup cost cancels, and the slope is
// taken twice so that a cost which is not linear in signatures is visible as a
// disagreement rather than assumed away.
//
// This binary deliberately stays out of the sanitized build: replacing the
// global allocator would displace the sanitizer's own, which is a worse trade
// than leaving one measurement unsanitized.
#include <cstddef>
#include <cstdlib>
#include <new>

namespace {
// Live bytes handed out by the replaced allocator. Single-threaded by
// construction: the ledger serializes its own access and this test drives it
// from one thread.
std::size_t live_bytes = 0;

constexpr std::size_t header = alignof(std::max_align_t);

void* tracked_allocate(std::size_t size) {
  auto raw = std::malloc(size + header);
  if (!raw)
    throw std::bad_alloc();
  *static_cast<std::size_t*>(raw) = size;
  live_bytes += size;
  return static_cast<char*>(raw) + header;
}

void tracked_release(void* pointer) noexcept {
  if (!pointer)
    return;
  auto raw = static_cast<char*>(pointer) - header;
  live_bytes -= *reinterpret_cast<std::size_t*>(raw);
  std::free(raw);
}
}  // namespace

void* operator new(std::size_t size) {
  return tracked_allocate(size);
}
void* operator new[](std::size_t size) {
  return tracked_allocate(size);
}
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
  try {
    return tracked_allocate(size);
  } catch (...) {
    return nullptr;
  }
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
  try {
    return tracked_allocate(size);
  } catch (...) {
    return nullptr;
  }
}
void operator delete(void* pointer) noexcept {
  tracked_release(pointer);
}
void operator delete[](void* pointer) noexcept {
  tracked_release(pointer);
}
void operator delete(void* pointer, std::size_t) noexcept {
  tracked_release(pointer);
}
void operator delete[](void* pointer, std::size_t) noexcept {
  tracked_release(pointer);
}
void operator delete(void* pointer, const std::nothrow_t&) noexcept {
  tracked_release(pointer);
}
void operator delete[](void* pointer, const std::nothrow_t&) noexcept {
  tracked_release(pointer);
}

#include "signer-fixture.h"

namespace {
// Reserve and complete `count` signatures against a fresh ledger, and report
// the live bytes still held afterwards. The ledger and its log are destroyed
// before reading, except for the ledger under measurement, which is exactly
// what stays resident on a running node.
struct Sample {
  unsigned signatures = 0;
  std::size_t bytes = 0;
};

Sample hold(const std::filesystem::path& dir, const std::string& name, unsigned count) {
  auto witness = value(FileWitness::open((dir / (name + "-witness")).string(), h(999), true), "witness");
  auto fence = value(witness->acquire(), "acquire");
  auto ledger = value(SafetyLedger::open((dir / (name + "-ledger")).string(), true, *witness, fence), "ledger");
  auto before = live_bytes;
  for (unsigned n = 0; n < count; ++n) {
    auto r = request(4, n + 1);
    value(ledger->reserve(r, receipt_for(r, 2 * n + 1, 1)), "reserve");
    value(ledger->complete(r.request_id_, result_for(r, 2 * n + 2)), "complete");
  }
  check(ledger->frontier().sequence == 2 * count, "records-written");
  auto after = live_bytes;
  check(after >= before, "accounting-did-not-underflow");
  return {count, after - before};
}
}  // namespace

int main(int argc, char** argv) {
  try {
    check(argc == 2, "temporary-directory-required");
    std::filesystem::path dir = argv[1];
    check(std::filesystem::create_directory(dir), "fresh-directory-required");
    ::chmod(dir.c_str(), 0700);

    // The allocator must be the one being read. A counter that never moves
    // would report a per-signature cost of zero and look like good news.
    auto probe_start = live_bytes;
    {
      auto probe = std::make_unique<std::array<std::uint8_t, 4096>>();
      check(live_bytes >= probe_start + 4096, "allocator-counts-allocations");
    }
    check(live_bytes == probe_start, "allocator-counts-releases");
    std::cout << "CASE_PASS allocator-is-the-instrument\n";

    // Two slopes over three counts. A cost that is linear in signatures gives
    // the same slope twice; anything super-linear separates them.
    auto small = hold(dir, "small", 64);
    auto middle = hold(dir, "middle", 128);
    auto large = hold(dir, "large", 256);
    auto lower = (middle.bytes - small.bytes) / (middle.signatures - small.signatures);
    auto upper = (large.bytes - middle.bytes) / (large.signatures - middle.signatures);
    for (const auto& s : {small, middle, large})
      std::cout << "signatures=" << s.signatures << " retained_bytes=" << s.bytes << '\n';
    std::cout << "retained bytes per signature: " << lower << " (64-128) and " << upper << " (128-256)\n";

    check(lower > 0 && upper > 0, "a-signature-costs-memory");
    // The two slopes are measured by the same exact counter over the same code
    // path, so genuine linearity makes them identical. The tolerance here is for
    // container growth stepping at a different point between the two windows,
    // not for a real trend: three percent is already far more than that costs,
    // and anything looser stops being able to see retention that grows with
    // history at all.
    auto spread = lower > upper ? lower - upper : upper - lower;
    check(spread * 32 <= (lower < upper ? lower : upper), "retention-is-linear-in-signatures");
    std::cout << "CASE_PASS retention-is-linear-in-signatures\n";

    // The number that decides which limit a node reaches first. The journal
    // refuses admission at roughly 372,000 signatures; the heap refuses nothing.
    constexpr std::uint64_t journal_capacity = 372439;
    auto at_capacity = upper * journal_capacity;
    std::cout << "retained heap at journal capacity (" << journal_capacity
              << " signatures): " << at_capacity / 1048576 << " MiB\n";

    // A guard on the figure itself, so a change that makes retention heavier
    // fails here rather than on a node months later. The bound is not the
    // measured value: exact retention depends on the standard library's node
    // layout and would make this brittle across platforms for no gain. It is
    // the point past which the heap, not the journal, becomes the limit an
    // operator actually hits. Being a bound and not an equality, it catches a
    // regression that adds most of a kilobyte per signature and does not catch
    // one that adds a hundred bytes; the linearity check above is the part that
    // holds without a threshold.
    check(upper <= 4096, "a-signature-retains-at-most-four-kilobytes");
    std::cout << "CASE_PASS a-signature-retains-at-most-four-kilobytes\n";

    std::ofstream report(dir / "ledger-memory.txt");
    report << "bytes_per_signature_low " << lower << '\n';
    report << "bytes_per_signature_high " << upper << '\n';
    report << "retained_bytes_at_journal_capacity " << at_capacity << '\n';
    std::cout << "SUMMARY cases=3 passed=3\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
