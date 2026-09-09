#include "workchain-i13e-contract.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>

namespace {
using namespace i13e_proposal;
struct Failed { int identity; };
void demand(bool yes, int identity) { if (!yes) throw Failed{identity}; }
Bytes bytes(const std::filesystem::path& file) {
  std::ifstream in(file, std::ios::binary);
  demand(in.is_open(), 60);
  Bytes result{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
  demand(!in.bad(), 60);
  return result;
}
std::uint64_t number(const std::filesystem::path& file) {
  auto content = bytes(file);
  while (!content.empty() && (content.back() == '\n' || content.back() == '\r')) content.pop_back();
  demand(!content.empty(), 60);
  std::uint64_t n = 0;
  for (auto c : content) {
    demand(c >= '0' && c <= '9', 60);
    auto digit = static_cast<std::uint64_t>(c - '0');
    demand(n <= (std::numeric_limits<std::uint64_t>::max() - digit) / 10, 60);
    n = n * 10 + digit;
  }
  return n;
}
Snapshot oracle(const std::filesystem::path& directory) {
  static const std::array<const char*, field_count> names{
      "accounts", "account-blocks", "in-msg-descr", "out-msg-descr", "out-queue",
      "dispatch-queue", "shard-state", "shard-update", "value-flow", "processing-metadata"};
  Snapshot result;
  result.generation = number(directory / "generation.txt");
  result.committed_batches = number(directory / "committed-batches.txt");
  result.released = bytes(directory / "released.bin");
  for (unsigned i = 0; i < field_count; ++i) {
    result.same_block[i] = bytes(directory / (std::string(names[i]) + ".bin"));
    demand(!result.same_block[i].empty(), 60);
    // One committed generation must be reconstructed by both reader surfaces.
    result.recovered[i] = result.same_block[i];
  }
  return result;
}
std::vector<Point> required_points() {
  std::vector<Point> points;
  for (unsigned i = 0; i < 3; ++i) {
    points.push_back({Stage::ParticipantFinalize, i});
    points.push_back({Stage::AccountBlockStage, i});
    points.push_back({Stage::AccountRootStage, i});
  }
  for (unsigned i = 0; i < 2; ++i) points.push_back({Stage::InboundStage, i});
  for (unsigned i = 0; i < 3; ++i) {
    points.push_back({Stage::OutboundDescriptorStage, i});
    points.push_back({Stage::OutboundQueueStage, i});
  }
  for (auto stage : {Stage::ValueFlowFreeze, Stage::CoverageFreeze, Stage::ShardUpdateBuild,
                     Stage::FinalBudgetCheck, Stage::ReferencedCellsPersist, Stage::GenerationCheck,
                     Stage::BeforeAtomicPublish, Stage::AtomicStoreAbort}) points.push_back({stage, 0});
  return points;
}
void require_private_isolation(Session& session) {
  const auto audit = session.private_visibility_audit();
  demand(audit.coverage_complete, 79);  // An uninstrumented consumer is not safe.
  demand(audit.intermediate_observations.empty(), 78);
}
void exercise(Adapter& adapter, const Snapshot& before, const Snapshot& committed,
              const Snapshot& released, Fault fault, const std::vector<Point>& required) {
  auto session = adapter.fresh_session();
  demand(static_cast<bool>(session), 61);
  demand(session->observe() == before, 62);
  require_private_isolation(*session);
  const auto saved_before = before;  // Deep copies owned by the assertion code.
  const auto saved_committed = committed;
  const auto saved_released = released;
  auto prepared = session->prepare();
  demand(static_cast<bool>(prepared), 61);
  demand(session->observe() == before, 63);  // Preparing the engine cut is private.
  require_private_isolation(*session);
  demand(session->registered_points() == required, 64);  // Missing stages never skip.
  std::vector<Point> visited;
  auto result = session->attempt(*prepared, fault, [&](Point point) {
    demand(visited.size() < required.size() && point == required[visited.size()], 65);
    visited.push_back(point);
    require_private_isolation(*session);
    demand(session->observe() == before, 66);  // Check during the attempt, not only after it.
    session->poll_release();
    require_private_isolation(*session);
    demand(session->observe() == before, 67);  // No publication can escape early.
  });
  require_private_isolation(*session);
  demand(before == saved_before && committed == saved_committed && released == saved_released, 68);
  if (fault.kind == FaultKind::FailAtPoint) {
    demand(!visited.empty() && visited.back() == fault.point, 69);
    demand(result.outcome == Outcome::NotCommitted && result.failure == FailureIdentity::InjectedAtPoint, 70);
    demand(result.generation == before.generation, 70);
    demand(session->observe() == before, 71);
    session->poll_release();
    require_private_isolation(*session);
    demand(session->observe() == before, 72);  // Also no deferred orphan after failure.
    return;
  }
  // A fault after the durable decision is not a failed commit. The entry must
  // resolve that decision (including restart) and report the single commit.
  demand(visited == required, 65);
  demand(result.outcome == Outcome::Committed && result.failure == FailureIdentity::None, 73);
  demand(result.generation == committed.generation, 73);
  demand(session->observe() == committed, 74);
  session->poll_release();
  require_private_isolation(*session);
  demand(session->observe() == released, 75);
  // Same logical request: one committed generation and no extra logical message.
  auto retry = session->attempt(*prepared, {}, [&](Point) { throw Failed{76}; });
  demand(retry.outcome == Outcome::Committed && retry.failure == FailureIdentity::None && retry.generation == committed.generation, 76);
  session->poll_release();
  require_private_isolation(*session);
  demand(session->observe() == released, 77);
}
}
int main(int argc, char** argv) {
  try {
    demand(argc == 2, 60);
    const std::filesystem::path fixture(argv[1]);
    const auto before = oracle(fixture / "before");
    const auto committed = oracle(fixture / "committed");
    const auto released = oracle(fixture / "released");
    demand(before.generation < std::numeric_limits<std::uint64_t>::max(), 60);
    demand(before.committed_batches < std::numeric_limits<std::uint64_t>::max(), 60);
    demand(committed.generation == before.generation + 1, 60);
    demand(committed.committed_batches == before.committed_batches + 1, 60);
    demand(committed.released == before.released && !before.released.empty(), 60);
    auto after_release = committed;
    after_release.released = released.released;
    demand(after_release == released && released.released != before.released, 60);
    for (unsigned i = 0; i < field_count; ++i) demand(before.same_block[i] != committed.same_block[i], 60);
    auto adapter = make_real_i13e_adapter();
    demand(static_cast<bool>(adapter), 61);
    const auto points = required_points();
    demand(points.size() == 25, 64);
    exercise(*adapter, before, committed, released, {}, points);
    for (auto point : points) exercise(*adapter, before, committed, released, {FaultKind::FailAtPoint, point}, points);
    exercise(*adapter, before, committed, released, {FaultKind::AfterLinearizationBeforeReply, {}}, points);
    exercise(*adapter, before, committed, released, {FaultKind::RestartAfterLinearization, {}}, points);
    std::cout << "PASS I13e contract assertions; evidence and coordinator review still required\n";
    return 0;
  } catch (const Failed& failure) {
    std::cerr << "assertion_id=" << failure.identity << '\n';
    return failure.identity;
  } catch (...) { std::cerr << "unclassified test failure\n"; return 2; }
}
