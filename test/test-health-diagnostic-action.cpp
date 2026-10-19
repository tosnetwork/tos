#include <memory>

#include "metrics/consensus-health.h"
#include "td/utils/check.h"
int main() {
  using namespace tos::health;
  auto producer = std::make_unique<DiagnosticProducer>(diagnostic_stats, std::array<std::uint8_t, 16>{});
  diagnostic_producer.store(producer.get());
  enabled.store(true);
  consensus_enabled.store(true);
  ConsensusStats stats;
  {
    ActionObservation action(Action::Notarize, Origin::Live, stats);
    action.observe(Phase::Signed);
    action.finish();
  }
  CHECK(stats.phase(Action::Notarize, Origin::Live, Phase::Requested) == 1);
  CHECK(stats.phase(Action::Notarize, Origin::Live, Phase::Signed) == 1);
  CHECK(diagnostic_stats.records == 0 && diagnostic_stats.dropped == 0);
  producer->enable();
  {
    ActionObservation action(Action::Notarize, Origin::Live, stats);
    action.observe(Phase::Signed);
    action.observe(Phase::Signed);
    action.finish();
  }
  DiagnosticProducer::Packet packet;
  CHECK(producer->pop(packet) && packet.bytes[66] == static_cast<std::uint8_t>(Phase::Requested));
  CHECK(producer->pop(packet) && packet.bytes[66] == static_cast<std::uint8_t>(Phase::Signed));
  CHECK(producer->pop(packet) && packet.bytes[66] == static_cast<std::uint8_t>(Phase::Completed));
  CHECK(!producer->pop(packet));
  for (unsigned i = 0; i < DiagnosticProducer::capacity; ++i)
    CHECK(producer->phase(0, 0, 0));
  const auto prior = diagnostic_stats.dropped.load();
  {
    ActionObservation action(Action::Notarize, Origin::Live, stats);
    action.observe(Phase::Signed);
    action.finish();
  }
  CHECK(diagnostic_stats.dropped > prior);
  CHECK(stats.phase(Action::Notarize, Origin::Live, Phase::Signed) == 3);
  CHECK(stats.inflight(Action::Notarize, Origin::Live) == 0);
  producer->disable();
  diagnostic_producer.store(nullptr);
}
