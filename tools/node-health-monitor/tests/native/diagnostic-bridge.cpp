#include "metrics/diagnostic-ipc.h"
#include "metrics/consensus-health.h"
#include <charconv>
#include <cstdlib>
#include <iostream>

int main(int argc,char **argv) {
  if (argc!=4 && argc!=5) return 2;
  const bool lifecycle=argc==5 && std::string(argv[4])=="lifecycle";
  int pid=0; const std::string peer=argv[2];
  const auto parsed=std::from_chars(peer.data(),peer.data()+peer.size(),pid);
  const std::string text=argv[3];
  if (parsed.ec!=std::errc{} || parsed.ptr!=peer.data()+peer.size() || (pid<=0 && !lifecycle) || text.size()!=32) return 2;
  std::array<std::uint8_t,16> epoch{};
  for (std::size_t i=0;i<16;++i) {
    unsigned byte=0;
    const auto result=std::from_chars(text.data()+2*i,text.data()+2*i+2,byte,16);
    if (result.ec!=std::errc{} || result.ptr!=text.data()+2*i+2) return 2;
    epoch[i]=static_cast<std::uint8_t>(byte);
  }
  using namespace tos::health;
  std::string ready;
  if (!std::getline(std::cin,ready)) return 2;
  if (lifecycle) {
    const auto parsed_pid=std::from_chars(ready.data(),ready.data()+ready.size(),pid);
    if (parsed_pid.ec!=std::errc{} || parsed_pid.ptr!=ready.data()+ready.size() || pid<=0) return 2;
  } else if (ready!="go") return 2;
  diagnostic_ipc=std::make_unique<DiagnosticIpc>(argv[1],pid,epoch,1);
  if (!diagnostic_ipc->start()) return 3;
  // Allow the independent receiver's bounded pump to complete its handshake.
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  if (lifecycle) {
    enabled.store(true);consensus_enabled.store(true);
    ConsensusStats stats;
    std::cout<<"ready"<<std::endl;
    while (std::getline(std::cin,ready) && ready=="emit") {
      for (unsigned i=0;i<100;++i) {
        ActionObservation action(Action::Notarize,Origin::Live,stats);
        action.observe(Phase::Signed);action.finish();
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      std::cout<<stats.phase(Action::Notarize,Origin::Live,Phase::Signed)<<" "
               <<stats.inflight(Action::Notarize,Origin::Live)<<" "
               <<diagnostic_stats.sent.load()<<" "<<diagnostic_stats.dropped.load()<<std::endl;
    }
    diagnostic_ipc->stop();return 0;
  }
  for (unsigned i=0;i<10;++i) diagnostic_phase(1,0,static_cast<std::uint8_t>(i));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  diagnostic_ipc->stop();
  return diagnostic_stats.sent==10 && diagnostic_stats.dropped==0 ? 0 : 4;
}
