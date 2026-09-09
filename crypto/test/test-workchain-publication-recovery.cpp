// Reuse the committed Native provider fixture, not the publication implementation
// to manufacture expected stored values. The old fixture main is never called.
#define main construction_fixture_main
#include "test-workchain-construction-isolation.cpp"
#undef main
#include "block/workchain-candidate-publication.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <filesystem>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" void workchain_publication_set_arm(int);
extern "C" unsigned workchain_publication_set_errors();
namespace {
using Publisher=block::WorkchainCandidatePublication;
using Bundle=block::WorkchainPublicationBundle;
using PubPoint=block::WorkchainPublicationPoint;
using Outcome=block::WorkchainPublicationOutcome;
using Availability=block::WorkchainPublicationAvailability;
constexpr block::WorkchainPublicationLimits limits{16*1024*1024};
struct CancelBeforeWrite {};
struct Io {
  using Arm=void(*)(int,const char*);
  using Clear=void(*)();
  using Count=unsigned long long(*)();
  Arm arm=reinterpret_cast<Arm>(dlsym(RTLD_DEFAULT,"workchain_publication_fault_arm"));
  Clear clear=reinterpret_cast<Clear>(dlsym(RTLD_DEFAULT,"workchain_publication_fault_clear"));
  Count written=reinterpret_cast<Count>(dlsym(RTLD_DEFAULT,"workchain_publication_fault_written"));
  Count synced=reinterpret_cast<Count>(dlsym(RTLD_DEFAULT,"workchain_publication_fault_synced"));
  Count failed_reads=reinterpret_cast<Count>(dlsym(RTLD_DEFAULT,"workchain_publication_fault_failed_reads"));
  Io(){check(arm&&clear&&written&&synced&&failed_reads,213);}
};
Bundle package(const Contents& c, Root admitted) {
  Bundle b(td::Bits256(c.batch_identity->get_hash().bits()),td::Bits256(admitted->get_hash().bits()),
           c.committed_batch_count,c.revision);
  for(std::size_t i=0;i<b.components.size();++i)b.components[i]=bytes(c.roots[i]);
  b.pending_messages=message_bytes(c.pending_messages->items());return b;
}
Bundle build_bundle(Prepared& f) {
  auto draft=f.before;
  check(f.build(f.before,draft,[](Point){return td::Status::OK();}).is_ok(),10);
  return package(draft,f.batch.effects);
}
void freeze_bundle(const Bundle& b,const std::string& dir) {
  check(std::filesystem::create_directory(dir),224);
  write(dir+"/identity",b.batch_identity.as_slice().str());write(dir+"/input",b.admitted_input.as_slice().str());
  write(dir+"/count",std::to_string(b.committed_batch_count));write(dir+"/revision",std::to_string(b.revision));
  for(std::size_t i=0;i<b.components.size();++i)write(dir+"/field-"+std::to_string(i),b.components[i]);
  write(dir+"/messages",b.pending_messages);
}
void check_bundle(const Bundle& b,const std::string& dir,int state_id=201,bool verify_count=true) {
  check(b.batch_identity.as_slice().str()==read(dir+"/identity")&&b.admitted_input.as_slice().str()==read(dir+"/input"),state_id);
  if(verify_count)check(std::to_string(b.committed_batch_count)==read(dir+"/count"),state_id);
  check(std::to_string(b.revision)==read(dir+"/revision"),state_id);
  for(std::size_t i=0;i<b.components.size();++i)check(b.components[i]==read(dir+"/field-"+std::to_string(i)),state_id);
  check(b.pending_messages==read(dir+"/messages"),203);
}
void trace(const std::string& dir,const std::string& value) {
  int fd=::open((dir+"/trace").c_str(),O_CREAT|O_WRONLY|O_APPEND,0600);check(fd>=0,214);
  const auto line=value+"\n";
  check(::write(fd,line.data(),line.size())==static_cast<ssize_t>(line.size()),214);
  check(::fsync(fd)==0&&::close(fd)==0,214);
}
unsigned count_trace(const std::string& dir,const std::string& wanted) {
  std::ifstream f(dir+"/trace");check(bool(f),214);unsigned count=0;std::string line;
  while(std::getline(f,line))if(line==wanted)++count;
  return count;
}
struct Session {
  Prepared fixture;
  Bundle before=package(fixture.before,fixture.seed.effects);
  Bundle expected=build_bundle(fixture);
  std::string dir,oracle,expected_dir;
  std::uint64_t supplied_count=1;
  Io io;
  std::unique_ptr<Publisher> publisher;
  bool intermediate=false;
  Session(std::string d,std::string o):dir(std::move(d)),oracle(std::move(o)),expected_dir(oracle+"/after"){}
  block::WorkchainPublicationObserver observer(int mode=0) {
    return [this,mode](PubPoint p) {
      trace(dir,"point "+std::to_string(static_cast<unsigned>(p)));
      if(p==PubPoint::ReleaseInstall) {
        auto actual=publisher->released();check(actual.is_ok(),207);
        trace(dir,"release "+actual.ok()->batch_identity.to_hex());
      }
      if(p==PubPoint::BeforeWrite) {
        auto actual=publisher->released();check(actual.is_ok(),208);
        intermediate |= actual.ok()->batch_identity!=before.batch_identity;
        if(mode==1)throw CancelBeforeWrite{};
        if(mode==2)io.arm(1,(dir+"/db").c_str());
        if(mode==3||mode==6)io.arm(2,(dir+"/db").c_str());
        if(mode==4)io.arm(3,(dir+"/db").c_str());
        if(mode==10||mode==11)workchain_publication_set_arm(mode-9);
      }
      if(p==PubPoint::BatchStaged)trace(dir,"write attempt");
      if(p==PubPoint::AfterCommitBeforeRead&&mode==5) {
        trace(dir,"crash before first release");
        ::kill(::getpid(),SIGKILL);::_exit(215);
      }
    };
  }
  Publisher::Build builder() {
    return [this]()->td::Result<Bundle> {
      // This independent durable probe counts entry into actual Native work,
      // including re-execution that produces exactly the same bytes.
      trace(dir,"execute");auto result=build_bundle(fixture);result.committed_batch_count=supplied_count;return result;
    };
  }
  void initialize() {
    publisher=take(Publisher::create_new(dir+"/db",key(240),limits));
    auto r=publisher->initialize(before,[&](PubPoint p){
      if(p==PubPoint::ReleaseInstall) {
        auto actual=publisher->released();check(actual.is_ok(),207);
        trace(dir,"release "+actual.ok()->batch_identity.to_hex());
      }
    });
    check(r.outcome==Outcome::Committed&&r.availability==Availability::Ready,204);
    auto actual=publisher->released();check(actual.is_ok(),201);check_bundle(*actual.ok(),oracle+"/before");
  }
  void reopen() {publisher.reset();publisher=take(Publisher::open(dir+"/db",key(240),limits));}
  void verify_retry() {
    const auto prior=take(publisher->released());
    const auto executions=count_trace(dir,"execute"),writes=count_trace(dir,"write attempt");
    const auto releases=count_trace(dir,"release "+expected.batch_identity.to_hex());
    // Use the current predecessor: an omitted duplicate check cannot be hidden
    // by the independent predecessor guard. The callback returns identical data.
    auto r=publisher->publish(expected.batch_identity,expected.admitted_input,expected.batch_identity,builder(),observer());
    check(r.outcome==Outcome::Committed&&r.availability==Availability::Ready,204);
    auto actual=publisher->released();check(actual.is_ok(),207);
    std::cout<<"{\"retry_execute_delta\":"<<(count_trace(dir,"execute")-executions)
        <<",\"retry_write_delta\":"<<(count_trace(dir,"write attempt")-writes)
        <<",\"retry_release_delta\":"<<(count_trace(dir,"release "+expected.batch_identity.to_hex())-releases)
        <<",\"same_view\":"<<(actual.ok()==prior)<<",\"same_bundle\":"<<(*actual.ok()==*prior)<<"}\n";
    check(count_trace(dir,"execute")==executions,205);
    check(count_trace(dir,"write attempt")==writes,219);
    check(take(publisher->released())==prior&&count_trace(dir,"release "+expected.batch_identity.to_hex())==releases,206);
    check(take(publisher->released())->committed_batch_count==supplied_count,222);
    check_bundle(*take(publisher->released()),expected_dir,201,supplied_count==1);
  }
};
void run_publication(unsigned which,const std::string& dir,const std::string& oracle,const char* binary) {
  Session s(dir,oracle);s.initialize();
  if(which==7) {s.supplied_count=19;s.expected.committed_batch_count=19;s.expected_dir=oracle+"/after-false-count";}
  if(which==5) {
    s.publisher.reset();
    auto child=::fork();check(child>=0,215);
    if(child==0) {::execl(binary,binary,"worker",dir.c_str(),oracle.c_str(),nullptr);::_exit(215);}
    int status=0;check(::waitpid(child,&status,0)==child&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL,215);
    check(count_trace(dir,"execute")==1,205);
    check(count_trace(dir,"release "+s.expected.batch_identity.to_hex())==0,207);
    s.reopen();check(s.publisher->released().is_error(),208);
    const auto reads=count_trace(dir,"point 3");
    auto r=s.publisher->recover(s.expected.batch_identity,s.expected.admitted_input,s.observer());
    check(count_trace(dir,"point 3")==reads+1,220);
    check(r.outcome==Outcome::Committed&&r.availability==Availability::Ready,204);
    check(count_trace(dir,"release "+s.expected.batch_identity.to_hex())==1,207);
    check_bundle(*take(s.publisher->released()),oracle+"/after",207);s.verify_retry();
  } else {
    bool cancelled=false;
    block::WorkchainPublicationResult r{Outcome::Undetermined,Availability::LocalUnavailable,td::Status::OK()};
    try {r=s.publisher->publish(s.expected.batch_identity,s.expected.admitted_input,s.before.batch_identity,s.builder(),s.observer(which));}
    catch(CancelBeforeWrite&) {cancelled=true;}
    check(!s.intermediate,202);
    std::cout<<"{\"case\":"<<which<<",\"returned\":"<<!cancelled
        <<",\"outcome\":"<<(cancelled?"null":std::to_string(static_cast<int>(r.outcome)))<<",\"availability\":"<<(cancelled?"null":std::to_string(static_cast<int>(r.availability)))
        <<",\"partial_bytes\":"<<s.io.written()<<",\"completed_syncs\":"<<s.io.synced()<<"}\n";
    if(which==10||which==11) {
      check(!cancelled&&r.outcome==Outcome::NotCommitted&&r.availability==Availability::LocalUnavailable,225);
      check(r.detail.is_error()&&r.detail.code()==-73002,226);
      check(workchain_publication_set_errors()==1,227);
      check(count_trace(dir,"write attempt")==0,228);
      check(s.publisher->released().is_error(),208);
      auto blocked=s.publisher->publish(s.expected.batch_identity,s.expected.admitted_input,s.expected.batch_identity,s.builder());
      check(blocked.outcome==Outcome::Undetermined&&count_trace(dir,"execute")==1,211);
      workchain_publication_set_arm(0);
      auto recovered=s.publisher->recover(s.expected.batch_identity,s.expected.admitted_input,s.observer());
      check(recovered.outcome==Outcome::NotCommitted&&recovered.availability==Availability::Ready,210);
      check_bundle(*take(s.publisher->released()),oracle+"/before");
      check(count_trace(dir,"release "+s.expected.batch_identity.to_hex())==0,207);
    } else if(which==0||which>=7) {
      check(!cancelled&&r.outcome==Outcome::Committed&&r.availability==Availability::Ready,204);
      check(count_trace(dir,"point 3")==1,220);
      check(count_trace(dir,"release "+s.expected.batch_identity.to_hex())==1,207);
      auto visible=s.publisher->released();check(visible.is_ok(),207);
      check(visible.ok()->committed_batch_count==s.supplied_count,222);
      check_bundle(*visible.ok(),s.expected_dir,201,which!=7);
      const auto first=take(s.publisher->released());
      auto again=s.publisher->recover(s.expected.batch_identity,s.expected.admitted_input,s.observer());
      check(again.outcome==Outcome::Committed&&take(s.publisher->released())==first,206);s.verify_retry();
      if(which==8||which==9) {
        s.publisher.reset();
        if(which==8)std::filesystem::rename(dir+"/db",dir+"/db.saved");
        auto wrong=Publisher::open(dir+"/db",key(which==8?240:241),limits);
        check(wrong.is_error()&&wrong.error().code()==-73001,223);
        if(which==8) {
          check(!std::filesystem::exists(dir+"/db"),223);
          std::filesystem::rename(dir+"/db.saved",dir+"/db");
        }
        s.reopen();
        auto resolved=s.publisher->recover(s.expected.batch_identity,s.expected.admitted_input,s.observer());
        check(resolved.outcome==Outcome::Committed,210);
        check_bundle(*take(s.publisher->released()),s.expected_dir);
      }
    } else if(which==1) {
      check(cancelled,204);check_bundle(*take(s.publisher->released()),oracle+"/before");
      auto recovered=s.publisher->recover(s.expected.batch_identity,s.expected.admitted_input,s.observer());
      check(recovered.outcome==Outcome::NotCommitted&&recovered.availability==Availability::Ready,204);
      check_bundle(*take(s.publisher->released()),oracle+"/before");
      check(count_trace(dir,"release "+s.expected.batch_identity.to_hex())==0,207);
    } else {
      check(!cancelled&&r.outcome==Outcome::Undetermined&&r.availability==Availability::LocalUnavailable,204);
      if(which==2)check(s.io.written()>0,216);
      if(which==3||which==6)check(s.io.synced()==1,216);
      check(s.publisher->released().is_error(),208);
      const auto executions=count_trace(dir,"execute"),writes=count_trace(dir,"write attempt");
      auto blocked=s.publisher->publish(s.expected.batch_identity,s.expected.admitted_input,s.expected.batch_identity,s.builder());
      check(blocked.outcome==Outcome::Undetermined&&blocked.availability==Availability::LocalUnavailable,211);
      check(count_trace(dir,"execute")==executions&&count_trace(dir,"write attempt")==writes,211);
      s.io.clear();
      if(which==6) {
        s.io.arm(4,(dir+"/db").c_str());
        auto unreadable=s.publisher->recover(s.expected.batch_identity,s.expected.admitted_input,s.observer());
        check(unreadable.outcome==Outcome::Undetermined&&unreadable.availability==Availability::LocalUnavailable,212);
        check(s.io.failed_reads()>0,217);
        std::cout<<"{\"failed_recovery_reads\":"<<s.io.failed_reads()<<"}\n";
        check(s.publisher->released().is_error(),208);s.io.clear();
      }
      auto recovered=s.publisher->recover(s.expected.batch_identity,s.expected.admitted_input,s.observer());
      std::cout<<"{\"recovered_outcome\":"<<static_cast<int>(recovered.outcome)
          <<",\"recovered_availability\":"<<static_cast<int>(recovered.availability)<<"}\n";
      const bool committed=which==3||which==6;
      check(recovered.outcome==(committed?Outcome::Committed:Outcome::NotCommitted)&&recovered.availability==Availability::Ready,210);
      check_bundle(*take(s.publisher->released()),oracle+(committed?"/after":"/before"));
      check(count_trace(dir,"release "+s.expected.batch_identity.to_hex())==(committed?1u:0u),207);
      if(committed)s.verify_retry();
      if(which==2) {
        // Reopen once more before allowing a new execution: a pending fragment
        // must not reappear as a delayed commit after the first absence result.
        s.reopen();
        auto still_absent=s.publisher->recover(s.expected.batch_identity,s.expected.admitted_input,s.observer());
        check(still_absent.outcome==Outcome::NotCommitted&&still_absent.availability==Availability::Ready,210);
        check_bundle(*take(s.publisher->released()),oracle+"/before");
        auto retried=s.publisher->publish(s.expected.batch_identity,s.expected.admitted_input,s.before.batch_identity,s.builder(),s.observer());
        check(retried.outcome==Outcome::Committed&&retried.availability==Availability::Ready,204);
        check(count_trace(dir,"execute")==2,221);
        check(count_trace(dir,"release "+s.expected.batch_identity.to_hex())==1,207);
        check_bundle(*take(s.publisher->released()),oracle+"/after");s.verify_retry();
      }
    }
  }
  check(count_trace(dir,"execute")==unsigned(which==2?2:1),205);
  std::cout<<"PASS publication case "<<which<<"\n";
}
}
int main(int argc,char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_FATAL);
  try {
    check(argc>=3,10);
    const std::string mode=argv[1],dir=argv[2];
    if(mode=="freeze") {
      Prepared f;freeze_bundle(package(f.before,f.seed.effects),dir+"/before");auto after=build_bundle(f);freeze_bundle(after,dir+"/after");after.committed_batch_count=19;freeze_bundle(after,dir+"/after-false-count");return 0;
    }
    check(argc==4,10);
    if(mode=="worker") {
      Session s(dir,argv[3]);s.reopen();
      auto initial=s.publisher->recover(s.before.batch_identity,s.before.admitted_input,s.observer());
      check(initial.outcome==Outcome::Committed,204);
      auto impossible=s.publisher->publish(s.expected.batch_identity,s.expected.admitted_input,s.before.batch_identity,s.builder(),s.observer(5));
      (void)impossible;throw Failed{215};
    }
    run_publication(static_cast<unsigned>(std::stoul(mode)),dir,argv[3],argv[0]);return 0;
  } catch(Failed f) {std::cerr<<"failure "<<f.identity<<'\n';return f.identity;}
}
