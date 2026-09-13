#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

#include "validator/auth/provider-channel.h"

#include "service-fixture.h"
namespace {
void send_exact(int fd, std::span<const std::uint8_t> raw) {
  while (!raw.empty()) {
    auto n = ::write(fd, raw.data(), raw.size());
    if (n < 0 && errno == EINTR)
      continue;
    check(n > 0, "pipe-write");
    raw = raw.subspan(n);
  }
}
Bytes receive_exact(int fd, std::size_t size) {
  Bytes out(size);
  std::size_t offset = 0;
  while (offset < size) {
    pollfd p{fd, POLLIN, 0};
    check(::poll(&p, 1, 15000) > 0, "child-timeout");
    auto n = ::read(fd, out.data() + offset, size - offset);
    check(n > 0, "child-reply");
    offset += n;
  }
  return out;
}
struct Child {
  pid_t pid = -1;
  explicit Child(pid_t p) : pid(p) {
  }
  Child(const Child&) = delete;
  ~Child() {
    if (pid > 0) {
      ::kill(pid, SIGKILL);
      ::waitpid(pid, nullptr, 0);
    }
  }
  void kill() {
    check(::kill(pid, SIGKILL) == 0, "kill-process");
    int status = 0;
    check(::waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "killed-process");
    pid = -1;
  }
  void wait() {
    int status = 0;
    check(::waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child-success");
    pid = -1;
  }
};
void gate(int fd) {
  send_exact(fd, Bytes{9});
  for (;;)
    ::pause();
}
class GatedProvider : public C0SigningProvider {
  RemoteProvider& source_;
  int phase_, pipe_;

 public:
  GatedProvider(RemoteProvider& p, int phase, int pipe) : source_(p), phase_(phase), pipe_(pipe) {
  }
  Result<Key> descriptor(const Hash& h) const override {
    return source_.descriptor(h);
  }
  Result<Record> sign(const SignRequest& r) override {
    if (phase_ == 2)
      gate(pipe_);
    auto result = source_.sign(r);
    if (phase_ == 3 && result.ok())
      gate(pipe_);
    return result;
  }
};
class GatedContext : public SignContext {
  Context context_;
  int phase_, pipe_;

 public:
  GatedContext(Context c, int phase, int pipe) : context_(std::move(c)), phase_(phase), pipe_(pipe) {
  }
  Result<PermitExpectation> authorize(const SignPlan& p) const override {
    if (phase_ == 1)
      gate(pipe_);
    return context_.authorize(p);
  }
};
pid_t provider_child(const std::filesystem::path& dir, bool create) {
  int fds[2];
  check(::pipe(fds) == 0, "pipe");
  pid_t pid = ::fork();
  check(pid >= 0, "fork-provider");
  if (pid == 0) {
    ::close(fds[0]);
    try {
      auto witness = value(FileWitness::open((dir / "witness").string(), h(999), create), "provider-witness");
      auto provider = create ? value(C0Provider::provision((dir / "provider").string(), *witness,
                                                           {{state().identities().begin()->first, 2, 1, 0, 1000}}),
                                     "provider-provision")
                             : value(C0Provider::open((dir / "provider").string(), *witness), "provider-reopen");
      auto socket = value(LocalListener::create((dir / "provider.sock").string(), ::geteuid()), "provider-listen");
      ProviderHost host(*witness, *provider);
      send_exact(fds[1], Bytes{1});
      ::close(fds[1]);
      for (;;) {
        auto served = socket->serve_one([&](std::span<const std::uint8_t> raw) { return host.dispatch(raw); }, 1000);
        if (!served.ok() && served.error().code != "local-io")
          std::cerr << "PROVIDER: " << served.error().code << '\n';
      }
    } catch (const std::exception& e) {
      std::cerr << "PROVIDER: " << e.what() << '\n';
      ::_exit(2);
    }
  }
  ::close(fds[1]);
  auto ready = receive_exact(fds[0], 1);
  ::close(fds[0]);
  check(ready == Bytes{1}, "provider-ready");
  return pid;
}
Result<SignResult> signer_child(const std::filesystem::path& dir, SignRequest request, std::uint64_t fence, bool create,
                                int phase) {
  int fds[2];
  check(::pipe(fds) == 0, "pipe");
  pid_t pid = ::fork();
  check(pid >= 0, "fork-signer");
  if (pid == 0) {
    ::close(fds[0]);
    try {
      RemoteWitness witness((dir / "provider.sock").string(), ::geteuid());
      RemoteProvider remote((dir / "provider.sock").string(), ::geteuid());
      auto ledger = value(SafetyLedger::open((dir / "journal").string(), create, witness, fence), "signer-open");
      ServiceTrust trust;
      ServicePolicy policy{h(800), 1, {}, {{1, 1}}};
      auto fixture = state();
      value(trust.install_trusted(policy, {h(802), fixture.keys().begin()->second.public_key_}), "signer-trust");
      Context context;
      authorize(request, context);
      GatedContext checked(std::move(context), phase, fds[1]);
      GatedProvider provider(remote, phase, fds[1]);
      Issuer issuer;
      SignerService service(*ledger, provider, trust, checked, issuer);
      auto result = service.sign(request);
      if (phase == 4 && result.ok())
        gate(fds[1]);
      if (result.ok()) {
        auto bytes = value(encode(result.value()), "result");
        Writer w;
        w.integer<std::uint8_t>(1);
        w.blob(bytes, 2000000);
        send_exact(fds[1], w.data);
      } else {
        Writer w;
        w.integer<std::uint8_t>(0);
        w.blob(Bytes(result.error().code.begin(), result.error().code.end()), 256);
        send_exact(fds[1], w.data);
      }
      ::close(fds[1]);
      ::_exit(0);
    } catch (const std::exception& e) {
      std::cerr << "SIGNER: " << e.what() << '\n';
      ::_exit(2);
    }
  }
  ::close(fds[1]);
  Child child(pid);
  auto status = receive_exact(fds[0], 1)[0];
  if (phase) {
    check(status == 9, "failure-point-reached");
    child.kill();
    ::close(fds[0]);
    return Error{"injected-process-kill"};
  }
  auto prefix = receive_exact(fds[0], 4);
  std::uint32_t length = 0;
  for (auto b : prefix)
    length = (length << 8) | b;
  check(length <= 2000000, "child-result-bound");
  auto bytes = receive_exact(fds[0], length);
  ::close(fds[0]);
  child.wait();
  if (status == 0)
    return Error{std::string(bytes.begin(), bytes.end())};
  check(status == 1, "child-result-status");
  return decode<SignResult>(bytes);
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 2, "temporary-directory-required");
    std::filesystem::path dir = argv[1];
    check(std::filesystem::create_directory(dir), "fresh-directory-required");
    ::chmod(dir.c_str(), 0700);
    Child backend(provider_child(dir, true));
    RemoteWitness witness((dir / "provider.sock").string(), ::geteuid());
    RemoteProvider provider((dir / "provider.sock").string(), ::geteuid());
    auto keys = value(provider.public_keys(), "remote-public-keys");
    check(keys.size() == 1, "provisioned-key");
    auto make = [&](unsigned slot, std::uint64_t fence) { return bind_key(request(2, slot, 100, fence), keys[0]); };
    auto fence = value(witness.acquire(), "initial-writer");
    auto first = make(1, fence);
    auto killed = signer_child(dir, first, fence, true, 1);
    check(!killed.ok(), "killed-before-reserve");
    fence = value(witness.acquire(), "replacement-writer");
    first = make(1, fence);
    auto completed = value(signer_child(dir, first, fence, false, 0), "absent-safe-retry");
    value(verify_receipt(
              completed.receipt_, completed.receipt_.body_,
              [&] {
                ServiceTrust t;
                auto f = state();
                value(t.install_trusted({h(800), 1, {}, {{1, 1}}}, {h(802), f.keys().begin()->second.public_key_}),
                      "receipt-trust");
                return t;
              }(),
              witness),
          "remote-witness-receipt");
    for (int phase : {2, 3}) {
      fence = value(witness.acquire(), "writer");
      auto r = make(phase, fence);
      auto before = std::filesystem::file_size(dir / "provider");
      killed = signer_child(dir, r, fence, false, phase);
      check(!killed.ok(), "killed-at-provider-boundary");
      if (phase == 2)
        check(std::filesystem::file_size(dir / "provider") == before, "before-call-no-primitive");
      auto after = std::filesystem::file_size(dir / "provider");
      fence = value(witness.acquire(), "replacement");
      r = make(phase, fence);
      auto uncertain = signer_child(dir, r, fence, false, 0);
      check(!uncertain.ok() && uncertain.error().code == "result-uncertain", "killed-request-never-resigned");
      check(std::filesystem::file_size(dir / "provider") == after, "uncertain-no-provider-write");
    }
    fence = value(witness.acquire(), "complete-writer");
    auto last = make(4, fence);
    killed = signer_child(dir, last, fence, false, 4);
    check(!killed.ok(), "killed-after-complete");
    auto before = std::filesystem::file_size(dir / "provider");
    fence = value(witness.acquire(), "complete-replacement");
    last = make(4, fence);
    auto cached = value(signer_child(dir, last, fence, false, 0), "complete-recovery");
    check(cached.fence_ < fence, "original-fence-retained");
    check(std::filesystem::file_size(dir / "provider") == before, "complete-recovery-no-provider-write");
    // Kill and restart the independent provider/witness process, retaining its
    // separately stored monotonic ledger. No stale socket is removed while alive.
    backend.kill();
    check(::unlink((dir / "provider.sock").c_str()) == 0, "owned-stale-socket");
    backend.pid = provider_child(dir, false);
    fence = value(witness.acquire(), "provider-restart-writer");
    last = make(4, fence);
    check(value(signer_child(dir, last, fence, false, 0), "provider-restart-cache") == cached,
          "separate-process-exact-recovery");
    backend.kill();
    auto lost = witness.check_fence(fence);
    check(!lost.ok(), "lost-witness-stops");
    std::cout << "PASS: separate signer/provider processes; SIGKILL before reserve, before call, after call, after "
                 "complete; exact restart and lost-witness refusal\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
