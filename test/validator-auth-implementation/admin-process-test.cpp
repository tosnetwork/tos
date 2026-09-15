#include "admin-fixture.h"
#include "process-fixture.h"
using namespace p0_process;
namespace {
class GatedAdminProvider : public C0SigningProvider {
  RemoteProvider& provider_;
  int phase_, fd_;

 public:
  GatedAdminProvider(RemoteProvider& provider, int phase, int fd) : provider_(provider), phase_(phase), fd_(fd) {
  }
  Result<Key> descriptor(const Hash& h) const override {
    return provider_.descriptor(h);
  }
  Result<Record> sign(const SignRequest& q) override {
    return provider_.sign(q);
  }
  Result<KeyHandle> prepare(const PrepareRequest& q) override {
    if (phase_ == 1)
      gate(fd_);
    auto result = provider_.prepare(q);
    if (phase_ == 2 && result.ok())
      gate(fd_);
    return result;
  }
  Result<PossessionAuth> prove_possession(const ChainContext& chain, const StageRequest& q) override {
    if (phase_ == 1)
      gate(fd_);
    auto result = provider_.prove_possession(chain, q);
    if (phase_ == 2 && result.ok())
      gate(fd_);
    return result;
  }
};
PermitExpectation permission(const ChainContext& chain, const RegistryState& registry, const RegistrySnapshot& snapshot,
                             const Identity& identity, std::uint64_t fence) {
  ServicePolicy service{h(800), 1, {}, {{1, 1}}};
  return {{h(800),
           value(object_id("service_policy", service), "service-policy"),
           h(801),
           chain.network,
           chain.genesis_root,
           chain.genesis_file,
           {100, h(301), h(302), h(303)},
           h(304),
           registry.current_policy(),
           snapshot.committee_id(),
           value(admin_session_id(chain, identity.identity_), "session"),
           identity.identity_,
           4,
           h(500),
           228,
           fence},
          100,
          fence,
          true};
}
Permit signed_permit(PermitExpectation expectation) {
  return {expectation.body, {{1, 1, h(802), signature(value(encode(expectation.body), "permit-body"))}}};
}
Result<Bytes> run_signer(const std::filesystem::path& dir, std::uint8_t method, const Bytes& raw, std::uint64_t fence,
                         bool create, int phase) {
  int fds[2];
  check(::pipe(fds) == 0, "pipe");
  auto pid = ::fork();
  check(pid >= 0, "fork");
  if (pid == 0) {
    ::close(fds[0]);
    try {
      RemoteWitness witness((dir / "provider.sock").string(), ::geteuid());
      RemoteProvider remote((dir / "provider.sock").string(), ::geteuid());
      GatedAdminProvider provider(remote, phase, fds[1]);
      auto ledger = value(SafetyLedger::open((dir / "journal").string(), create, witness, fence), "journal");
      auto registry = state();
      auto identity = registry.identities().begin()->second;
      ChainContext chain{-239, h(11), h(12), registry.chain_domain()};
      AdminAuthority authority(registry, chain, admin_snapshot(registry));
      ServiceTrust trust;
      ServicePolicy policy{h(800), 1, {}, {{1, 1}}};
      value(trust.install_trusted(policy, {h(802), registry.keys().begin()->second.public_key_}), "trust");
      std::uint64_t request_fence = fence;
      if (method == 4)
        request_fence = value(decode<StageRequest>(raw), "stage-request").fence_;
      AdminContext context(chain, identity, registry, authority,
                           permission(chain, registry, authority.snapshot, identity, request_fence));
      auto issuer =
          value(ServiceIssuer::open((dir / "receipt-issuer").string(), false, ServicePurpose::receipt, h(800), h(801)),
                "issuer");
      AdminSignerService service(*ledger, provider, trust, context, *issuer);
      Result<Bytes> result(Error{"operation"});
      if (method == 3) {
        auto answer = service.prepare(value(decode<PrepareRequest>(raw), "prepare-request"));
        result = answer.ok() ? encode(answer.value()) : Result<Bytes>(answer.error());
      } else if (method == 4) {
        auto answer = service.stage(value(decode<StageRequest>(raw), "stage-request"));
        result = answer.ok() ? encode(answer.value()) : Result<Bytes>(answer.error());
      }
      if (phase == 3 && result.ok())
        gate(fds[1]);
      Writer output;
      output.integer<std::uint8_t>(result.ok() ? 1 : 0);
      if (result.ok())
        output.blob(result.value(), 2000000);
      else
        output.blob(Bytes(result.error().code.begin(), result.error().code.end()), 256);
      send_exact(fds[1], output.data);
      ::close(fds[1]);
      ::_exit(0);
    } catch (const std::exception& e) {
      std::cerr << "ADMIN CHILD: " << e.what() << '\n';
      ::_exit(2);
    }
  }
  ::close(fds[1]);
  Child child(pid);
  auto status = receive_exact(fds[0], 1)[0];
  if (phase) {
    check(status == 9, "admin-failure-boundary-reached");
    child.kill();
    ::close(fds[0]);
    return Error{"injected-process-kill"};
  }
  auto prefix = receive_exact(fds[0], 4);
  std::uint32_t size = 0;
  for (auto b : prefix)
    size = (size << 8) | b;
  check(size <= 2000000, "child-bound");
  auto bytes = receive_exact(fds[0], size);
  ::close(fds[0]);
  child.wait();
  if (status == 0)
    return Error{std::string(bytes.begin(), bytes.end())};
  check(status == 1, "child-status");
  return bytes;
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 2, "directory-required");
    std::filesystem::path dir = argv[1];
    check(std::filesystem::create_directory(dir), "fresh-directory");
    check(::chmod(dir.c_str(), 0700) == 0, "private-directory");
    ServiceTrust receipt_trust;
    {
      auto issuer =
          value(ServiceIssuer::open((dir / "receipt-issuer").string(), true, ServicePurpose::receipt, h(800), h(801)),
                "issuer");
      for (const auto& p : issuer->public_history())
        value(receipt_trust.install_trusted(p.policy, p.key), "receipt-trust");
    }
    Child host(provider_child(dir, true));
    RemoteWitness witness((dir / "provider.sock").string(), ::geteuid());
    RemoteProvider provider((dir / "provider.sock").string(), ::geteuid());
    auto registry = state();
    auto identity = registry.identities().begin()->second;
    ChainContext chain{-239, h(11), h(12), registry.chain_domain()};
    AdminAuthority authority(registry, chain, admin_snapshot(registry));
    PrepareResult prepared;
    PrepareRequest preparation;
    for (int phase = 1; phase <= 3; ++phase) {
      auto fence = value(witness.acquire(), "prepare-fence");
      preparation = {h(600 + phase), identity.identity_, 1, 1, 1, 2, 100, 1000, 0, {}, fence};
      auto raw = value(encode(preparation), "prepare");
      auto before = std::filesystem::file_size(dir / "provider");
      check(!run_signer(dir, 3, raw, fence, phase == 1, phase).ok(), "prepare-killed");
      auto after = std::filesystem::file_size(dir / "provider");
      if (phase == 1)
        check(before == after, "prepare-before-generation");
      else
        check(after > before, "prepare-generation-reached");
      auto next = value(witness.acquire(), "prepare-replacement");
      if (phase == 1) {
        check(!run_signer(dir, 3, raw, next, false, 0).ok(), "old-preparation-fenced");
        preparation.fence_ = next;
        raw = value(encode(preparation), "new-prepare-fence");
      }
      auto bytes = value(run_signer(dir, 3, raw, next, false, 0), "prepare-recover");
      prepared = value(decode<PrepareResult>(bytes), "prepared");
      if (phase != 1)
        check(std::filesystem::file_size(dir / "provider") == after, "prepare-no-regeneration");
      check(value(run_signer(dir, 3, raw, next, false, 0), "prepare-cached") == bytes, "prepare-exact-bytes");
      value(verify_receipt(prepared.receipt_, prepared.receipt_.body_, receipt_trust, witness), "prepare-witnessed");
    }
    Bytes complete, complete_request;
    for (int phase = 1; phase <= 3; ++phase) {
      auto fence = value(witness.acquire(), "stage-fence");
      Update update{2,
                    identity.identity_,
                    static_cast<std::uint64_t>(phase),
                    value(object_id("identity", identity), "predecessor"),
                    100,
                    identity.active_[0].key_.key_id_,
                    value(encode(prepared.prepared_.key_), "key"),
                    {},
                    {}};
      StageRequest stage{prepared.prepared_.key_,
                         prepared.prepared_.handle_,
                         update,
                         authority.evidence(update, identity, true),
                         {},
                         fence};
      AdminContext context(chain, identity, registry, authority,
                           permission(chain, registry, authority.snapshot, identity, fence));
      stage.permit_ = signed_permit(value(context.authorize(stage), "stage-permission"));
      auto raw = value(encode(stage), "stage");
      auto before = std::filesystem::file_size(dir / "provider");
      check(!run_signer(dir, 4, raw, fence, false, phase).ok(), "stage-killed");
      auto after = std::filesystem::file_size(dir / "provider");
      if (phase == 1)
        check(before == after, "stage-before-primitive");
      else
        check(after > before, "stage-primitive-reached");
      auto next = value(witness.acquire(), "stage-replacement");
      auto recovered = run_signer(dir, 4, raw, next, false, 0);
      if (phase < 3)
        check(!recovered.ok() && recovered.error().code == "result-uncertain", "stage-uncertain-no-reinvoke");
      else {
        check(recovered.ok(), "stage-complete-recovery");
        complete = recovered.value();
        complete_request = raw;
        auto result = value(decode<StageResult>(complete), "stage-result");
        value(verify_possession(chain, update, result.key_, result.possession_), "stage-real-pop");
        value(verify_receipt(result.receipt_, result.receipt_.body_, receipt_trust, witness), "stage-witnessed");
      }
      check(std::filesystem::file_size(dir / "provider") == after, "stage-recovery-no-provider-write");
    }
    host.kill();
    check(std::filesystem::remove(dir / "provider.sock"), "remove-stale-socket");
    Child restarted(provider_child(dir, false));
    auto fence = value(witness.acquire(), "provider-restarted-fence");
    check(value(run_signer(dir, 4, complete_request, fence, false, 0), "host-restart-recovery") == complete,
          "admin-host-restart-exact-bytes");
    check(value(provider.public_keys(), "provider-key-enumeration").size() == 4, "retained-preparations");
    std::cout << "PASS: six separate-process preparation/PoP SIGKILL boundaries, witnessed exact recovery and provider "
                 "restart\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
