#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/wait.h>
#include <thread>

#include "validator/auth/api-routes.h"
#include "validator/auth/local-channel.h"
#include "validator/auth/native-rpc.h"
#include "vm/boc.h"

#include "admin-fixture.h"
using namespace auth_fixture;
namespace {
Bytes read(const std::filesystem::path& p) {
  std::ifstream f(p, std::ios::binary);
  check(f.good(), "input");
  return Bytes(std::istreambuf_iterator<char>(f), {});
}
class History final : public NativeStateSource {
 public:
  td::Ref<vm::Cell> root;
  Anchor anchor;
  ChainContext chain;
  Duty expected;
  Certificate archived;
  bool available = true, allowed = true;
  std::string refusal = "history-unavailable";
  mutable unsigned duty_calls = 0;
  Result<td::Ref<vm::Cell>> state(const Anchor& request) const override {
    if (!available || request != anchor)
      return Error{"history-unavailable"};
    return root;
  }
  Result<ChainContext> chain_context() const override {
    return chain;
  }
  Result<Duty> expected_duty(const Anchor& request, const Duty&) const override {
    ++duty_calls;
    if (!allowed || request != anchor)
      return Error{refusal};
    return expected;
  }
  Result<Certificate> certificate(const Anchor& request, const Hash&) const override {
    if (!available || request != anchor)
      return Error{"history-unavailable"};
    return archived;
  }
};
void sign(Certificate& cert) {
  Hash pk{};
  std::array<unsigned char, 64> secret{};
  check(crypto_sign_seed_keypair(pk.data(), secret.data(), h(7).data()) == 0, "keygen");
  for (auto& row : cert.records_) {
    auto bytes = value(signing_statement(cert.duty_, row), "statement");
    auto& signature = row.components_[0].signature_;
    signature.resize(64);
    check(crypto_sign_detached(signature.data(), nullptr, bytes.data(), bytes.size(), secret.data()) == 0, "sign");
  }
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 3 || argc == 4, "arguments");
    check(sodium_init() >= 0, "sodium");
    std::filesystem::path states(argv[1]), proofs(argv[2]);
    std::string temp = (std::filesystem::temp_directory_path() / "p0-certificate-rpc-XXXXXX").string();
    check(::mkdtemp(temp.data()) != nullptr, "private-directory");
    struct Cleanup {
      std::filesystem::path path;
      ~Cleanup() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
      }
    } cleanup{temp};
    std::filesystem::path dir(temp);
    auto registry = state();
    auto identity = registry.identities().begin()->second;
    ChainContext signing_chain{-239, h(11), h(12), registry.chain_domain()};
    AdminAuthority authority(registry, signing_chain, admin_snapshot(registry));
    auto witness = value(FileWitness::open((dir / "witness").string(), h(900), true), "witness");
    auto fence = value(witness->acquire(), "fence");
    auto ledger = value(SafetyLedger::open((dir / "ledger").string(), true, *witness, fence), "ledger");
    auto provider =
        value(C0Provider::provision((dir / "provider").string(), *witness, {{identity.identity_, 2, 1, 0, 1000}}),
              "provider");
    ServiceTrust trust;
    Issuer receipts;
    AdminContext admin_context(signing_chain, identity, registry, authority, {});
    AdminSignerService admin(*ledger, *provider, trust, admin_context, receipts);
    Context context;
    SignerService signer(*ledger, *provider, trust, context, receipts);
    unsigned count = 0, total = 0, cases = 0;
    std::ifstream(states / "complete") >> count;
    std::ifstream(proofs / "complete") >> total;
    check(count >= 40 && total >= 55, "complete-input");
    std::map<Hash, td::Ref<vm::Cell>> roots;
    for (unsigned i = 0; i < count; ++i) {
      auto prefix = states / std::to_string(i);
      auto a = value(decode<Anchor>(read(prefix.string() + ".anchor")), "anchor");
      auto raw = read(prefix.string() + ".boc");
      auto cell = vm::std_boc_deserialize(td::Slice(reinterpret_cast<const char*>(raw.data()), raw.size()));
      check(cell.is_ok(), "state-boc");
      roots.emplace(a.state_, cell.ok());
    }
    for (unsigned i = 0; i < total; ++i) {
      auto prefix = proofs / std::to_string(i);
      unsigned method;
      bool accepted;
      std::string label, error;
      std::ifstream(prefix.string() + ".case") >> method >> accepted >> label >> error;
      if (method != 12 || !accepted)
        continue;
      auto request = read(prefix.string() + ".request");
      auto get = value(decode<GetCertificateRequest>(request), "get");
      auto response = value(decode<CertificateResult>(read(prefix.string() + ".response")), "response");
      History history;
      history.anchor = get.anchor_;
      history.root = roots.at(history.anchor.state_);
      history.expected = value(decode<Duty>(read(prefix.string() + ".expected")), "expected");
      auto raw_chain = read(prefix.string() + ".chain");
      Reader chain(raw_chain);
      chain.integer(history.chain.network);
      chain.hash(history.chain.genesis_root);
      chain.hash(history.chain.genesis_file);
      chain.hash(history.chain.chain_domain);
      check(chain.ok(), "chain");
      check(response.certificate_.reference_.empty(), "c0-inline-certificate");
      history.archived = value(decode<Certificate>(response.certificate_.inline_), "certificate");
      auto original = history;
      ScopedObjectStore objects;
      Hash principal = h(6300);
      NativeClientRpc rpc(history, objects, history.chain.network);
      auto call = [&](NativeClientRpc& endpoint, unsigned method_, const Bytes& q) -> Result<Bytes> {
        ObjectReader reader(
            [&](const ObjectRef& ref, std::uint8_t n) { return objects.get(principal, history.anchor, ref, n, 1); });
        return endpoint.call(static_cast<std::uint8_t>(method_), q, principal, 1, reader);
      };
      SignerApi api(
          history.chain, {{principal, history.chain.chain_domain, 0x7fff, {}}}, *ledger, signer, admin, *provider,
          [&] { return Result<std::vector<OpaqueKey>>(provider->public_keys()); }, objects, rpc);
      auto api_call = [&](std::uint8_t method_, const Bytes& raw) {
        auto id = value(api_request_id(method_, raw), "api-request-id");
        auto frame = value(encode_transport_frame({method_, id, raw, false, false}), "api-frame");
        auto route = api_routes[method_ - 1];
        auto response = value(
            api.dispatch(principal,
                         {std::string(route.verb), std::string(route.path), std::string(api_media_type), frame}, 1),
            "api-dispatch");
        return value(decode_transport_frame(response.body, method_, true, &id), "api-response");
      };
      auto api_error = [&](const Bytes& raw, unsigned code, bool retry, const char* label_) {
        auto frame = api_call(13, raw);
        check(frame.error, label_);
        auto error_ = value(decode<ApiError>(frame.payload), "api-error");
        check(error_.code_ == code && bool(error_.retryable_) == retry && error_.request_state_ == (code == 1 ? 4 : 0),
              label_);
      };
      auto fetched = value(call(rpc, 12, request), "rpc-get");
      ObjectReader client(
          [&](const ObjectRef& ref, std::uint8_t n) { return objects.get(principal, history.anchor, ref, n, 1); });
      auto verified = value(verify_native_certificate_response(12, request, fetched, history.anchor, history.chain,
                                                               history.expected, client),
                            "rpc-client-proof");
      check(value(encode(value(verified.result(), "verified")), "result") == read(prefix.string() + ".verified"),
            "rpc-verified-values");
      auto got = value(decode<CertificateResult>(fetched), "fetched");
      VerifyCertificateRequest q{history.anchor, got.certificate_, got.committee_, got.policy_};
      auto query = value(encode(q), "verify-query");
      unsigned before = history.duty_calls;
      auto checked = value(call(rpc, 13, query), "rpc-verify");
      check(checked == read(prefix.string() + ".verified"), "rpc-verified-weight");
      bool resolved_once = history.duty_calls == before + 1;
      auto api_get = api_call(12, request), api_verified = api_call(13, query);
      check(!api_get.error && api_get.payload == fetched && !api_verified.error && api_verified.payload == checked,
            "api-certificate-values");
      if (argc == 4) {
        auto listener = value(LocalListener::create((dir / "api.sock").string(), ::geteuid()), "http-listener");
        auto rust = std::filesystem::absolute(argv[3]).string();
        auto socket = (dir / "api.sock").string(), input = (dir / "http-request").string(),
             output = (dir / "http-output").string();
        auto trust_prefix = std::filesystem::absolute(prefix).string();
        std::set<std::pair<Hash, std::uint8_t>> chunks;
        for (const auto& object : {got.certificate_, got.committee_.proof_, got.policy_.proof_})
          for (const auto& manifest : object.reference_)
            for (std::size_t n = 0; n < manifest.chunk_hashes_.size(); ++n)
              chunks.emplace(manifest.object_id_, static_cast<std::uint8_t>(n));
        for (const auto& [method_, raw] : std::vector<std::pair<unsigned, Bytes>>{{12, request}, {13, query}}) {
          {
            std::ofstream f(input, std::ios::binary);
            f.write(reinterpret_cast<const char*>(raw.data()), raw.size());
            check(f.good(), "http-write");
          }
          auto uid = std::to_string(::geteuid()), method_text = std::to_string(method_);
          auto child = ::fork();
          check(child >= 0, "http-fork");
          if (child == 0) {
            ::execl(rust.c_str(), rust.c_str(), "http", socket.c_str(), uid.c_str(), method_text.c_str(), input.c_str(),
                    output.c_str(), trust_prefix.c_str(), static_cast<char*>(nullptr));
            ::_exit(2);
          }
          std::atomic<bool> stopped{false};
          unsigned calls = 0;
          Result<bool> serving(true);
          std::jthread thread([&] {
            while (!stopped.load()) {
              auto handled = listener->serve_http_one(
                  [&](const HttpRequest& q_) {
                    ++calls;
                    return api.dispatch(principal, q_, 1);
                  },
                  100);
              if (!handled.ok()) {
                serving = handled.error();
                break;
              }
              if (calls > 65) {
                serving = Error{"fixture-call-bound"};
                break;
              }
            }
          });
          int status = 0;
          auto waited = ::waitpid(child, &status, 0);
          stopped.store(true);
          thread.join();
          check(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "http-native-certificate-client");
          check(serving.ok() && serving.value(), "http-native-certificate-server");
          check(calls == 1 + chunks.size(), "http-native-proof-chunks-once");
          check(read(output) == checked, "http-native-certificate-values");
        }
      }
      ++cases;
      if (i != 0) {
        check(resolved_once, "rpc-duty-resolved-once");
        continue;
      }
      history.allowed = false;
      check(!call(rpc, 13, query).ok(), "rpc-history-refusal");
      api_error(query, 13, false, "api-certificate-history");
      history.refusal = "storage-unavailable";
      api_error(query, 10, true, "api-certificate-source-storage");
      history.refusal = "source-internal-failure";
      api_error(query, 12, true, "api-certificate-source-backend");
      history = original;
      history.expected.session_[0] ^= 1;
      check(!call(rpc, 13, query).ok(), "rpc-independent-duty");
      api_error(query, 5, false, "api-certificate-context");
      check(!call(rpc, 12, request).ok(), "rpc-get-duty");
      history = original;
      NativeClientRpc wrong_network(history, objects, history.chain.network + 1);
      check(!call(wrong_network, 13, query).ok(), "rpc-router-chain");
      vm::CellBuilder empty;
      history.root = empty.finalize();
      check(!call(rpc, 13, query).ok(), "rpc-source-root");
      history = original;
      auto different = get;
      different.certificate_id_[0] ^= 1;
      check(!call(rpc, 12, value(encode(different), "id")).ok(), "rpc-get-id");
      history.archived.records_.back().components_[0].signature_[0] ^= 1;
      different = get;
      different.certificate_id_ = value(object_id("certificate", history.archived), "corrupt-id");
      check(!call(rpc, 12, value(encode(different), "bad-signature")).ok(), "rpc-get-signatures");
      history = original;
      history.archived.duty_.genesis_root_[0] ^= 1;
      sign(history.archived);
      history.expected = history.archived.duty_;
      different = get;
      different.certificate_id_ = value(object_id("certificate", history.archived), "alien-id");
      check(!call(rpc, 12, value(encode(different), "alien-genesis")).ok(), "rpc-get-chain");
      history = original;
      auto bad = q;
      bad.policy_.proof_hash_[0] ^= 1;
      check(!call(rpc, 13, value(encode(bad), "bad-policy")).ok(), "rpc-invalid-proof");
      api_error(value(encode(bad), "bad-proof"), 1, false, "api-certificate-bad-proof");
      bad = q;
      auto forged = history.archived;
      forged.records_.back().components_[0].signature_[0] ^= 1;
      bad.certificate_ = value(object_value(4, value(encode(forged), "forged")), "forged-value");
      api_error(value(encode(bad), "forged-query"), 1, false, "api-certificate-bad-signature");
      bad = q;
      auto absent = value(object_value(5, Bytes(65537, 4)), "missing-proof");
      bad.policy_.proof_ = absent;
      auto missing = value(encode(bad), "missing-object");
      api_error(missing, 13, false, "api-certificate-missing-object");
      ObjectReader storage(
          [](const ObjectRef&, std::uint8_t) -> Result<Bytes> { return Error{"storage-unavailable"}; });
      auto unavailable = rpc.call(13, missing, principal, 1, storage);
      check(!unavailable.ok() && unavailable.error().code == "storage-unavailable", "rpc-object-source-error");
      auto inline_value = value(object_value(5, Bytes{1}), "inline-object");
      value(storage.resolve(inline_value, 5), "inline-resolve");
      check(!storage.source_error(), "object-source-reset");
      ObjectReader no_source({});
      auto no_object = rpc.call(13, missing, principal, 1, no_source);
      check(!no_object.ok() && no_object.error().code == "object-unavailable", "rpc-object-no-source");
      auto unrelated = get;
      unrelated.anchor_.file_[0] ^= 1;
      check(!call(rpc, 12, value(encode(unrelated), "bad-anchor")).ok(), "rpc-history-anchor");
      history.available = false;
      check(!call(rpc, 13, query).ok(), "rpc-unavailable-state");
      history = original;
      auto oversized = call(rpc, 12, Bytes(2000001));
      check(!oversized.ok() && oversized.error().code == "api-binary-bound", "rpc-request-bound");
      check(resolved_once, "rpc-duty-resolved-once");
    }
    std::cout << "PASS: native certificate RPC " << cases << " snapshots, source refusal and exact verification\n";
    return 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
