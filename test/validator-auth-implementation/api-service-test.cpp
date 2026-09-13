#include <atomic>
#include <sys/wait.h>
#include <thread>

#include "validator/auth/api-routes.h"
#include "validator/auth/api-service.h"
#include "validator/auth/local-channel.h"
#include "validator/auth/native-rpc.h"

#include "admin-fixture.h"
class NativeHistory : public NativeStateSource {
 public:
  td::Ref<vm::Cell> root;
  Anchor trusted;
  explicit NativeHistory(const RegistryState& registry) : root(masterchain(registry)), trusted(anchor(root)) {
  }
  Result<td::Ref<vm::Cell>> state(const Anchor& request) const override {
    if (request != trusted)
      return Error{"history-unavailable"};
    return root;
  }
};
int main(int argc, char** argv) {
  try {
    check(argc >= 2 && argc <= 4, "directory-required");
    std::filesystem::path dir = argv[1];
    check(std::filesystem::create_directory(dir), "fresh-directory");
    check(::chmod(dir.c_str(), 0700) == 0, "private-directory");
    auto registry = state();
    auto identity = registry.identities().begin()->second;
    ChainContext chain{-239, h(11), h(12), registry.chain_domain()};
    AdminAuthority authority(registry, chain, admin_snapshot(registry));
    auto witness = value(FileWitness::open((dir / "witness").string(), h(900), true), "witness");
    auto fence = value(witness->acquire(), "fence");
    auto ledger = value(SafetyLedger::open((dir / "ledger").string(), true, *witness, fence), "ledger");
    auto provider =
        value(C0Provider::provision((dir / "provider").string(), *witness, {{identity.identity_, 2, 1, 0, 1000}}),
              "provider");
    auto receipts = value(
        ServiceIssuer::open((dir / "receipts").string(), true, ServicePurpose::receipt, h(800), h(801)), "receipts");
    ServiceTrust trust, receipt_trust;
    ServicePolicy service_policy{h(800), 1, {}, {{1, 1}}};
    value(trust.install_trusted(service_policy, {h(802), registry.keys().begin()->second.public_key_}), "permit-trust");
    for (const auto& p : receipts->public_history())
      value(receipt_trust.install_trusted(p.policy, p.key), "receipt-trust");
    PermitExpectation permission{{h(800),
                                  value(object_id("service_policy", service_policy), "service-policy"),
                                  h(801),
                                  chain.network,
                                  chain.genesis_root,
                                  chain.genesis_file,
                                  {100, h(301), h(302), h(303)},
                                  h(304),
                                  registry.current_policy(),
                                  authority.snapshot.committee_id(),
                                  value(admin_session_id(chain, identity.identity_), "admin-session"),
                                  identity.identity_,
                                  4,
                                  h(500),
                                  228,
                                  fence},
                                 100,
                                 fence,
                                 true};
    AdminContext admin_context(chain, identity, registry, authority, permission);
    AdminSignerService admin(*ledger, *provider, trust, admin_context, *receipts);
    Context context;
    SignerService signer(*ledger, *provider, trust, context, *receipts);
    ScopedObjectStore objects;
    NativeHistory history(registry);
    NativeClientRpc rpc(history, objects, chain.network);
    Hash principal = h(700), restricted = h(701);
    SignerApi api(
        chain,
        {{principal, chain.chain_domain, 0x7fff, {identity.identity_}},
         {restricted, chain.chain_domain, 0x7fff, {h(99)}},
         {h(702), chain.chain_domain, 1, {identity.identity_}}},
        *ledger, signer, admin, *provider, [&] { return Result<std::vector<OpaqueKey>>(provider->public_keys()); },
        objects, rpc);
    auto other_chain = chain;
    other_chain.network += 1;
    SignerApi other_api(
        other_chain, {{principal, chain.chain_domain, 0x7fff, {identity.identity_}}}, *ledger, signer, admin, *provider,
        [&] { return Result<std::vector<OpaqueKey>>(provider->public_keys()); }, objects, rpc);
    auto call = [&](std::uint8_t method, const Bytes& raw, Hash who = Hash{}, SignerApi* endpoint = nullptr) {
      if (who == Hash{})
        who = principal;
      auto id = value(api_request_id(method, raw), "request-id");
      auto json =
          value(encode_transport_frame({static_cast<std::uint8_t>(method), id, raw, false, false}), "request-json");
      const auto& route = api_routes[method - 1];
      HttpRequest request{std::string(route.verb), std::string(route.path), std::string(api_media_type),
                          method == 1 ? std::string{} : json};
      auto response = value((endpoint ? endpoint : &api)->dispatch(who, request, 1000), "api-call");
      check(response.content_type == api_media_type, "api-media-type");
      auto result = value(decode_transport_frame(response.body, method, true, &id), "response-frame");
      if (!result.error) {
        ObjectReader reader([&](const ObjectRef& ref, std::uint8_t index) {
          return objects.get(who, history.trusted, ref, index, 1000);
        });
        value(validate_api_response(method, raw, result.payload, reader), "response-association");
      }
      return result;
    };
    auto capabilities = call(1, value(encode(CapabilitiesRequest{}), "capabilities"));
    check(!capabilities.error, "api-capabilities");
    auto key = provider->public_keys()[0];
    auto public_request = value(encode(PublicRequest{value(object_id("key", key.descriptor), "key-id")}), "public");
    check(!call(2, public_request).error, "api-public-key");
    auto denied = call(2, public_request, restricted);
    check(denied.error && value(decode<ApiError>(denied.payload), "denied").code_ == 2, "api-identity-acl");
    denied = call(1, value(encode(CapabilitiesRequest{}), "capabilities"), h(799));
    check(denied.error && value(decode<ApiError>(denied.payload), "unknown-principal").code_ == 2, "api-principal-acl");
    check(value(decode<ApiError>(denied.payload), "denied-state").request_state_ == 4, "api-private-state");
    denied = call(2, public_request, h(702));
    check(denied.error && value(decode<ApiError>(denied.payload), "method-denied").code_ == 2, "api-method-acl");
    PrepareRequest prepare{h(8000), identity.identity_, 1, 1, 1, 2, 100, 1000, 0, {}, fence};
    auto preparation_raw = value(encode(prepare), "prepare");
    denied = call(3, preparation_raw, restricted);
    check(denied.error && value(decode<ApiError>(denied.payload), "prepare-denied").code_ == 2, "api-prepare-acl");
    auto preparation = call(3, preparation_raw);
    check(!preparation.error, "api-prepare");
    auto prepared = value(decode<PrepareResult>(preparation.payload), "prepared");
    value(verify_receipt(prepared.receipt_, prepared.receipt_.body_, receipt_trust, *witness), "prepare-receipt");
    Update update{2,
                  identity.identity_,
                  0,
                  value(object_id("identity", identity), "identity"),
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
    auto expectation = value(admin_context.authorize(stage), "stage-authority");
    stage.permit_ = {expectation.body, {{1, 1, h(802), signature(value(encode(expectation.body), "permit"))}}};
    denied = call(4, value(encode(stage), "stage"), restricted);
    check(denied.error && value(decode<ApiError>(denied.payload), "stage-denied").code_ == 2, "api-stage-acl");
    auto staged = call(4, value(encode(stage), "stage"));
    check(!staged.error, "api-stage");
    auto staged_result = value(decode<StageResult>(staged.payload), "staged-result");
    value(verify_possession(chain, update, stage.key_, staged_result.possession_), "stage-pop");
    denied = call(4, value(encode(stage), "stage"), principal, &other_api);
    check(denied.error && value(decode<ApiError>(denied.payload), "stage-chain").code_ == 5, "api-stage-cached-chain");
    auto sign = bind_key(request(2, 1), key);
    authorize(sign, context);
    auto sign_raw = value(encode(sign), "sign");
    denied = call(5, sign_raw, restricted);
    check(denied.error && value(decode<ApiError>(denied.payload), "sign-denied").code_ == 2, "api-sign-acl");
    auto signed_result = call(5, sign_raw);
    check(!signed_result.error, "api-sign");
    auto sign_result = value(decode<SignResult>(signed_result.payload), "signed-result");
    value(verify_receipt(sign_result.receipt_, sign_result.receipt_.body_, receipt_trust, *witness), "sign-receipt");
    denied = call(5, sign_raw, principal, &other_api);
    check(denied.error && value(decode<ApiError>(denied.payload), "sign-chain").code_ == 5, "api-sign-cached-chain");
    auto polling = call(6, value(encode(ResultRequest{sign.request_id_}), "poll"));
    check(!polling.error, "api-poll");
    check(value(decode<RequestState>(polling.payload), "poll-result").result_[0] == sign_result,
          "api-poll-exact-result");
    denied = call(6, value(encode(ResultRequest{sign.request_id_}), "poll"), restricted);
    check(denied.error && value(decode<ApiError>(denied.payload), "private-result").code_ == 2, "api-result-acl");
    check(value(decode<ApiError>(denied.payload), "private-state").request_state_ == 4, "api-result-private-state");
    denied = call(6, value(encode(ResultRequest{sign.request_id_}), "poll"), principal, &other_api);
    check(denied.error && value(decode<ApiError>(denied.payload), "poll-chain").code_ == 5, "api-result-cached-chain");
    Update retirement{3,  identity.identity_,
                      0,  value(object_id("identity", identity), "identity"),
                      0,  identity.active_[1].key_.key_id_,
                      {}, {},
                      {}};
    RetireRequest retire{retirement.old_key_, retirement, authority.evidence(retirement, identity, false), {}, fence};
    expectation = value(admin_context.authorize(retire), "retire-authority");
    retire.permit_ = {expectation.body, {{1, 1, h(802), signature(value(encode(expectation.body), "permit"))}}};
    denied = call(7, value(encode(retire), "retire"), restricted);
    check(denied.error && value(decode<ApiError>(denied.payload), "retire-denied").code_ == 2, "api-retire-acl");
    check(!call(7, value(encode(retire), "retire")).error, "api-retire");
    denied = call(7, value(encode(retire), "retire"), principal, &other_api);
    check(denied.error && value(decode<ApiError>(denied.payload), "retire-chain").code_ == 5,
          "api-retire-cached-chain");
    std::vector<std::pair<std::uint8_t, Bytes>> queries{
        {8, value(encode(GetProfileRequest{history.trusted}), "profile-request")},
        {9, value(encode(GetPolicyRequest{history.trusted, registry.current_policy()}), "policy-request")},
        {10, value(encode(GetRegistryRequest{history.trusted, 2, {}}), "registry-request")},
        {11, value(encode(GetKeyRequest{history.trusted, identity.active_[0].key_.key_id_}), "key-request")}};
    for (const auto& [method, raw] : queries) {
      auto result = call(method, raw);
      check(!result.error, "api-native-response");
      ObjectReader reader([&](const ObjectRef& ref, std::uint8_t index) {
        return objects.get(principal, history.trusted, ref, index, 1000);
      });
      value(verify_native_response(method, raw, result.payload, history.trusted, chain.network, reader),
            "api-native-proof");
    }
    Bytes large(70000, 3);
    auto carrier = value(object_value(5, large), "manifest");
    auto manifest = carrier.reference_[0];
    auto uploaded = call(15, value(encode(PutChunkRequest{history.trusted, manifest, 0, large}), "upload"));
    check(!uploaded.error, "api-object-upload");
    auto chunk_raw = value(encode(ChunkRequest{history.trusted, manifest, 0}), "chunk-request");
    auto chunk = call(14, chunk_raw);
    check(!chunk.error, "api-object-download");
    check(value(decode<ChunkResult>(chunk.payload), "chunk").data_ == large, "api-chunk-bytes");
    auto hidden = call(14, chunk_raw, restricted);
    check(hidden.error && value(decode<ApiError>(hidden.payload), "hidden-chunk").code_ == 13,
          "api-object-principal-isolation");
    auto before = ledger->frontier();
    auto id = value(api_request_id(3, preparation_raw), "id");
    auto json = value(encode_transport_frame({3, id, preparation_raw, false, false}), "json");
    for (auto [label, request] : std::vector<std::pair<std::string, HttpRequest>>{
             {"api-verb", {"GET", "/v1/keys/prepare", std::string(api_media_type), json}},
             {"api-request-media", {"POST", "/v1/keys/prepare", "application/json", json}},
             {"api-capabilities-body", {"GET", "/v1/capabilities", "", "{}"}}}) {
      auto response = value(api.dispatch(principal, request, 1000), "invalid-http-shape");
      std::uint8_t method = request.path == "/v1/capabilities" ? 1 : 3;
      auto frame = value(decode_transport_frame(response.body, method, true), "invalid-http-frame");
      check(frame.error && value(decode<ApiError>(frame.payload), "invalid-http-error").code_ == 1, label.c_str());
    }
    json.insert(1, "\"api_version\":\"1\",");
    auto malformed =
        value(api.dispatch(principal, {"POST", "/v1/keys/prepare", std::string(api_media_type), json}, 1000),
              "malformed-json");
    auto invalid = value(decode_transport_frame(malformed.body, 3, true), "malformed-response");
    auto error = value(decode<ApiError>(invalid.payload), "error");
    check(invalid.error && error.code_ == 1 && error.request_id_ == Hash{}, "api-duplicate-json");
    check(ledger->frontier() == before, "api-malformed-no-reservation");
    auto listener = value(LocalListener::create((dir / "api.sock").string(), ::geteuid()), "listener");
    Result<bool> served(Error{"not-served"});
    std::thread thread([&] {
      served = listener->serve_http_one([&](const HttpRequest& q) { return api.dispatch(principal, q, 1000); }, 5000);
    });
    auto response = local_http_call((dir / "api.sock").string(), ::geteuid(), {"GET", "/v1/capabilities", "", ""});
    thread.join();
    check(served.ok() && served.value(), "http-dispatch");
    auto http = value(std::move(response), "http-response");
    check(http.status == 200 && http.content_type == api_media_type, "http-canonical-media");
    check(value(decode_transport_frame(http.body, 1, true), "http-frame").payload == capabilities.payload,
          "http-canonical-result");
    if (argc >= 3) {
      auto binary = std::filesystem::absolute(argv[2]).string();
      auto socket = (dir / "api.sock").string();
      auto input = (dir / "http-request").string(), output = (dir / "http-result").string();
      auto rust_call = [&](std::uint8_t method, const Bytes& raw, bool native = false, unsigned expected_calls = 1) {
        {
          std::ofstream file(input, std::ios::binary);
          file.write(reinterpret_cast<const char*>(raw.data()), raw.size());
          check(file.good(), "rust-request-write");
        }
        auto uid = std::to_string(::geteuid()), number = std::to_string(method);
        auto native_binary = argc == 4 ? std::filesystem::absolute(argv[3]).string() : std::string{};
        auto anchor_file = (dir / "trusted-anchor").string(), network = std::to_string(chain.network);
        {
          auto bytes = value(encode(history.trusted), "trusted-anchor");
          std::ofstream file(anchor_file, std::ios::binary);
          file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
          check(file.good(), "trusted-anchor-write");
        }
        auto child = ::fork();
        check(child >= 0, "rust-fork");
        if (child == 0) {
          if (native) {
            ::execl(native_binary.c_str(), native_binary.c_str(), "http", socket.c_str(), uid.c_str(), number.c_str(),
                    input.c_str(), anchor_file.c_str(), network.c_str(), output.c_str(), static_cast<char*>(nullptr));
            ::_exit(2);
          }
          ::execl(binary.c_str(), binary.c_str(), "http", socket.c_str(), uid.c_str(), number.c_str(), input.c_str(),
                  output.c_str(), static_cast<char*>(nullptr));
          ::_exit(2);
        }
        Result<bool> serving(true);
        std::atomic<bool> stopped{false};
        unsigned calls = 0;
        std::jthread server([&] {
          while (!stopped.load()) {
            auto result = listener->serve_http_one(
                [&](const HttpRequest& q) {
                  ++calls;
                  return api.dispatch(principal, q, 1000);
                },
                100);
            if (!result.ok()) {
              serving = result.error();
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
        server.join();
        if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
          std::cerr << "RUST HTTP method=" << unsigned(method)
                    << " served=" << (serving.ok() ? (serving.value() ? "handled" : "idle") : serving.error().code)
                    << '\n';
        }
        check(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "rust-http-client");
        check(serving.ok() && serving.value(), "rust-http-server");
        check(calls == expected_calls, "rust-http-exact-calls");
        check(std::filesystem::file_size(output) <= 2000000, "rust-result-bound");
        std::ifstream result(output, std::ios::binary);
        return Bytes(std::istreambuf_iterator<char>(result), {});
      };
      check(rust_call(1, value(encode(CapabilitiesRequest{}), "capabilities")) == capabilities.payload,
            "rust-http-capabilities");
      check(rust_call(2, public_request) == value(encode(key.descriptor), "public-key"), "rust-http-public-key");
      check(rust_call(3, preparation_raw) == preparation.payload, "rust-http-prepare-cache");
      check(rust_call(4, value(encode(stage), "stage")) == staged.payload, "rust-http-stage-cache");
      check(rust_call(5, sign_raw) == signed_result.payload, "rust-http-sign-cache");
      check(rust_call(6, value(encode(ResultRequest{sign.request_id_}), "poll")) == polling.payload,
            "rust-http-request-state");
      check(rust_call(7, value(encode(retire), "retire")) == call(7, value(encode(retire), "retire")).payload,
            "rust-http-retire-cache");
      for (const auto& [method, raw] : queries) {
        auto result = rust_call(method, raw);
        ObjectReader reader({});
        value(verify_native_response(method, raw, result, history.trusted, chain.network, reader),
              "rust-http-native-proof");
      }
      if (argc == 4) {
        for (const auto& [method, raw] : queries)
          check(rust_call(method, raw, true) == call(method, raw).payload, "rust-http-verified-native");
      }
      check(rust_call(15, value(encode(PutChunkRequest{history.trusted, manifest, 0, large}), "upload")) ==
                uploaded.payload,
            "rust-http-upload");
      check(rust_call(14, chunk_raw) == chunk.payload, "rust-http-download");
      auto fresh = prepare;
      fresh.preparation_id_ = h(8001);
      auto fresh_result =
          value(decode<PrepareResult>(rust_call(3, value(encode(fresh), "fresh-prepare"))), "rust-fresh-key");
      check(fresh_result.prepared_.handle_ != prepared.prepared_.handle_, "rust-real-preparation");
      value(verify_receipt(fresh_result.receipt_, fresh_result.receipt_.body_, receipt_trust, *witness),
            "rust-fresh-receipt");
      if (argc == 4) {
        auto large = pending_state(128);
        history.root = masterchain(large, 1);
        history.trusted = anchor(history.root, 1);
        auto raw = value(encode(GetRegistryRequest{history.trusted, 128, {}}), "large-native-request");
        auto response = rust_call(10, raw, true, 2);
        auto page = value(decode<RegistryResult>(response), "large-native-page");
        check(page.identities_.size() == 128 && page.proof_.proof_.reference_.size() == 1,
              "rust-http-large-native-proof");
      }
    }
    std::cout << "PASS: authenticated signer API, native profile/policy/registry/key proofs, scoped chunks and "
                 "canonical local HTTP\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
