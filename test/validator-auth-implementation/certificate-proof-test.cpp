#include <filesystem>
#include <fstream>
#include <iostream>

#include "validator/auth/certificate-proof.h"
#include "vm/boc.h"

#include "native-fixture.h"
using namespace auth_fixture;
namespace {
Bytes read(const std::filesystem::path& p) {
  std::ifstream f(p, std::ios::binary);
  check(f.good(), "input");
  return Bytes(std::istreambuf_iterator<char>(f), {});
}
void write(const std::filesystem::path& p, const Bytes& bytes) {
  std::ofstream f(p, std::ios::binary);
  f.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  check(f.good(), "output");
}
std::string hex(const Hash& id) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (auto b : id) {
    out += digits[b >> 4];
    out += digits[b & 15];
  }
  return out;
}
void sign(Certificate& cert) {
  Hash pk{};
  std::array<unsigned char, 64> secret{};
  check(crypto_sign_seed_keypair(pk.data(), secret.data(), h(7).data()) == 0, "keygen");
  for (auto& row : cert.records_) {
    auto statement = value(signing_statement(cert.duty_, row), "statement");
    auto& signature = row.components_[0].signature_;
    signature.resize(64);
    check(crypto_sign_detached(signature.data(), nullptr, statement.data(), statement.size(), secret.data()) == 0,
          "sign");
  }
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 2 || argc == 3, "arguments");
    check(sodium_init() >= 0, "sodium");
    std::filesystem::path input(argv[1]), output;
    if (argc == 3) {
      output = argv[2];
      check(std::filesystem::create_directory(output), "fresh-output");
      std::filesystem::create_directory(output / "objects");
    }
    unsigned total = 0, cases = 0;
    std::ifstream(input / "complete") >> total;
    check(total >= 40, "complete-input");
    std::map<Hash, Bytes> objects;
    auto publish = [&](const ObjectRef& ref, std::span<const std::uint8_t> raw) -> Result<bool> {
      objects[ref.object_id_] = Bytes(raw.begin(), raw.end());
      return true;
    };
    auto fetch = [&](const ObjectRef& ref, std::uint8_t n) -> Result<Bytes> {
      auto i = objects.find(ref.object_id_);
      if (i == objects.end())
        return Error{"fixture-object"};
      auto offset = std::size_t(n) * chunk_bytes;
      if (offset >= i->second.size())
        return Error{"fixture-chunk"};
      return Bytes(i->second.begin() + offset, i->second.begin() + std::min(i->second.size(), offset + chunk_bytes));
    };
    for (unsigned i = 0; i < total; ++i) {
      auto prefix = input / std::to_string(i);
      int wc;
      std::uint64_t shard;
      unsigned cc;
      bool accepted;
      std::string label;
      std::ifstream(prefix.string() + ".case") >> wc >> shard >> cc >> accepted >> label;
      if (!accepted)
        continue;
      auto anchor = value(decode<Anchor>(read(prefix.string() + ".anchor")), "anchor");
      auto c = read(prefix.string() + ".chain");
      Reader cr(c);
      ChainContext chain;
      cr.integer(chain.network);
      cr.hash(chain.genesis_root);
      cr.hash(chain.genesis_file);
      cr.hash(chain.chain_domain);
      check(cr.ok(), "chain");
      auto boc = read(prefix.string() + ".boc");
      auto root = vm::std_boc_deserialize(td::Slice(reinterpret_cast<const char*>(boc.data()), boc.size()));
      check(root.is_ok(), "state-boc");
      auto native = value(NativeCommittee::derive(root.ok(), anchor, chain, {wc, shard}, cc), "committee");
      const auto& snapshot = native.snapshot();
      auto proof = value(make_committee_proof(root.ok(), anchor, chain, {wc, shard}, cc, publish), "committee-proof");
      auto policy_request = value(encode(GetPolicyRequest{anchor, snapshot.policy_id()}), "policy-query");
      auto policy = value(
          decode<PolicyResult>(value(make_native_response(root.ok(), anchor, chain.network, 9, policy_request, publish),
                                     "policy-response")),
          "policy-result");
      Bytes payload{0x05, 0xe1, 0xa7, 0x40, 0x3f, 0xcd, 0x91, 0xb6, 7, 0, 0, 0};
      auto candidate = h(6100);
      payload.insert(payload.end(), candidate.begin(), candidate.end());
      auto session = value(session_id(chain, snapshot, {h(6200), 2, 0}), "session");
      auto duty = value(make_duty(chain, snapshot, session, 3, 7, payload), "duty");
      Certificate cert{duty, payload, {}};
      for (const auto& member : snapshot.committee().members_) {
        auto ref = value(key_reference(member.keys_[2]), "keyref");
        cert.records_.push_back({member.identity_, {{ref.suite_, ref.parameters_, ref.epoch_, ref.key_id_, {}}}});
      }
      sign(cert);
      auto carrier = [&](const Certificate& value_) {
        return value(object_value(4, value(encode(value_), "certificate")), "carrier");
      };
      VerifyCertificateRequest query{anchor, carrier(cert), proof, policy.proof_};
      auto core = value(snapshot.verify(cert, duty), "certificate-baseline");
      VerifyResult expected{anchor,
                            core.certificate_id(),
                            duty.policy_,
                            duty.committee_,
                            value(object_id("duty", duty), "duty-id"),
                            core.signers(),
                            core.weight()};
      GetCertificateRequest get{anchor, core.certificate_id()};
      CertificateResult got{anchor, 1, interface_fingerprint, query.certificate_, proof, policy.proof_};
      auto run = [&](std::uint8_t method, const Bytes& q, const Bytes& response, const Anchor& a,
                     const ChainContext& ctx, const Duty& wanted, const char* name, bool ok, const char* error = "") {
        ObjectReader reader(fetch);
        auto result = verify_native_certificate_response(method, q, response, a, ctx, wanted, reader);
        if (result.ok() != ok)
          throw std::runtime_error(std::string(name) + ": " + (result.ok() ? "accepted" : result.error().code));
        if (!ok && *error)
          check(result.error().code == error, name);
        if (ok)
          check(value(result.value().result(), "verified-result") == expected, "verified-native-values");
        if (!output.empty()) {
          auto out = output / std::to_string(cases);
          write(out.string() + ".request", q);
          write(out.string() + ".response", response);
          write(out.string() + ".anchor", value(encode(a), "anchor"));
          write(out.string() + ".expected", value(encode(wanted), "duty"));
          Writer w;
          w.integer(ctx.network);
          w.bytes(ctx.genesis_root);
          w.bytes(ctx.genesis_file);
          w.bytes(ctx.chain_domain);
          write(out.string() + ".chain", w.data);
          std::ofstream(out.string() + ".case")
              << static_cast<unsigned>(method) << ' ' << ok << ' ' << name << ' ' << (*error ? error : "-") << '\n';
          if (ok)
            write(out.string() + ".verified", value(encode(expected), "verified"));
        }
        ++cases;
      };
      auto q = value(encode(query), "query"), response = value(encode(expected), "response"),
           g = value(encode(get), "get"), gr = value(encode(got), "got");
      run(12, g, gr, anchor, chain, duty, "native-get-certificate", true);
      run(13, q, response, anchor, chain, duty, "native-verify-certificate", true);
      if (i != 0)
        continue;
      auto vr = expected;
      vr.weight_ = 999;
      run(13, q, value(encode(vr), "weight"), anchor, chain, duty, "claimed-weight", false);
      vr = expected;
      vr.signers_.pop_back();
      run(13, q, value(encode(vr), "signers"), anchor, chain, duty, "claimed-signers", false);
      vr = expected;
      vr.duty_[0] ^= 1;
      run(13, q, value(encode(vr), "id"), anchor, chain, duty, "claimed-duty", false);
      vr = expected;
      vr.anchor_.file_[0] ^= 1;
      run(13, q, value(encode(vr), "anchor"), anchor, chain, duty, "claimed-anchor", false);
      auto gc = get;
      gc.certificate_id_[0] ^= 1;
      run(12, value(encode(gc), "id"), gr, anchor, chain, duty, "get-certificate-id", false);
      gc = get;
      gc.anchor_.root_[0] ^= 1;
      run(12, value(encode(gc), "anchor"), gr, anchor, chain, duty, "get-request-anchor", false);
      auto rg = got;
      rg.anchor_.file_[0] ^= 1;
      run(12, g, value(encode(rg), "anchor"), anchor, chain, duty, "get-response-anchor", false);
      rg = got;
      rg.era_ = 0;
      run(12, g, value(encode(rg), "era"), anchor, chain, duty, "get-era", false);
      rg = got;
      rg.interface_digest_[0] ^= 1;
      run(12, g, value(encode(rg), "fingerprint"), anchor, chain, duty, "get-fingerprint", false);
      auto vq = query;
      vq.anchor_.file_[0] ^= 1;
      run(13, value(encode(vq), "anchor"), response, anchor, chain, duty, "verify-request-anchor", false);
      auto wrong = duty;
      wrong.session_[0] ^= 1;
      run(13, q, response, anchor, chain, wrong, "independent-session", false);
      auto early = query;
      early.committee_.proof_hash_[0] ^= 1;
      run(13, value(encode(early), "early-context"), response, anchor, chain, wrong, "early-context-admission", false,
          "expected-context");
      wrong = duty;
      wrong.position_++;
      run(13, q, response, anchor, chain, wrong, "independent-position", false);
      vq = query;
      vq.committee_.proof_hash_[0] ^= 1;
      run(13, value(encode(vq), "proof"), response, anchor, chain, duty, "committee-proof-authentication", false);
      vq = query;
      vq.policy_.proof_hash_[0] ^= 1;
      run(13, value(encode(vq), "proof"), response, anchor, chain, duty, "policy-proof-authentication", false);
      vq = query;
      vq.policy_.object_id_[0] ^= 1;
      run(13, value(encode(vq), "proof"), response, anchor, chain, duty, "policy-proof-object", false);
      vq = query;
      vq.committee_.anchor_.file_[0] ^= 1;
      run(13, value(encode(vq), "proof"), response, anchor, chain, duty, "committee-proof-anchor", false);
      vq = query;
      auto invalid = cert;
      invalid.records_.back().components_[0].signature_[0] ^= 1;
      vq.certificate_ = carrier(invalid);
      vr = expected;
      vr.certificate_id_ = value(object_id("certificate", invalid), "invalid-id");
      run(13, value(encode(vq), "invalid"), value(encode(vr), "claim"), anchor, chain, duty, "native-signature-refusal",
          false);
      vq = query;
      invalid = cert;
      invalid.records_.resize(1);
      vq.certificate_ = carrier(invalid);
      vr = expected;
      vr.certificate_id_ = value(object_id("certificate", invalid), "invalid-id");
      vr.signers_.resize(1);
      vr.weight_ = snapshot.committee().members_[0].weight_;
      run(13, value(encode(vq), "quorum"), value(encode(vr), "claim"), anchor, chain, duty, "native-quorum-refusal",
          false);
      vq = query;
      invalid = cert;
      invalid.duty_.genesis_root_[0] ^= 1;
      sign(invalid);
      vq.certificate_ = carrier(invalid);
      vr = expected;
      vr.certificate_id_ = value(object_id("certificate", invalid), "invalid-id");
      vr.duty_ = value(object_id("duty", invalid.duty_), "invalid-duty");
      run(13, value(encode(vq), "genesis"), value(encode(vr), "claim"), anchor, chain, invalid.duty_,
          "independent-genesis", false, "certificate-chain-context");
      run(12, Bytes(2000001), gr, anchor, chain, duty, "request-byte-admission", false, "api-binary-bound");
      run(12, g, Bytes(2000001), anchor, chain, duty, "response-byte-admission", false, "api-binary-bound");
      run(11, g, gr, anchor, chain, duty, "method-admission", false, "unsupported-native-method");
    }
    if (!output.empty()) {
      for (const auto& [id, raw] : objects)
        write(output / "objects" / hex(id), raw);
      std::ofstream(output / "complete") << cases << '\n';
    }
    std::cout << "PASS: native certificate proofs " << cases << " cases\n";
    return 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
