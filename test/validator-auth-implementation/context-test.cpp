#include <filesystem>
#include <fstream>
#include <iostream>

#include "validator/auth/context.h"
using namespace tos::auth;
namespace {
Bytes read(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream.good())
    throw std::runtime_error("fixture-input");
  return Bytes(std::istreambuf_iterator<char>(stream), {});
}
template <class T>
T value(Result<T> result) {
  if (!result.ok())
    throw std::runtime_error("fixture-input: " + result.error().code);
  return std::move(result.value());
}
Result<Bytes> run(const std::filesystem::path& path, unsigned mode) {
  auto input = [&](const char* name) { return read(path / name); };
  auto raw = input("chain");
  Reader chain_reader(raw);
  ChainContext chain;
  chain_reader.integer(chain.network);
  chain_reader.hash(chain.genesis_root);
  chain_reader.hash(chain.genesis_file);
  chain_reader.hash(chain.chain_domain);
  if (!chain_reader.ok() || raw.size() != 100)
    throw std::runtime_error("fixture-chain");
  auto origin_raw = input("origin");
  Reader origin_reader(origin_raw);
  SessionOrigin origin;
  origin_reader.hash(origin.native_options_hash);
  origin_reader.integer(origin.vertical_seqno);
  origin_reader.integer(origin.key_block_seqno);
  if (!origin_reader.ok() || origin_raw.size() != 40)
    throw std::runtime_error("fixture-origin");
  auto snapshot = value(
      RegistrySnapshot::compile(value(decode<Committee>(input("committee"))), value(decode<Policy>(input("policy")))));
  auto identity = value(decode<Identity>(input("identity")));
  auto key = value(decode<Key>(input("key")));
  auto update = value(decode<Update>(input("update")));
  if (mode == 1 || mode == 2) {
    auto hash = mode == 1 ? session_id(chain, snapshot, origin) : admin_session_id(chain, identity.identity_);
    if (!hash.ok())
      return hash.error();
    return Bytes(hash.value().begin(), hash.value().end());
  }
  if (mode == 3) {
    auto expected = value(decode<Duty>(input("expected")));
    auto result = make_duty(chain, snapshot, expected.session_, expected.role_, expected.position_, input("payload"));
    if (!result.ok())
      return result.error();
    return encode(result.value());
  }
  if (mode == 4)
    return possession_preimage(chain, update, key);
  Result<bool> result(Error{"fixture-mode"});
  if (mode == 5)
    result = verify_possession(chain, update, key, value(decode<PossessionAuth>(input("pop"))));
  if (mode == 6) {
    auto inc_raw = input("inclusion");
    Reader inc_reader(inc_raw);
    std::uint32_t inclusion;
    inc_reader.integer(inclusion);
    if (!inc_reader.ok() || inc_raw.size() != 4)
      throw std::runtime_error("fixture-inclusion");
    auto count = input("key-count");
    if (count.size() != 1 || count[0] > 2)
      throw std::runtime_error("fixture-key-count");
    result = verify_identity_certificate(value(decode<Certificate>(input("certificate"))),
                                         value(decode<Duty>(input("expected"))), identity,
                                         std::vector<Key>(count[0], key), inclusion);
  }
  if (!result.ok())
    return result.error();
  return Bytes{static_cast<std::uint8_t>(result.value())};
}
}  // namespace
int main(int argc, char** argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("arguments");
    std::filesystem::path root(argv[1]);
    unsigned count = 0;
    std::ifstream(root / "complete") >> count;
    if (count < 50)
      throw std::runtime_error("complete-corpus");
    for (unsigned i = 0; i < count; ++i) {
      auto path = root / std::to_string(i);
      unsigned mode = 0;
      std::string label, error;
      std::ifstream(path / "case") >> mode >> label >> error;
      auto result = run(path, mode);
      if (error == "-") {
        if (!result.ok() || result.value() != read(path / "golden"))
          throw std::runtime_error(label);
      } else if (result.ok() || result.error().code != error) {
        std::cerr << "DETAIL: expected=" << error << " actual=" << (result.ok() ? "accepted" : result.error().code)
                  << '\n';
        throw std::runtime_error(label);
      }
    }
    std::cout << "PASS: current authority and context " << count << " cases\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
