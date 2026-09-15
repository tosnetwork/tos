#include "validator/auth/verify.h"
#ifndef TOS_AUTH_CORE_ONLY
#include "validator/auth/cells.h"
#endif
#include <fstream>
#include <iostream>
#include <iterator>
using namespace tos::auth;
Bytes load(const char* path) {
  std::ifstream f(path, std::ios::binary);
  return Bytes(std::istreambuf_iterator<char>(f), {});
}
template <class T>
bool roundtrip(const Bytes& input, const char* output) {
  auto value = decode<T>(input);
  if (!value.ok())
    return false;
  auto raw = encode(value.value());
  if (!raw.ok())
    return false;
  std::ofstream f(output, std::ios::binary);
  f.write(reinterpret_cast<const char*>(raw.value().data()), raw.value().size());
  return f.good();
}
#include "lifecycle-driver.h"
int main(int argc, char** argv) {
  if (argc >= 7 &&
      (std::string(argv[1]) == "apply" || std::string(argv[1]) == "due" || std::string(argv[1]) == "select"))
    return lifecycle_main(argc, argv);

#ifndef TOS_AUTH_CORE_ONLY
  if (argc == 4 && (std::string(argv[1]) == "pack" || std::string(argv[1]) == "unpack")) {
    auto value = std::string(argv[1]) == "pack" ? serialize_bytes(load(argv[2])) : deserialize_bytes(load(argv[2]));
    if (!value.ok())
      return 1;
    std::ofstream out(argv[3], std::ios::binary);
    out.write(reinterpret_cast<const char*>(value.value().data()), value.value().size());
    return out.good() ? 0 : 2;
  }

#endif
  if (argc == 7 && std::string(argv[1]) == "certificate") {
    auto policy = decode<Policy>(load(argv[2]));
    auto committee = decode<Committee>(load(argv[3]));
    auto cert = decode<Certificate>(load(argv[4]));
    auto expected = decode<Duty>(load(argv[5]));
    if (!policy.ok() || !committee.ok() || !cert.ok() || !expected.ok())
      return 1;
    auto snapshot = RegistrySnapshot::compile(committee.value(), policy.value());
    if (!snapshot.ok())
      return 1;
    auto verified = snapshot.value().verify(cert.value(), expected.value());
    if (!verified.ok())
      return 1;
    std::ofstream f(argv[6]);
    f << verified.value().weight();
    return f.good() ? 0 : 2;
  }
  if (argc == 6 && std::string(argv[1]) == "verify") {
    // The command line carries key bytes and no suite. This driver speaks
    // the one the legacy corpus was produced with, stated rather than implied.
    auto key = AdmittedKey::admit(suite_ed25519, parameters_default, load(argv[2]));
    if (!key.ok())
      return 1;
    auto valid = key.value().verify(load(argv[3]), load(argv[4]));
    return valid.ok() && valid.value() ? 0 : 1;
  }
  if (argc == 3 && std::string(argv[1]) == "admit")
    return AdmittedKey::admit(suite_ed25519, parameters_default, load(argv[2])).ok() ? 0 : 1;
  if (argc != 5 || std::string(argv[1]) != "codec")
    return 2;
  auto bytes = load(argv[3]);
  std::string kind = argv[2];
#include "dispatch.inc"
  return 2;
}
