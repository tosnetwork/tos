#include <fstream>
#include <iostream>
#include <iterator>

#include "validator/auth/api-semantics.h"
using namespace tos::auth;
Result<Bytes> load(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return Error{"fixture-file"};
  return Bytes(std::istreambuf_iterator<char>(input), {});
}
#include "service-probe.h"
int main(int argc, char** argv) {
  if (argc == 4 && std::string(argv[1]) == "service") {
    auto valid = service_probe(argv[2], argv[3]);
    if (!valid.ok()) {
      std::cerr << valid.error().code << '\n';
      return 1;
    }
    return valid.value() ? 0 : 2;
  }

  if (argc != 6)
    return 2;
  unsigned method = 0;
  for (char c : std::string(argv[1])) {
    if (c < '0' || c > '9' || method > 25)
      return 2;
    method = method * 10 + unsigned(c - '0');
  }
  if (method > 255)
    return 2;
  auto request = load(argv[3]), response = load(argv[4]);
  if (!request.ok() || !response.ok())
    return 2;
  ObjectReader reader([&](const ObjectRef& ref, std::uint8_t index) -> Result<Bytes> {
    constexpr char hex[] = "0123456789abcdef";
    std::string id;
    for (auto c : ref.object_id_) {
      id.push_back(hex[c >> 4]);
      id.push_back(hex[c & 15]);
    }
    std::ifstream input(std::string(argv[5]) + "/" + id, std::ios::binary | std::ios::ate);
    if (!input)
      return Error{"fixture-file"};
    auto length = input.tellg();
    if (length < 0)
      return Error{"fixture-file"};
    std::size_t offset = std::size_t(index) * chunk_bytes;
    if (offset >= static_cast<std::size_t>(length))
      return Error{"fixture-chunk"};
    Bytes bytes(std::min(chunk_bytes, static_cast<std::size_t>(length) - offset));
    input.seekg(offset);
    input.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
    if (!input)
      return Error{"fixture-file"};
    return bytes;
  });
  auto valid =
      std::string(argv[2]) == "request"
          ? validate_api_request(static_cast<std::uint8_t>(method), request.value(), reader)
          : validate_api_response(static_cast<std::uint8_t>(method), request.value(), response.value(), reader);
  if (!valid.ok()) {
    std::cerr << valid.error().code << '\n';
    return 1;
  }
  return valid.value() ? 0 : 2;
}
