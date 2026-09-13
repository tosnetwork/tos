#include <fstream>
#include <iostream>
#include <iterator>

#include "validator/auth/transport.h"
using namespace tos::auth;
int main(int argc, char** argv) {
  if (argc != 5)
    return 2;
  std::ifstream input(argv[3], std::ios::binary);
  std::string json(std::istreambuf_iterator<char>(input), {});
  unsigned method = 0;
  for (char c : std::string(argv[1])) {
    if (c < '0' || c > '9' || method > 25)
      return 2;
    method = method * 10 + unsigned(c - '0');
  }
  if (method > 255)
    return 2;
  auto result = decode_transport_frame(json, static_cast<std::uint8_t>(method), std::string(argv[2]) == "response");
  if (!result.ok()) {
    std::cerr << result.error().code << '\n';
    return 1;
  }
  auto encoded = encode_transport_frame(result.value());
  if (!encoded.ok())
    return 2;
  std::ofstream output(argv[4], std::ios::binary);
  output << encoded.value();
  return output.good() ? 0 : 2;
}
