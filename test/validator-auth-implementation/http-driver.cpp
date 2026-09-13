#include <fstream>
#include <iostream>

#include "validator/auth/local-channel.h"
using namespace tos::auth;
int main(int argc, char** argv) {
  try {
    if (argc != 5)
      return 2;
    auto parsed = std::stoul(argv[3]);
    if (parsed > std::numeric_limits<uid_t>::max())
      return 2;
    auto uid = static_cast<uid_t>(parsed);
    if (std::string_view(argv[1]) == "server") {
      auto listener = LocalListener::create(argv[2], uid);
      if (!listener.ok()) {
        std::cerr << listener.error().code << '\n';
        return 2;
      }
      std::cout << "READY\n" << std::flush;
      auto served = listener.value()->serve_http_one(
          [&](const HttpRequest& request) -> Result<HttpResponse> {
            std::ofstream seen(argv[4], std::ios::binary);
            seen << "invoked";
            if (!seen.good())
              return Error{"fixture-write"};
            return HttpResponse{200, std::string(api_media_type), request.body};
          },
          5000);
      if (!served.ok()) {
        std::cerr << served.error().code << '\n';
        return 1;
      }
      return served.value() ? 0 : 2;
    }
    if (std::string_view(argv[1]) != "client")
      return 2;
    auto response = local_http_call(argv[2], uid, {"GET", "/v1/capabilities", "", ""});
    if (!response.ok()) {
      std::cerr << response.error().code << '\n';
      return 1;
    }
    std::ofstream output(argv[4], std::ios::binary);
    output << response.value().body;
    return output.good() ? 0 : 2;
  } catch (const std::exception& e) {
    std::cerr << "HARNESS: " << e.what() << '\n';
    return 2;
  }
}
