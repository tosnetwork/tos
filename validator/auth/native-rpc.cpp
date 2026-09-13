#include "native-rpc.h"
namespace tos::auth {
Result<Bytes> NativeClientRpc::call(std::uint8_t method, const Bytes& request, const Hash& principal, std::uint64_t now,
                                    ObjectReader&) {
  Result<Anchor> anchor(Error{"unsupported-native-method"});
  if (method == 8) {
    auto q = decode<GetProfileRequest>(request);
    if (!q.ok())
      return q.error();
    anchor = q.value().anchor_;
  } else if (method == 9) {
    auto q = decode<GetPolicyRequest>(request);
    if (!q.ok())
      return q.error();
    anchor = q.value().anchor_;
  } else if (method == 10) {
    auto q = decode<GetRegistryRequest>(request);
    if (!q.ok())
      return q.error();
    anchor = q.value().anchor_;
  } else if (method == 11) {
    auto q = decode<GetKeyRequest>(request);
    if (!q.ok())
      return q.error();
    anchor = q.value().anchor_;
  }
  if (!anchor.ok())
    return anchor.error();
  auto state = source_.state(anchor.value());
  if (!state.ok())
    return state.error();
  return make_native_response(state.value(), anchor.value(), network_, method, request,
                              [&](const ObjectRef& manifest, std::span<const std::uint8_t> bytes) {
                                return objects_.publish(principal, anchor.value(), manifest, bytes, now);
                              });
}
}  // namespace tos::auth
