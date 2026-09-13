#include "provider-channel.h"
namespace tos::auth {
namespace {
void read_frontier(Reader& r, LogFrontier& f) {
  r.integer(f.sequence);
  r.hash(f.hash);
}
void write_frontier(Writer& w, const LogFrontier& f) {
  w.integer(f.sequence);
  w.bytes(f.hash);
}
Result<Bytes> boolean(Result<bool> result) {
  if (!result.ok())
    return result.error();
  return Bytes{static_cast<std::uint8_t>(result.value())};
}
Result<bool> call_bool(const std::string& path, uid_t uid, const Writer& w) {
  if (!w.ok())
    return Error{w.error};
  auto result = local_call(path, uid, w.data);
  if (!result.ok())
    return result.error();
  if (result.value().size() != 1 || result.value()[0] > 1)
    return Error{"provider-channel-response"};
  return result.value()[0] == 1;
}
}  // namespace
Result<Bytes> ProviderHost::dispatch(std::span<const std::uint8_t> raw) {
  Reader r(raw, {2000000, 4000000});
  std::uint8_t operation = 0;
  r.integer(operation);
  std::uint64_t fence = 0;
  Hash id{};
  LogFrontier previous;
  WitnessMark mark;
  if (operation == 1 || operation == 8) {
    if (!r.ok() || r.remaining())
      return Error{"provider-channel-request"};
    if (operation == 1) {
      auto generation = witness_.acquire();
      if (!generation.ok())
        return generation.error();
      Writer w;
      w.integer(generation.value());
      return w.data;
    }
    auto keys = provider_.public_keys();
    if (keys.size() > 4096)
      return Error{"provider-channel-bound"};
    Writer w;
    w.length(keys.size(), 2);
    for (const auto& key : keys) {
      write(w, key.descriptor);
      w.bytes(key.handle);
    }
    return w.data;
  }
  if (operation == 9) {
    r.hash(id);
    if (!r.ok() || r.remaining())
      return Error{"provider-channel-request"};
    auto key = provider_.descriptor(id);
    if (!key.ok())
      return key.error();
    return encode(key.value());
  }
  if (operation == 10) {
    auto request = decode<SignRequest>(raw.subspan(1), {1999999, 4000000});
    if (!request.ok())
      return request.error();
    auto result = provider_.sign(request.value());
    if (!result.ok())
      return result.error();
    return encode(result.value());
  }
  if (operation == 11) {
    auto request = decode<PrepareRequest>(raw.subspan(1));
    if (!request.ok())
      return request.error();
    auto result = provider_.prepare(request.value());
    if (!result.ok())
      return result.error();
    return encode(result.value());
  }
  if (operation == 12) {
    ChainContext chain;
    StageRequest request;
    r.integer(chain.network);
    r.hash(chain.genesis_root);
    r.hash(chain.genesis_file);
    r.hash(chain.chain_domain);
    read(r, request);
    if (!r.ok() || r.remaining())
      return Error{"provider-channel-request"};
    auto result = provider_.prove_possession(chain, request);
    if (!result.ok())
      return result.error();
    return encode(result.value());
  }
  if (operation < 2 || operation > 7)
    return Error{"provider-channel-operation"};
  r.integer(fence);
  if (operation == 2 || operation == 3)
    read_frontier(r, previous);
  if (operation == 3) {
    read_frontier(r, mark.journal);
    r.hash(mark.receipt_body);
    r.hash(mark.request);
    r.integer(mark.state);
  }
  if (operation == 4 || operation == 6 || operation == 7)
    r.hash(id);
  if (!r.ok() || r.remaining())
    return Error{"provider-channel-request"};
  switch (operation) {
    case 2:
      return boolean(witness_.check(fence, previous));
    case 3:
      return boolean(witness_.advance(fence, previous, mark));
    case 4:
      return boolean(witness_.contains(fence, id));
    case 5:
      return boolean(witness_.check_fence(fence));
    case 6:
      return boolean(witness_.claim_primitive(fence, id));
    case 7:
      return boolean(witness_.primitive_allowed(fence, id));
    default:
      return Error{"provider-channel-operation"};
  }
}
Result<std::uint64_t> RemoteWitness::acquire() {
  auto raw = local_call(path_, uid_, Bytes{1});
  if (!raw.ok())
    return raw.error();
  Reader r(raw.value());
  std::uint64_t fence = 0;
  r.integer(fence);
  if (!r.ok() || r.remaining() || fence == 0)
    return Error{"provider-channel-response"};
  return fence;
}
Result<bool> RemoteWitness::check(std::uint64_t fence, const LogFrontier& previous) const {
  Writer w;
  w.integer<std::uint8_t>(2);
  w.integer(fence);
  write_frontier(w, previous);
  return call_bool(path_, uid_, w);
}
Result<bool> RemoteWitness::advance(std::uint64_t fence, const LogFrontier& previous, const WitnessMark& mark) {
  Writer w;
  w.integer<std::uint8_t>(3);
  w.integer(fence);
  write_frontier(w, previous);
  write_frontier(w, mark.journal);
  w.bytes(mark.receipt_body);
  w.bytes(mark.request);
  w.integer(mark.state);
  return call_bool(path_, uid_, w);
}
Result<bool> RemoteWitness::contains(std::uint64_t sequence, const Hash& receipt) const {
  Writer w;
  w.integer<std::uint8_t>(4);
  w.integer(sequence);
  w.bytes(receipt);
  return call_bool(path_, uid_, w);
}
Result<bool> RemoteWitness::check_fence(std::uint64_t fence) const {
  Writer w;
  w.integer<std::uint8_t>(5);
  w.integer(fence);
  return call_bool(path_, uid_, w);
}
Result<bool> RemoteWitness::claim_primitive(std::uint64_t fence, const Hash& request) {
  Writer w;
  w.integer<std::uint8_t>(6);
  w.integer(fence);
  w.bytes(request);
  return call_bool(path_, uid_, w);
}
Result<bool> RemoteWitness::primitive_allowed(std::uint64_t fence, const Hash& request) const {
  Writer w;
  w.integer<std::uint8_t>(7);
  w.integer(fence);
  w.bytes(request);
  return call_bool(path_, uid_, w);
}
Result<std::vector<OpaqueKey>> RemoteProvider::public_keys() const {
  auto raw = local_call(path_, uid_, Bytes{8});
  if (!raw.ok())
    return raw.error();
  Reader r(raw.value());
  auto count = r.length(2);
  if (!r.ok() || count == 0 || count > 4096)
    return Error{"provider-channel-bound"};
  std::vector<OpaqueKey> keys;
  for (unsigned i = 0; i < count; ++i) {
    OpaqueKey key;
    read(r, key.descriptor);
    r.hash(key.handle);
    if (!r.ok())
      return Error{r.error};
    keys.push_back(std::move(key));
  }
  if (r.remaining())
    return Error{"provider-channel-response"};
  return keys;
}
Result<Key> RemoteProvider::descriptor(const Hash& handle) const {
  Bytes request{9};
  request.insert(request.end(), handle.begin(), handle.end());
  auto raw = local_call(path_, uid_, request);
  if (!raw.ok())
    return raw.error();
  return decode<Key>(raw.value());
}
Result<Record> RemoteProvider::sign(const SignRequest& request) {
  auto raw = encode(request);
  if (!raw.ok())
    return raw.error();
  raw.value().insert(raw.value().begin(), 10);
  auto result = local_call(path_, uid_, raw.value());
  if (!result.ok())
    return result.error();
  return decode<Record>(result.value());
}
Result<KeyHandle> RemoteProvider::prepare(const PrepareRequest& request) {
  auto raw = encode(request);
  if (!raw.ok())
    return raw.error();
  raw.value().insert(raw.value().begin(), 11);
  auto result = local_call(path_, uid_, raw.value());
  if (!result.ok())
    return result.error();
  return decode<KeyHandle>(result.value());
}
Result<PossessionAuth> RemoteProvider::prove_possession(const ChainContext& chain, const StageRequest& request) {
  Writer w;
  w.integer<std::uint8_t>(12);
  w.integer(chain.network);
  w.bytes(chain.genesis_root);
  w.bytes(chain.genesis_file);
  w.bytes(chain.chain_domain);
  write(w, request);
  if (!w.ok())
    return Error{w.error};
  auto result = local_call(path_, uid_, w.data);
  if (!result.ok())
    return result.error();
  return decode<PossessionAuth>(result.value());
}
}  // namespace tos::auth
