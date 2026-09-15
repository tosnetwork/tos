#pragma once
// Test-only input adapter. Files supply independently selected trust and context;
// this is not a service configuration loader or a public protocol endpoint.
class ProbeWitness : public ReceiptWitness {
 public:
  std::uint64_t sequence = 0;
  Hash hash{};
  Result<bool> contains(std::uint64_t n, const Hash& h) const override {
    return n == sequence && h == hash;
  }
};
Result<bool> service_probe(const std::string& kind, const std::string& dir) {
  auto input = [&](const std::string& name) { return load(dir + "/" + name); };
  auto count = input("count");
  if (!count.ok())
    return count.error();
  if (count.value().size() != 1 || count.value()[0] > 4)
    return Error{"fixture-trust"};
  ServiceTrust trust;
  for (unsigned i = 0; i < count.value()[0]; ++i) {
    auto prefix = "trust-" + std::to_string(i);
    auto policy = input(prefix + "-policy"), key = input(prefix + "-key"), id = input(prefix + "-id");
    if (!policy.ok() || !key.ok() || !id.ok())
      return Error{"fixture-trust"};
    auto p = decode<ServicePolicy>(policy.value());
    if (!p.ok())
      return p.error();
    if (id.value().size() != 32)
      return Error{"fixture-trust"};
    Hash hash{};
    std::copy(id.value().begin(), id.value().end(), hash.begin());
    auto installed = trust.install_trusted(p.value(), {hash, key.value()});
    if (!installed.ok())
      return installed.error();
  }
  auto raw = input("value"), expected = input("expected"), context = input("context");
  if (!raw.ok() || !expected.ok() || !context.ok())
    return Error{"fixture-input"};
  Reader reader(context.value());
  if (kind == "permit") {
    std::uint32_t current = 0;
    std::uint64_t fence = 0;
    std::uint8_t live = 0;
    reader.integer(current);
    reader.integer(fence);
    reader.integer(live);
    if (!reader.ok() || reader.remaining() || live > 1)
      return Error{"fixture-context"};
    auto p = decode<Permit>(raw.value());
    auto e = decode<PermitBody>(expected.value());
    if (!p.ok())
      return p.error();
    if (!e.ok())
      return e.error();
    return verify_permit(p.value(), e.value(), trust, current, fence, live == 1);
  }
  if (kind == "receipt") {
    ProbeWitness witness;
    reader.integer(witness.sequence);
    reader.hash(witness.hash);
    if (!reader.ok() || reader.remaining())
      return Error{"fixture-context"};
    auto p = decode<Receipt>(raw.value());
    auto e = decode<ReceiptBody>(expected.value());
    if (!p.ok())
      return p.error();
    if (!e.ok())
      return e.error();
    return verify_receipt(p.value(), e.value(), trust, witness);
  }
  if (kind == "state") {
    auto next = decode<RequestState>(raw.value());
    if (!next.ok())
      return next.error();
    auto old = decode<RequestState>(expected.value());
    if (!old.ok())
      return old.error();
    Hash id{};
    reader.hash(id);
    if (!reader.ok() || reader.remaining())
      return Error{"fixture-context"};
    return observe_request_state(&old.value(), next.value(), id);
  }
  return Error{"fixture-kind"};
}
