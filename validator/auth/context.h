#pragma once
#include "verify.h"
namespace tos::auth {
struct ChainContext {
  std::int32_t network{};
  Hash genesis_root{}, genesis_file{}, chain_domain{};
  // Defaulted so a field added later is compared without anyone remembering to
  // extend a hand-written comparison elsewhere. Its sibling birth types are
  // declared the same way for the same reason.
  bool operator==(const ChainContext&) const = default;
};
struct SessionOrigin {
  Hash native_options_hash{};
  std::uint32_t vertical_seqno = 0, key_block_seqno = 0;
};
Result<Hash> session_id(const ChainContext&, const RegistrySnapshot&, const SessionOrigin&);
Result<Hash> admin_session_id(const ChainContext&, const Hash& target);
Result<Duty> make_duty(const ChainContext&, const RegistrySnapshot&, const Hash& session, std::uint8_t role,
                       std::uint64_t position, std::span<const std::uint8_t> payload);
Result<Bytes> possession_preimage(const ChainContext&, const Update&, const Key&);
// Both of these verify one signature, and both take the same meter the
// certificate path takes, for the same reason: a transaction pays for the
// verifications it causes, and these are caused by the transaction too.
Result<bool> verify_possession(const ChainContext&, const Update&, const Key&, const PossessionAuth&,
                               const SignatureMeter* meter = nullptr);
// Identity authority verifies exactly the target's current role-5 keys; it never
// assigns governance weight or substitutes the committee's old-session keys.
Result<bool> verify_identity_certificate(const Certificate&, const Duty& expected, const Identity&,
                                         const std::vector<Key>& current_admin_keys, std::uint32_t inclusion,
                                         const SignatureMeter* meter = nullptr);
}  // namespace tos::auth
