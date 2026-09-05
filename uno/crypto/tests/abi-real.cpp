#include "uno_crypto.h"
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>

template <size_t N>
bool read_bytes(std::istream& input, uint8_t (&bytes)[N]) {
  return static_cast<bool>(input.read(reinterpret_cast<char*>(bytes), N));
}

bool check(const char* label, uint32_t actual, uint32_t expected) {
  if (actual == expected) return true;
  std::cerr << label << ": got " << actual << ", expected " << expected << '\n';
  return false;
}

bool fixture(const char* path, uint32_t context, uint64_t principal, uint64_t fee, int64_t balance) {
  std::ifstream input(path, std::ios::binary);
  std::array<char, 8> magic{};
  if (!input.read(magic.data(), magic.size()) || magic != std::array<char, 8>{'U','N','O','A','B','I','T','0'}) return false;
  UnoCryptoVerifyRequest request{};
  uint8_t flags[1], balance_bytes[8];
  if (!read_bytes(input, flags) || !read_bytes(input, balance_bytes)) return false;
  uint64_t encoded_balance = 0;
  for (unsigned i = 0; i < 8; ++i) encoded_balance |= uint64_t(balance_bytes[i]) << (8 * i);
  if (encoded_balance != static_cast<uint64_t>(balance)) return false;
  request.flags = flags[0];
  request.value_balance = balance;
  if (!read_bytes(input, request.anchor) || !read_bytes(input, request.binding_signature)) return false;
  uint8_t proof[7264];
  UnoCryptoAction actions[2];
  if (!read_bytes(input, proof)) return false;
  for (auto& action : actions) {
    if (!read_bytes(input, action.cv_net) || !read_bytes(input, action.nullifier) ||
        !read_bytes(input, action.rk) || !read_bytes(input, action.cmx) || !read_bytes(input, action.epk) ||
        !read_bytes(input, action.enc_ciphertext) || !read_bytes(input, action.out_ciphertext) ||
        !read_bytes(input, action.spend_signature)) return false;
  }
  if (input.peek() != std::char_traits<char>::eof() || input.bad()) return false;
  request.abi_version = UNO_CRYPTO_ABI_VERSION;
  request.profile = UNO_CRYPTO_FIXED_PROFILE;
  request.context = context;
  request.principal_lo = principal;
  request.fee_lo = fee;
  for (auto& byte : request.sighash) byte = 42;
  request.actions = actions;
  request.action_count = 2;
  request.proof = proof;
  request.proof_bytes = sizeof(proof);
  request.max_actions = 2;
  request.max_proof_bytes = sizeof(proof);
  if (!check("valid", uno_crypto_verify_v0(&request), UNO_CRYPTO_OK)) return false;
  request.sighash[0] ^= 1;
  if (!check("wrong digest", uno_crypto_verify_v0(&request), UNO_CRYPTO_VERIFY)) return false;
  request.sighash[0] ^= 1;
  proof[0] ^= 1;
  if (!check("bad proof", uno_crypto_verify_v0(&request), UNO_CRYPTO_VERIFY)) return false;
  proof[0] ^= 1;
  for (auto& action : actions) {
    action.spend_signature[0] ^= 1;
    if (!check("bad spend signature", uno_crypto_verify_v0(&request), UNO_CRYPTO_VERIFY)) return false;
    action.spend_signature[0] ^= 1;
  }
  request.binding_signature[0] ^= 1;
  if (!check("bad binding signature", uno_crypto_verify_v0(&request), UNO_CRYPTO_VERIFY)) return false;
  request.binding_signature[0] ^= 1;
  request.max_actions = 1;
  if (!check("action bound", uno_crypto_verify_v0(&request), UNO_CRYPTO_ARGUMENTS)) return false;
  request.max_actions = 2;
  request.principal_hi = 1;
  if (!check("wide public amount", uno_crypto_verify_v0(&request),
             context == UNO_TRANSFER ? UNO_CRYPTO_ARGUMENTS : UNO_CRYPTO_VERIFY)) return false;
  request.principal_hi = 0;
  return check("restored valid", uno_crypto_verify_v0(&request), UNO_CRYPTO_OK);
}

int main(int argc, char** argv) {
  if (argc != 3) return 1;
  if (!fixture(argv[1], UNO_SHIELD_CLAIM, 5000, 0, -5000)) return 2;
  if (!fixture(argv[2], UNO_TRANSFER, 0, 100, 100)) return 3;
  std::cout << "Both real ABI fixtures and their mutations passed\n";
  return 0;
}
