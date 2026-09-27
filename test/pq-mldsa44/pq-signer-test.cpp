/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#ifdef NDEBUG
#undef NDEBUG  // test assertions must stay live even in Release (-DNDEBUG)
#endif
#include <cassert>
#include <cstdio>
#include <string>

#include "consensus-pq-signer.h"
#include "mldsa44.h"  // production verify-only path

using namespace tos::pq;

// Self-contained hex decoder so the signer test keeps its minimal dependency set
// (signer + verify path only). Rejects odd-length and non-hex input.
static std::string from_hex(std::string_view h) {
  auto nyb = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  std::string out;
  if (h.size() % 2 != 0)
    return out;
  out.reserve(h.size() / 2);
  for (std::size_t i = 0; i < h.size(); i += 2) {
    int hi = nyb(h[i]), lo = nyb(h[i + 1]);
    if (hi < 0 || lo < 0)
      return std::string();
    out.push_back(static_cast<char>((hi << 4) | lo));
  }
  return out;
}
int main() {
  auto ks_opt = ValidatorPQKeyStore::generate();
  assert(ks_opt.has_value());
  const auto& ks = *ks_opt;
  const auto& key = ks.consensus_key();
  assert(key.algorithm_id == PQAlgorithmId::mldsa44);
  assert(key.public_key.size() == mldsa44_public_key_bytes);  // 1312
  const std::string msg = "consensus finality vote fixture";
  auto sig_opt = ks.sign_consensus(msg);
  assert(sig_opt.has_value() && sig_opt->signature.size() == mldsa44_signature_bytes);  // 2420
  const std::string& sig = sig_opt->signature;

  // production signer -> production verifier, under the consensus context: VALID
  assert(verify_mldsa44(msg, simplex_sign_context, sig, key.public_key) == VerifyResult::valid);
  // context substitution (the frozen boundary): a consensus sig must NOT verify under a wallet context
  assert(verify_mldsa44(msg, "tos.pq.wallet.v1", sig, key.public_key) == VerifyResult::invalid);
  // nor under any OTHER frozen authority surface: each context is its own domain, so a
  // Simplex/finality signature can never be replayed as an election, config-vote or admin act
  assert(verify_mldsa44(msg, validator_election_context, sig, key.public_key) == VerifyResult::invalid);
  assert(verify_mldsa44(msg, validator_config_vote_context, sig, key.public_key) == VerifyResult::invalid);
  assert(verify_mldsa44(msg, config_admin_context, sig, key.public_key) == VerifyResult::invalid);
  // the four frozen contexts are distinct strings (a collision would merge two authorities)
  assert(simplex_sign_context != validator_election_context &&
         validator_election_context != validator_config_vote_context &&
         validator_config_vote_context != config_admin_context && simplex_sign_context != config_admin_context);
  // The two authority surfaces a signer has. Each verifies under its own context and
  // under no other, which is what stops a validator's vote on a configuration proposal
  // being replayed as a vote on a complaint, or as a finality signature.
  {
    const std::string vote = "config vote preimage fixture";
    auto config_opt = ks.sign_config_vote(vote);
    assert(config_opt.has_value() && config_opt->signature.size() == mldsa44_signature_bytes);
    const std::string& config_sig = config_opt->signature;
    assert(verify_mldsa44(vote, validator_config_vote_context, config_sig, key.public_key) == VerifyResult::valid);
    assert(verify_mldsa44(vote, simplex_sign_context, config_sig, key.public_key) == VerifyResult::invalid);
    assert(verify_mldsa44(vote, validator_election_context, config_sig, key.public_key) == VerifyResult::invalid);
    assert(verify_mldsa44(vote, config_admin_context, config_sig, key.public_key) == VerifyResult::invalid);

    auto election_opt = ks.sign_election(vote);
    assert(election_opt.has_value() && election_opt->signature.size() == mldsa44_signature_bytes);
    const std::string& election_sig = election_opt->signature;
    assert(verify_mldsa44(vote, validator_election_context, election_sig, key.public_key) == VerifyResult::valid);
    assert(verify_mldsa44(vote, validator_config_vote_context, election_sig, key.public_key) == VerifyResult::invalid);
    assert(verify_mldsa44(vote, simplex_sign_context, election_sig, key.public_key) == VerifyResult::invalid);

    // The same key over the same bytes under two surfaces: two signatures, neither
    // usable as the other. If the context ever stopped reaching the backend, both would
    // verify everywhere and this is where that would show.
    assert(config_sig != election_sig);
  }

  // tampered signature: invalid
  {
    std::string bad = sig;
    bad[0] ^= 1;
    assert(verify_mldsa44(msg, simplex_sign_context, bad, key.public_key) == VerifyResult::invalid);
  }
  // wrong message: invalid
  assert(verify_mldsa44("different message", simplex_sign_context, sig, key.public_key) == VerifyResult::invalid);

  // Independent known-answer test: the backend must reproduce a published
  // FIPS-204 ML-DSA-44 KeyGen vector (an external authority, not self-generated).
  // Input is the 32-byte seed; the derived public key must equal the published pk.
  {
    auto kseed = from_hex("7194b13c95231010afd2c909992bd2003ba6f437c3886bdbe3f6b867a14ba161");
    auto want_pk = from_hex(
        "0b89806f0eec39f2891116152ed4319d4260dfb8ac0710765bd497e6e1de17783cf81e435a412eabef5db3af5d15867bbb4c60f8cf98ba"
        "31bad6d41a5f8eb0c11b632c3f19d844a223c353bd182883dcf13b5c97823d0c0e6902db25ad8d344a37f59f4afaca5bc8874792da1e6a"
        "3eae742ab7034b20a4ab75a93bca4b68002dd242ced348920b7e5abf645a0e2e79617bcb3ee7ba972b3e718d3effc59b1869814ba3f526"
        "927477b12bf25cbad8b04b09905fdad3820715a8b9a905de1cd65eff6b0b0886305efb6cfeec9e90b5ef9a5aaec45c753298e8df9b017c"
        "e0fec9b7431b20775ce8cb11f1f42d1d9fe936d0803196e71addc26cc430cc3b69760c7ccafab7651e21baa28f92bbff1c4a6eef156d6f"
        "08f80b5e3b6fc943e6e984378b90888d09a6ea38b0ba86a3446211452e076dc9f65620014205d5271c7a44fec3cc5375eb246affc11b26"
        "cafb8b96cee3a68e31642e3d69b9130795f25ed818ebb211cd8be648adb5c8a120c8186017727fbcab31c7425c08fe9195de6bdbada577"
        "8d727ee5cde0674facb7ab81786357b529c71ddb24df770e8e95e5f3112bd297b352cb91b08ed1097a98e87bd7ce4235b8dd42292cd4c5"
        "9d87c1f0ff00734aa22d7cae4361adc47742c897601048526702538828ba3c3a959990c0e99463fd22417e147ff2daa74c0c8d3a06e970"
        "3a2e160590086db8011a3d9cec5ae6348706f87cb2379632ce56e660a0ba1b30e3846c5b5c6c0339dd993e543a5322af5a11fc7040a2df"
        "23a0b43e882d7a0ff4431a723bbb918aff7f14bc045cbe94bcab27ae3109147b588665ef486006562b1297016efde787b46237060ee431"
        "e0f011166f916aa0789a7647103b7400a1cbcf0e22bd7b6dd2bb3ec51ec98f0ec6a5baa4cdc83f993d302f8fa849f2046b78aa32f0b375"
        "1885ecb941799e250e6546dca5c20c24845190f239edc20dda77353d555de61509ca6d3c6dc3195bbc6f1703cb03ead5e7fcbcf5d196e9"
        "ab71522408e11d6337c74f9a31eb22ad084a19132bf72e7076a9743ed070aba78789791824e050cd27694c2648263d1200811fa1b81a00"
        "b8fc09cb7a338795e54f6598d7753395f05c60e6eba9630912b7aa8caab3017565def72c7929f4e7736c2b8043feb448801e2ded704e83"
        "4294b69f6a109c0968214fdc5c3ff0d1b1555d617e16df61829231962c59b22a10fe400f8b8cb2a3f19fb4b2e8d087f22687506e7f0d06"
        "1857d1c1789c7f55b899ff4b322982d64bd0aa751d5bee320b135c7f5ddcd5e6245b57dd22f44042f2ba6de942365a59fd0c6b0f20c07b"
        "71277c6ee7dd9d225032605aed1d3cf8242eb85c33a0afc3ab42764088d8f4a80faf804cd84360b2055181e58a0b5ad4c367abc6679820"
        "45ad0fd7e048af8c326d5db60233302b107e515b15b0f90e5f348c54192b559b4c0a86cdf0719387ea3ff6b1d60b324a98963c56927e2b"
        "8dd5a39ac792aeb85ebdbd8dc34b395c2b4def4d853ac21a7660348ea8c96c943de0baff3aa6849179e5ef2baa1731c81c605bec3860fc"
        "4a6a08cc9f75bde9533511780ff1e0b01d34c0dc3eb80a7e2f52a7a4b815dda98ea775dfe0c5b3d419b05934dda05a9616c0978cc99cc8"
        "d7b68227bd846419d765956c3d7aa811ce60af22df322fef0dce38c4278e0237f1d29ef139e201c8ecb4d36e79910d06c5ca4caa8c2886"
        "b96de6edd40d2499e30eb942f22bebf6ed5c8e37df9557e74d67dc467baafa68f1ce37c8bd9b3a4f9de71670128125aa16aca723223957"
        "5e1c6819c820ad16832f23647dd53c5740a8552f86901aa4f883efd5a3efd7c3bf458c5122712d44be43306c9b8264");
    assert(kseed.size() == 32 && want_pk.size() == 1312);
    auto kat = ValidatorPQKeyStore::from_seed(kseed);
    assert(kat.has_value());
    assert(kat->consensus_key().public_key == want_pk);
  }

  // deterministic keypair from a fixed seed (test vectors / recovery)
  const std::string seed(mldsa44_public_key_bytes ? 32 : 32, '\x2a');
  auto a = ValidatorPQKeyStore::from_seed(seed), b = ValidatorPQKeyStore::from_seed(seed);
  assert(a.has_value() && b.has_value());
  assert(a->consensus_key().public_key == b->consensus_key().public_key);
  assert(a->consensus_key().key_id == b->consensus_key().key_id);
  assert(!ValidatorPQKeyStore::from_seed(std::string(31, 'x')).has_value());  // bad seed length refused

  printf(
      "PQ_SIGNER_OK signer->verifier valid for all three signed surfaces; context-substitution(all 4 frozen "
      "surfaces)+tamper+wrongmsg rejected; "
      "seed deterministic; NIST FIPS-204 KeyGen KAT matched\n");
  return 0;
}
