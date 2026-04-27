#include "json-rpc-server.h"

#include "evm/rpc/handlers.h"

#include <cstdio>

namespace {

// M-02: drive `JsonRpcServer::decide_listen_admission` through every
// row of the audit's listener-admission matrix. The test never spins
// up a real TCP server — it pokes the pure decision helper, which
// `listen()` consults right after computing `is_loopback` and BEFORE
// applying `evm_workchain::set_evm_rpc_profile`. A regression that
// re-orders the listener (applying the profile before the loopback
// check) or accepts AdminLocal on a public interface without an API
// key is an immediate test failure here.
struct M02Case {
  const char* label;
  bool is_loopback;
  ::evm_workchain::EvmRpcProfile profile;
  bool api_key_empty;
  bool allow_remote_admin;
  bool readonly;
  tos::JsonRpcServer::ListenDecision expected;
};

bool run_m02_listen_matrix() {
  using P = ::evm_workchain::EvmRpcProfile;
  using D = tos::JsonRpcServer::ListenDecision;

  // Audit M-02 (lines 880-888) plus a few defensive sub-cases that
  // pin down the exact reason the listener refuses (missing override
  // vs missing api key). Every accept/refuse outcome is asserted
  // explicitly — there is no "any refuse will do" wildcard.
  const M02Case cases[] = {
      // Row 1: loopback + admin profile, no api key, no override.
      // Loopback is the documented home for AdminLocal — accept.
      {"127.0.0.1 + admin + no key + no override + readonly",
       /*is_loopback=*/true, P::AdminLocal,
       /*api_key_empty=*/true, /*allow_remote_admin=*/false,
       /*readonly=*/true, D::Accept},

      // Row 2: 0.0.0.0 + admin profile, no api key, no override.
      // The listener-layer hardening must refuse with the
      // missing-override reason BEFORE the api-key reason, because
      // the operator first needs to opt in to the dangerous mode.
      {"0.0.0.0 + admin + no key + no override + readonly",
       /*is_loopback=*/false, P::AdminLocal,
       /*api_key_empty=*/true, /*allow_remote_admin=*/false,
       /*readonly=*/true, D::RefuseAdminRemoteWithoutOverride},

      // Row 3: 0.0.0.0 + admin profile + api key, no override.
      // Override is missing — refuse with the same reason as row 2;
      // the api key alone does NOT imply consent to remote admin.
      {"0.0.0.0 + admin + key + no override + readonly",
       /*is_loopback=*/false, P::AdminLocal,
       /*api_key_empty=*/false, /*allow_remote_admin=*/false,
       /*readonly=*/true, D::RefuseAdminRemoteWithoutOverride},

      // Row 4: 0.0.0.0 + admin + api key + override — accept. Two
      // explicit consent tokens (API key AND override flag) are the
      // only path that opens AdminLocal on a public interface.
      {"0.0.0.0 + admin + key + override + readonly",
       /*is_loopback=*/false, P::AdminLocal,
       /*api_key_empty=*/false, /*allow_remote_admin=*/true,
       /*readonly=*/true, D::Accept},

      // Row 4b: same as row 4 but missing the api key. The override
      // is set but the api key is absent — refuse with the
      // missing-api-key reason (override pre-condition was met but
      // we still refuse because the second pre-condition was not).
      {"0.0.0.0 + admin + no key + override + readonly",
       /*is_loopback=*/false, P::AdminLocal,
       /*api_key_empty=*/true, /*allow_remote_admin=*/true,
       /*readonly=*/true, D::RefuseAdminRemoteWithoutApiKey},

      // Row 5: 0.0.0.0 + follower profile, no api key. Read-only
      // FollowerPublic on a public interface is fine — that is the
      // documented role of a follower RPC replica.
      {"0.0.0.0 + follower + no key + readonly",
       /*is_loopback=*/false, P::FollowerPublic,
       /*api_key_empty=*/true, /*allow_remote_admin=*/false,
       /*readonly=*/true, D::Accept},

      // Row 6: 0.0.0.0 + validator profile, no api key, readonly.
      // ValidatorMinimal is the safest default and read-only mode
      // makes the unauthenticated surface acceptable.
      {"0.0.0.0 + validator + no key + readonly",
       /*is_loopback=*/false, P::ValidatorMinimal,
       /*api_key_empty=*/true, /*allow_remote_admin=*/false,
       /*readonly=*/true, D::Accept},

      // Row 7 (defensive): 0.0.0.0 + validator profile + write
      // enabled + no api key. Pre-existing rule (independent of the
      // M-02 AdminLocal hardening): refuse the write-enabled
      // unauthenticated public surface.
      {"0.0.0.0 + validator + no key + write",
       /*is_loopback=*/false, P::ValidatorMinimal,
       /*api_key_empty=*/true, /*allow_remote_admin=*/false,
       /*readonly=*/false, D::RefuseWriteRemoteWithoutAuth},

      // Row 8 (defensive): same as row 7 but with an api key. The
      // api key satisfies the write-remote rule, so the listener
      // accepts.
      {"0.0.0.0 + validator + key + write",
       /*is_loopback=*/false, P::ValidatorMinimal,
       /*api_key_empty=*/false, /*allow_remote_admin=*/false,
       /*readonly=*/false, D::Accept},

      // Row 9 (defensive): loopback + admin + write + no key. The
      // M-02 admin hardening only kicks in on non-loopback, and the
      // write-remote rule only kicks in on non-loopback, so a fully
      // unauthenticated write-enabled admin endpoint on 127.0.0.1
      // is accepted (this is the historical default for local
      // development / conformance suites).
      {"127.0.0.1 + admin + no key + write",
       /*is_loopback=*/true, P::AdminLocal,
       /*api_key_empty=*/true, /*allow_remote_admin=*/false,
       /*readonly=*/false, D::Accept},
  };

  bool all_ok = true;
  for (const auto& c : cases) {
    auto got = tos::JsonRpcServer::decide_listen_admission(
        c.is_loopback, c.profile, c.api_key_empty, c.allow_remote_admin,
        c.readonly);
    bool ok = (got == c.expected);
    printf("    [%s] %s\n", ok ? "PASS" : "FAIL", c.label);
    if (!ok) {
      printf("      expected=%d got=%d\n",
             static_cast<int>(c.expected), static_cast<int>(got));
      all_ok = false;
    }
  }
  return all_ok;
}

}  // namespace

int main() {
  using tos::JsonRpcResponseCache;
  bool ok = false;

  printf("=== test_json_rpc_cache ===\n");

  JsonRpcResponseCache cache(3, 16);
  cache.store("a", "\"A\"", td::Timestamp::in(60.0));
  cache.store("b", "\"BB\"", td::Timestamp::in(60.0));
  cache.store("c", "\"CCC\"", td::Timestamp::in(60.0));
  auto hit_a = cache.lookup("a");
  cache.store("d", "\"DDDD\"", td::Timestamp::in(60.0));

  bool lru_ok = hit_a.has_value() &&
                cache.lookup("a").has_value() &&
                !cache.lookup("b").has_value() &&
                cache.lookup("c").has_value() &&
                cache.lookup("d").has_value() &&
                cache.size() == 3;

  printf("  LRU eviction: %s\n", lru_ok ? "PASS" : "FAIL");

  JsonRpcResponseCache body_cache(8, 10);
  body_cache.store("x", "\"1234\"", td::Timestamp::in(60.0));
  body_cache.store("y", "\"5678\"", td::Timestamp::in(60.0));
  body_cache.store("z", "\"abcdefghi\"", td::Timestamp::in(60.0));

  bool body_budget_ok = !body_cache.lookup("x").has_value() &&
                        body_cache.lookup("y").has_value() &&
                        !body_cache.lookup("z").has_value() &&
                        body_cache.body_bytes() <= 10;

  printf("  Body budget: %s\n", body_budget_ok ? "PASS" : "FAIL");

  JsonRpcResponseCache update_cache(2, 32);
  update_cache.store("same", "\"old\"", td::Timestamp::in(60.0));
  update_cache.store("other", "\"1\"", td::Timestamp::in(60.0));
  update_cache.store("same", "\"newer\"", td::Timestamp::in(60.0));

  auto updated = update_cache.lookup("same");
  bool update_ok = updated.has_value() &&
                   *updated == "\"newer\"" &&
                   update_cache.size() == 2;

  printf("  Update replace: %s\n", update_ok ? "PASS" : "FAIL");

  // M-02: listener-admission decision matrix.
  printf("  M-02 listen-admission matrix:\n");
  bool listen_ok = run_m02_listen_matrix();
  printf("  M-02 listen-admission matrix: %s\n",
         listen_ok ? "PASS" : "FAIL");

  ok = lru_ok && body_budget_ok && update_ok && listen_ok;
  printf("  %s\n", ok ? "PASSED" : "FAILED");
  return ok ? 0 : 1;
}
