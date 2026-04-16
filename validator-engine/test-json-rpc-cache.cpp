#include "json-rpc-server.h"

#include <cstdio>

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

  ok = lru_ok && body_budget_ok && update_ok;
  printf("  %s\n", ok ? "PASSED" : "FAILED");
  return ok ? 0 : 1;
}
