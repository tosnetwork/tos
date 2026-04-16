#include "json-rpc-server.h"

#include <cstdio>

int main() {
  using tos::JsonRpcServer;

  printf("=== test_json_rpc_cache ===\n");

  JsonRpcServer::Options opts;
  opts.cache_ttl = 60;
  opts.cache_max_entries = 3;
  opts.cache_max_body_bytes = 16;
  JsonRpcServer server({}, opts);

  server.cache_store_for_test("a", "\"A\"", 60);
  server.cache_store_for_test("b", "\"BB\"", 60);
  server.cache_store_for_test("c", "\"CCC\"", 60);
  auto hit_a = server.cache_lookup_for_test("a");
  server.cache_store_for_test("d", "\"DDDD\"", 60);

  bool lru_ok = hit_a.has_value() &&
                server.cache_lookup_for_test("a").has_value() &&
                !server.cache_lookup_for_test("b").has_value() &&
                server.cache_lookup_for_test("c").has_value() &&
                server.cache_lookup_for_test("d").has_value() &&
                server.cache_entries_for_test() == 3;

  printf("  LRU eviction: %s\n", lru_ok ? "PASS" : "FAIL");

  JsonRpcServer::Options body_opts;
  body_opts.cache_ttl = 60;
  body_opts.cache_max_entries = 8;
  body_opts.cache_max_body_bytes = 10;
  JsonRpcServer body_server({}, body_opts);

  body_server.cache_store_for_test("x", "\"1234\"", 60);
  body_server.cache_store_for_test("y", "\"5678\"", 60);
  body_server.cache_store_for_test("z", "\"abcdefghi\"", 60);

  bool body_budget_ok = !body_server.cache_lookup_for_test("x").has_value() &&
                        body_server.cache_lookup_for_test("y").has_value() &&
                        !body_server.cache_lookup_for_test("z").has_value() &&
                        body_server.cache_body_bytes_for_test() <= body_opts.cache_max_body_bytes;

  printf("  Body budget: %s\n", body_budget_ok ? "PASS" : "FAIL");

  JsonRpcServer::Options update_opts;
  update_opts.cache_ttl = 60;
  update_opts.cache_max_entries = 2;
  update_opts.cache_max_body_bytes = 32;
  JsonRpcServer update_server({}, update_opts);

  update_server.cache_store_for_test("same", "\"old\"", 60);
  update_server.cache_store_for_test("other", "\"1\"", 60);
  update_server.cache_store_for_test("same", "\"newer\"", 60);

  auto updated = update_server.cache_lookup_for_test("same");
  bool update_ok = updated.has_value() &&
                   *updated == "\"newer\"" &&
                   update_server.cache_entries_for_test() == 2;

  printf("  Update replace: %s\n", update_ok ? "PASS" : "FAIL");

  bool ok = lru_ok && body_budget_ok && update_ok;
  printf("  %s\n", ok ? "PASSED" : "FAILED");
  return ok ? 0 : 1;
}
