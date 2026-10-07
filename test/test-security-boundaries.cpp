#include <deque>

#include "adnl/decrypt-admission.h"
#include "blockchain-explorer/blockchain-explorer-http.hpp"
#include "blockchain-explorer/html-escape.h"
#include "http/http.h"
#include "td/utils/Time.h"
#include "td/utils/tests.h"
#include "validator/impl/dispatch-progress.h"

TEST(SecurityBoundaries, DecryptAdmission) {
  tos::adnl::DecryptBudget concurrency{10000, 0.000001, 4};
  for (int i = 0; i < 4; ++i) {
    CHECK(concurrency.acquire());
  }
  CHECK(!concurrency.acquire());
  concurrency.release();
  CHECK(concurrency.acquire());
  tos::adnl::DecryptBudget work{4, 60.0, 10000};
  size_t admitted = 0;
  for (int i = 0; i < 10000; ++i) {
    if (work.acquire()) {
      ++admitted;
      work.release();
    }
  }
  ASSERT_EQ(admitted, 4u);
  std::map<td::IPAddress, int> sources;
  for (td::uint32 i = 1; i < 10000; ++i) {
    td::IPAddress addr;
    addr.init_ipv4_port(td::IPAddress::ipv4_to_str(i), 1234).ensure();
    tos::adnl::bounded_source(sources, tos::adnl::preauth_source(addr), 64);
  }
  ASSERT_EQ(sources.size(), 64u);
  CHECK(tos::adnl::bounded_source(sources, sources.begin()->first, 64));
  td::IPAddress a, b;
  a.init_ipv6_port("2001:db8:abcd:1234::1", 100).ensure();
  b.init_ipv6_port("2001:db8:abcd:1234:ffff::ffff", 200).ensure();
  CHECK(tos::adnl::preauth_source(a) == tos::adnl::preauth_source(b));
}

namespace {

td::IPAddress ipv4_source(td::uint32 i) {
  td::IPAddress addr;
  addr.init_ipv4_port(td::IPAddress::ipv4_to_str(i), 1234).ensure();
  return addr;
}

}  // namespace

TEST(SecurityBoundaries, PreauthSourceIsChargedBeforeSharedBudgets) {
  // The shared budget holds 100 tokens and never refills during the test.
  tos::adnl::DecryptBudget process{1000000, 0.000001, 1 << 20};
  tos::adnl::DecryptBudget local{100, 3600.0, 1 << 20};
  tos::adnl::PreauthGate<int> gate{16, 75, 3600.0};
  size_t admitted = 0;
  for (int i = 0; i < 10000; ++i) {
    auto r = gate.admit(ipv4_source(1), process, local);
    if (r.is_ok()) {
      ++admitted;
    }
  }
  // One source gets its own burst and no more of the shared budget.
  ASSERT_EQ(admitted, 75u);
  CHECK(gate.admit(ipv4_source(2), process, local).is_ok());
}

TEST(SecurityBoundaries, PreauthSourceIsChargedBeforeProcessBudget) {
  // The process budget holds 100 tokens and never refills during the test.
  tos::adnl::DecryptBudget process{100, 3600.0, 1 << 20};
  tos::adnl::DecryptBudget local{1000000, 0.000001, 1 << 20};
  tos::adnl::PreauthGate<int> gate{16, 75, 3600.0};
  size_t admitted = 0;
  for (int i = 0; i < 10000; ++i) {
    if (gate.admit(ipv4_source(1), process, local).is_ok()) {
      ++admitted;
    }
  }
  ASSERT_EQ(admitted, 75u);
  CHECK(gate.admit(ipv4_source(2), process, local).is_ok());
}

TEST(SecurityBoundaries, PreauthLocalRefusalReleasesProcessSlot) {
  tos::adnl::DecryptBudget process{1000000, 0.000001, 1};
  tos::adnl::DecryptBudget local{1, 3600.0, 1 << 20};
  tos::adnl::PreauthGate<int> gate{16, 75, 3600.0};
  CHECK(gate.admit(ipv4_source(1), process, local).is_ok());
  // The local budget has no token left: the process slot taken for this
  // packet must be returned.
  CHECK(gate.admit(ipv4_source(2), process, local).is_error());
  CHECK(process.acquire());
  process.release();
}

TEST(SecurityBoundaries, PreauthTableEvictsOnlyIdleSources) {
  tos::adnl::DecryptBudget process{1000000, 0.000001, 1 << 20};
  tos::adnl::DecryptBudget local{1000000, 0.000001, 1 << 20};
  tos::adnl::PreauthGate<int> gate{4, 75, 0.33};
  // Four sources that were seen and are idle, such as entries pinned by a
  // recent-peer set, do not lock a new source out: the oldest is replaced.
  for (td::uint32 i = 1; i <= 4; ++i) {
    auto r = gate.admit(ipv4_source(i), process, local);
    CHECK(r.is_ok());
    r.ok_ref().source().extra = static_cast<int>(i);
  }
  {
    auto r = gate.admit(ipv4_source(5), process, local);
    CHECK(r.is_ok());
  }
  ASSERT_EQ(gate.size(), 4u);
  CHECK(!gate.contains(ipv4_source(1)));
  CHECK(gate.contains(ipv4_source(5)));
  // Touching a source makes it the most recently used one.
  CHECK(gate.admit(ipv4_source(2), process, local).is_ok());
  CHECK(gate.admit(ipv4_source(6), process, local).is_ok());
  CHECK(gate.contains(ipv4_source(2)));
  CHECK(!gate.contains(ipv4_source(3)));

  // A source with a decryption in flight is never replaced.
  std::deque<tos::adnl::PreauthGate<int>::Ticket> busy;
  for (td::uint32 i : {2u, 4u, 5u, 6u}) {
    auto r = gate.admit(ipv4_source(i), process, local);
    CHECK(r.is_ok());
    busy.push_back(r.move_as_ok());
  }
  CHECK(gate.admit(ipv4_source(7), process, local).is_error());
  ASSERT_EQ(busy.front().source().extra, 2);
  busy.pop_front();
  CHECK(gate.admit(ipv4_source(7), process, local).is_ok());
  CHECK(!gate.contains(ipv4_source(2)));
  for (td::uint32 i : {4u, 5u, 6u, 7u}) {
    CHECK(gate.contains(ipv4_source(i)));
  }
}

TEST(SecurityBoundaries, PreauthTicketReleasesConcurrencyNotRate) {
  tos::adnl::DecryptBudget process{1000000, 0.000001, 1};
  tos::adnl::DecryptBudget local{1000000, 0.000001, 1};
  tos::adnl::PreauthGate<int> gate{4, 2, 3600.0};
  {
    auto first = gate.admit(ipv4_source(1), process, local);
    CHECK(first.is_ok());
    ASSERT_EQ(first.ok_ref().source().in_flight, 1u);
    // Both budgets admit one decryption at a time.
    CHECK(gate.admit(ipv4_source(2), process, local).is_error());
  }
  {
    auto again = gate.admit(ipv4_source(1), process, local);
    CHECK(again.is_ok());
  }
  // The source's two rate tokens are spent; releasing a ticket does not
  // return them.
  CHECK(gate.admit(ipv4_source(1), process, local).is_error());
  gate.erase_idle_if([](auto &) { return true; });
  CHECK(gate.empty());
}

TEST(SecurityBoundaries, HttpFraming) {
  for (const std::string headers :
       {"Transfer-Encoding : chunked\r\n", "Transfer-Encoding: gzip\r\n", "Transfer-Encoding: chunked, chunked\r\n",
        "Transfer-Encoding: gzip, chunked\r\n", "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n",
        "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n", "Content-Length: +5\r\n", ": ignored\r\n",
        "X\\Name: bad\r\n", "X: bad\x01value\r\n", "X: bad\n"}) {
    td::ChainBufferWriter wire;
    wire.init(0);
    wire.append("POST / HTTP/1.1\r\n" + headers + "\r\n");
    auto input = wire.extract_reader();
    std::string line;
    bool pause;
    auto result = tos::http::HttpRequest::parse(nullptr, line, pause, input);
    CHECK(result.is_error());
  }
  auto response = tos::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, true).move_as_ok();
  response->complete_parse_header().ensure();
  auto payload = response->create_empty_payload().move_as_ok();
  ASSERT_EQ(payload->payload_type(), tos::http::HttpPayload::PayloadType::pt_eof);
  td::ChainBufferWriter wire;
  wire.init(0);
  response->store_http(wire);
  auto input = wire.extract_reader();
  auto bytes = input.move_as_buffer_slice().as_slice().str();
  CHECK(bytes.starts_with("HTTP/1.1 200 OK\r\n"));
  CHECK(bytes.find("Transfer-Encoding: chunked\r\n") != std::string::npos);
  auto older = tos::http::HttpResponse::create("HTTP/1.0", 200, "OK", false, true).move_as_ok();
  older->complete_parse_header().ensure();
  CHECK(!older->keep_alive());
  td::ChainBufferWriter old_wire;
  old_wire.init(0);
  older->store_http(old_wire);
  auto old_reader = old_wire.extract_reader();
  auto old_headers = old_reader.move_as_buffer_slice().as_slice().str();
  CHECK(old_headers.find("Connection: Close\r\n") != std::string::npos);
  CHECK(old_headers.find("Transfer-Encoding") == std::string::npos);
  auto raw_payload = older->create_empty_payload().move_as_ok();
  raw_payload->add_chunk(td::BufferSlice("body"));
  raw_payload->complete_parse();
  td::ChainBufferWriter raw_wire;
  raw_wire.init(0);
  raw_payload->store_http(raw_wire, 1024, tos::http::HttpPayload::PayloadType::pt_eof);
  auto raw_reader = raw_wire.extract_reader();
  ASSERT_EQ(raw_reader.move_as_buffer_slice().as_slice().str(), "body");
  auto bad = tos::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, true).move_as_ok();
  CHECK(bad->add_header({"Transfer-Encoding", "gzip"}).is_error());
  auto valid = tos::http::HttpRequest::create("POST", "/", "HTTP/1.1").move_as_ok();
  valid->add_header({"Transfer-Encoding", "CHUNKED"}).ensure();
  valid->complete_parse_header().ensure();
  ASSERT_EQ(valid->create_empty_payload().move_as_ok()->payload_type(),
            tos::http::HttpPayload::PayloadType::pt_chunked);
}

namespace {

td::Result<std::unique_ptr<tos::http::HttpRequest>> parse_request(const std::string &bytes) {
  td::ChainBufferWriter wire;
  wire.init(0);
  wire.append(bytes);
  auto input = wire.extract_reader();
  std::string line;
  bool exit_loop;
  return tos::http::HttpRequest::parse(nullptr, line, exit_loop, input);
}

td::Status parse_chunked_body(const std::string &body) {
  td::ChainBufferWriter wire;
  wire.init(0);
  wire.append("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + body);
  auto input = wire.extract_reader();
  std::string line;
  bool exit_loop;
  TRY_RESULT(request, tos::http::HttpRequest::parse(nullptr, line, exit_loop, input));
  CHECK(request && request->check_parse_header_completed());
  TRY_RESULT(payload, request->create_empty_payload());
  TRY_STATUS(payload->parse(input));
  if (!payload->parse_completed()) {
    return td::Status::Error("incomplete body");
  }
  return td::Status::OK();
}

}  // namespace

TEST(SecurityBoundaries, HttpChunkSizesAndHeaderValues) {
  for (const std::string body : {"5\r\nhello\r\n0\r\n\r\n", "5;ext=1\r\nhello\r\n0\r\n\r\n",
                                 "5 ;ext\r\nhello\r\n0;done\r\n\r\n", "5\r\nhello\r\n0\r\nX-Sum: 1\r\n\r\n"}) {
    parse_chunked_body(body).ensure();
  }
  for (const std::string &body : std::vector<std::string>{
           " 5\r\nhello\r\n0\r\n\r\n", "5 junk\r\nhello\r\n0\r\n\r\n", "10000000000000005\r\nhello\r\n0\r\n\r\n",
           "\r\nhello\r\n0\r\n\r\n", "5 \r\nhello\r\n0\r\n\r\n", "5\r\nhello\r\n0\r\nBad Name: x\r\n\r\n",
           std::string("5\r\nhello\r\n0\r\nX: a\x0b"
                       "b\r\n\r\n")}) {
    CHECK(parse_chunked_body(body).is_error());
  }
  ASSERT_EQ(tos::http::util::parse_chunk_size("fffffffffffffff").move_as_ok(), 0xfffffffffffffffULL);
  CHECK(tos::http::util::parse_chunk_size("1000000000000000").is_error());

  // Only SP and HTAB are trimmed from header values; other control
  // characters reach the value check.
  for (const std::string &header : {std::string("Transfer-Encoding: chunked\x0b\r\n"),
                                    std::string("Content-Length: 5\0\r\n", 20), std::string("X: \x0bvalue\r\n")}) {
    CHECK(parse_request("POST / HTTP/1.1\r\n" + header + "\r\n").is_error());
  }
  parse_request("POST / HTTP/1.1\r\nContent-Length: \t5 \r\n\r\n").ensure();
}

TEST(SecurityBoundaries, HttpConnectionOptions) {
  auto upgrade =
      parse_request("GET / HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nX-Kept: 1\r\n\r\n")
          .move_as_ok();
  CHECK(upgrade->keep_alive());
  ASSERT_EQ(upgrade->get_header("Upgrade"), "");
  ASSERT_EQ(upgrade->get_header("X-Kept"), "1");
  // "close" wins over a later keep-alive.
  auto closing =
      parse_request("GET / HTTP/1.1\r\nConnection: close\r\nProxy-Connection: keep-alive\r\n\r\n").move_as_ok();
  CHECK(!closing->keep_alive());
  for (const std::string header : {"Connection: keep-alive,,\r\n", "Connection:\r\n", "Connection: a b\r\n",
                                   "Connection: Content-Length\r\n", "Connection: transfer-encoding\r\n"}) {
    CHECK(parse_request("GET / HTTP/1.1\r\n" + header + "\r\n").is_error());
  }
  auto response = tos::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, true).move_as_ok();
  response->add_header({"Connection", "close, X-Hop"}).ensure();
  response->add_header({"X-Hop", "secret"}).ensure();
  response->complete_parse_header().ensure();
  CHECK(!response->keep_alive());
  td::ChainBufferWriter wire;
  wire.init(0);
  response->store_http(wire);
  auto reader = wire.extract_reader();
  CHECK(reader.move_as_buffer_slice().as_slice().str().find("X-Hop") == std::string::npos);
}

TEST(SecurityBoundaries, HttpFramedBodyMatchesContentLength) {
  using tos::http::HttpPayload;
  auto make = [] {
    auto request = tos::http::HttpRequest::create("POST", "/", "HTTP/1.1").move_as_ok();
    request->add_header({"Content-Length", "5"}).ensure();
    request->complete_parse_header().ensure();
    return request->create_empty_payload().move_as_ok();
  };
  auto longer = make();
  CHECK(longer->add_framed_chunk(td::BufferSlice("hello!")).is_error());
  auto shorter = make();
  shorter->add_framed_chunk(td::BufferSlice("hel")).ensure();
  CHECK(shorter->complete_framed_parse().is_error());
  CHECK(!shorter->parse_completed());
  auto exact = make();
  exact->add_framed_chunk(td::BufferSlice("hel")).ensure();
  exact->add_framed_chunk(td::BufferSlice("lo")).ensure();
  CHECK(exact->add_framed_chunk(td::BufferSlice("x")).is_error());
  exact->complete_framed_parse().ensure();
  CHECK(exact->add_framed_chunk(td::BufferSlice("x")).is_error());
  ASSERT_EQ(exact->ready_bytes(), 5u);

  auto empty = std::make_shared<HttpPayload>(HttpPayload::PayloadType::pt_empty);
  CHECK(empty->add_framed_chunk(td::BufferSlice("x")).is_error());
  auto chunked = std::make_shared<HttpPayload>(HttpPayload::PayloadType::pt_chunked, 1, 1 << 20);
  chunked->add_framed_chunk(td::BufferSlice("any length")).ensure();
  chunked->complete_framed_parse().ensure();
}

namespace {

tos::tl_object_ptr<tos::tos_api::http_response> remote_answer(td::int32 code, std::string content_length,
                                                              bool no_payload) {
  std::vector<tos::tl_object_ptr<tos::tos_api::http_header>> headers;
  if (!content_length.empty()) {
    headers.push_back(tos::create_tl_object<tos::tos_api::http_header>("Content-Length", content_length));
  }
  return tos::create_tl_object<tos::tos_api::http_response>("HTTP/1.1", code, "Status", std::move(headers), no_payload);
}

tos::tl_object_ptr<tos::tos_api::http_payloadPart> payload_part(std::string data, bool last) {
  return tos::create_tl_object<tos::tos_api::http_payloadPart>(
      td::BufferSlice(data), std::vector<tos::tl_object_ptr<tos::tos_api::http_header>>(), last);
}

std::unique_ptr<tos::http::HttpRequest> relayed_request(const std::string &method) {
  auto request = tos::http::HttpRequest::create(method, "/", "HTTP/1.1").move_as_ok();
  request->complete_parse_header().ensure();
  return request;
}

}  // namespace

TEST(SecurityBoundaries, HttpRelayedResponseFraming) {
  using tos::http::HttpPayload;
  using tos::http::relayed_response;
  auto get = relayed_request("GET");
  // A remote that sends no payload may not announce one.
  CHECK(relayed_response(*get, *remote_answer(200, "5", true), {}).is_error());
  CHECK(relayed_response(*relayed_request("CONNECT"), *remote_answer(403, "5", true), {}).is_error());
  // HEAD answers and bodiless statuses keep their metadata lengths.
  for (auto [method, code, no_payload] : {std::tuple{"HEAD", 200, false}, std::tuple{"HEAD", 200, true},
                                          std::tuple{"GET", 304, true}, std::tuple{"GET", 204, true}}) {
    auto relayed = relayed_response(*relayed_request(method), *remote_answer(code, "5", no_payload), {});
    CHECK(relayed.is_ok());
    auto payload = relayed.move_as_ok().second;
    ASSERT_EQ(payload->payload_type(), HttpPayload::PayloadType::pt_empty);
    if (!no_payload) {
      CHECK(tos::http::add_payload_part(*payload, *payload_part("", true)).move_as_ok());
    }
    CHECK(payload->parse_completed());
  }
  // An established tunnel has no length.
  auto tunnel = relayed_response(*relayed_request("CONNECT"), *remote_answer(200, "", false), {}).move_as_ok();
  ASSERT_EQ(tunnel.second->payload_type(), HttpPayload::PayloadType::pt_tunnel);
  CHECK(relayed_response(*get, *remote_answer(200, "0", true), {}).move_as_ok().second->parse_completed());

  // Relayed parts are reconciled with the declared length.
  auto body = [&] { return relayed_response(*get, *remote_answer(200, "5", false), {}).move_as_ok().second; };
  auto longer = body();
  CHECK(tos::http::add_payload_part(*longer, *payload_part("hello!", false)).is_error());
  auto shorter = body();
  CHECK(!tos::http::add_payload_part(*shorter, *payload_part("hel", false)).move_as_ok());
  CHECK(tos::http::add_payload_part(*shorter, *payload_part("", true)).is_error());
  auto exact = body();
  CHECK(!tos::http::add_payload_part(*exact, *payload_part("hel", false)).move_as_ok());
  CHECK(tos::http::add_payload_part(*exact, *payload_part("lo", true)).move_as_ok());
  ASSERT_EQ(exact->ready_bytes(), 5u);
}

TEST(SecurityBoundaries, HttpRelayedRequestFraming) {
  auto request_with_length = [] {
    std::vector<tos::tl_object_ptr<tos::tos_api::http_header>> headers;
    headers.push_back(tos::create_tl_object<tos::tos_api::http_header>("Content-Length", "5"));
    auto tl = tos::create_tl_object<tos::tos_api::http_request>(td::Bits256::zero(), "POST", "/", "HTTP/1.1",
                                                                std::move(headers));
    auto request = tos::http::HttpRequest::create(*tl).move_as_ok();
    return request->create_empty_payload().move_as_ok();
  };
  auto longer = request_with_length();
  CHECK(tos::http::add_payload_part(*longer, *payload_part("hello, backend", true)).is_error());
  auto shorter = request_with_length();
  CHECK(tos::http::add_payload_part(*shorter, *payload_part("hi", true)).is_error());
  CHECK(!shorter->parse_completed());
  auto exact = request_with_length();
  CHECK(tos::http::add_payload_part(*exact, *payload_part("hello", true)).move_as_ok());
}

TEST(SecurityBoundaries, ExplorerPathPrefixAndPolicy) {
  for (const char *prefix : {"", "/", "/explorer/", "/a.b_c~d-e/"}) {
    CHECK(is_safe_path_prefix(prefix));
  }
  for (const char *prefix :
       {"/\"><script>/", "/a b/", "/<x>/", "/'/", "/%22/", "//other.invalid/", "/a//b/", "/a?b/"}) {
    CHECK(!is_safe_path_prefix(prefix));
  }
  std::string policy = kExplorerHtmlPolicy;
  CHECK(policy.find("form-action 'self'") != std::string::npos);
  CHECK(policy.find("script-src 'self' https://ajax.googleapis.com/ajax/libs/") != std::string::npos);
  // No script source is a whole host.
  for (const char *host : {"https://ajax.googleapis.com ", "https://cdnjs.cloudflare.com ",
                           "https://maxcdn.bootstrapcdn.com;", "https://cdnjs.cloudflare.com;"}) {
    CHECK(policy.find(host) == std::string::npos);
  }
  HttpAnswer answer("status", "/\"><b>/");
  auto page = answer.finish();
  CHECK(page.find("\"><b>") == std::string::npos);
}

TEST(SecurityBoundaries, HtmlErrorText) {
  ASSERT_EQ(escape_html("<img src=x onerror='attack()'>&\""),
            "&lt;img src=x onerror=&#39;attack()&#39;&gt;&amp;&quot;");
  ASSERT_EQ(escape_html("ordinary error"), "ordinary error");
  HttpAnswer answer("error", "/");
  auto page = answer.abort(td::Status::Error("<img src=x onerror='attack()'>"));
  CHECK(page.find("<img src=x") == std::string::npos);
  CHECK(page.find("&lt;img src=x") != std::string::npos);
  HttpAnswer streamed("error", "/");
  streamed << HttpAnswer::Error{td::Status::Error("<script>attack()</script>")};
  page = streamed.finish();
  CHECK(page.find("<script>attack()") == std::string::npos);
  CHECK(page.find("&lt;script&gt;attack()") != std::string::npos);
}

TEST(SecurityBoundaries, DispatchCleanupAndRegrowth) {
  using namespace tos::validator;
  const td::uint64 old = 2000, drops = 1200, regrowth = 1300, limit = 1000;
  const auto post_cleanup = old - drops;
  const auto final_size = post_cleanup + regrowth;
  CHECK(old > limit && final_size > limit);
  CHECK(dispatch_progress_required(old, post_cleanup, limit, limit));
  CHECK(!dispatch_progress_required(old, final_size, limit, limit));
  CHECK(is_pre_dispatch_cleanup(1, 6));
  CHECK(!is_pre_dispatch_cleanup(1, 4));  // same-shard reimport
  CHECK(!is_pre_dispatch_cleanup(1, 7));  // requeue after merge
  CHECK(!is_pre_dispatch_cleanup(2, 6));  // no removal
  CHECK(!dispatch_progress_required(old, 1001, limit, limit));
  CHECK(dispatch_progress_required(1000, 2000, limit, limit));
}
