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
