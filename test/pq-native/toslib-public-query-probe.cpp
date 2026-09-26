// Test-only public Client -> production Lite factory -> actual typed decoder.
#include "toslib/Client.h"
#include "toslib/PublicNetworkTestHook.h"
#include "tl-utils/lite-utils.hpp"
#include "td/utils/filesystem.h"
#include "td/utils/format.h"
#include <condition_variable>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <set>
#include <sstream>
namespace {
using namespace toslib;
class Proxy final : public liteclient::ExtClient {
 public:
  Proxy(td::actor::ActorOwn<liteclient::ExtClient> real, td::uint32 generation, std::string out)
      : real_(std::move(real)), generation_(generation), out_(std::move(out)) {}
  void arm(td::uint64 id, std::string nonce, td::Promise<QueryTraceContext> ack) {
    bool hex = nonce.size() == 64;
    for (char c : nonce) hex = hex && ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    if (!id || !hex || pending_ || armed_ || used_ids_.count(id) || used_nonces_.count(nonce))
      return ack.set_error(td::Status::Error("Q01 arm not unique or transport busy"));
    strict_ = true; armed_ = true; context_ = {id, generation_, ++token_}; nonce_ = std::move(nonce);
    used_ids_.insert(id); used_nonces_.insert(nonce_);
    ack.set_value(context_);
  }
  void bound(QueryTraceContext context, td::BufferSlice bytes, td::Timestamp deadline,
             td::Promise<td::BufferSlice> promise) {
    auto inner = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto expected = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);
    if (!armed_ || context.public_request_id != context_.public_request_id ||
        context.transport_generation != generation_ || context.arm_token != context_.arm_token ||
        bytes.as_slice() != expected.as_slice())
      return fail(std::move(promise), "Q01 bound query differs");
    armed_ = false;
    auto nonce = nonce_;
    auto prefix = out_ + "/" + nonce;
    td::write_file(prefix + ".request.bin", bytes.as_slice()).ensure();
    std::ostringstream exact_deadline; exact_deadline << std::hexfloat << deadline.at();
    td::write_file(prefix + ".deadline.txt", exact_deadline.str()).ensure();
    LOG(ERROR) << "Q01_PUBLIC_BOUND id=" << context.public_request_id << " generation=" << generation_
               << " token=" << context.arm_token << " nonce=" << nonce << " deadline=" << deadline.at();
    forward(nonce, std::move(bytes), deadline,
      td::Promise<td::BufferSlice>([prefix, promise = std::move(promise)](td::Result<td::BufferSlice> result) mutable {
        if (result.is_ok()) td::write_file(prefix + ".answer.bin", result.ok().as_slice()).ensure();
        else td::write_file(prefix + ".transport-error.txt", result.error().to_string()).ensure();
        // Same original result is returned to ExtClient queries_ and its real decoder.
        promise.set_result(std::move(result));
      }));
  }
  void send_query(std::string name, td::BufferSlice data, td::Timestamp timeout,
                  td::Promise<td::BufferSlice> promise) override {
    if (strict_) return fail(std::move(promise), "Q01 unexpected unbound query");
    LOG(ERROR) << "Q01_BOOTSTRAP_UNBOUND name=" << name;
    forward(std::move(name), std::move(data), timeout, std::move(promise));
  }
  void get_servers_status(td::Promise<std::vector<bool>> promise) override {
    td::actor::send_closure(real_, &liteclient::ExtClient::get_servers_status, std::move(promise));
  }
  void reset_servers() override {
    armed_ = false; ++token_;
    td::actor::send_closure(real_, &liteclient::ExtClient::reset_servers);
  }
 private:
  td::actor::ActorOwn<liteclient::ExtClient> real_;
  td::uint32 generation_; std::string out_, nonce_;
  td::uint64 token_{0}; QueryTraceContext context_;
  bool strict_{false}, armed_{false}; size_t pending_{0};
  std::set<td::uint64> used_ids_; std::set<std::string> used_nonces_;
  void fail(td::Promise<td::BufferSlice> promise, const char* text) {
    td::write_file(out_ + "/unexpected-query.txt", text).ensure();
    promise.set_error(td::Status::Error(text));
  }
  void forward(std::string name, td::BufferSlice bytes, td::Timestamp deadline,
               td::Promise<td::BufferSlice> promise) {
    ++pending_;
    auto self = actor_id(this);
    td::actor::send_closure(real_, &liteclient::ExtClient::send_query, std::move(name), std::move(bytes), deadline,
      td::Promise<td::BufferSlice>([self, promise = std::move(promise)](td::Result<td::BufferSlice> result) mutable {
        td::actor::send_closure(self, &Proxy::complete, std::move(result), std::move(promise));
      }));
  }
 public:
  void complete(td::Result<td::BufferSlice> result, td::Promise<td::BufferSlice> promise) {
    CHECK(pending_); --pending_; promise.set_result(std::move(result));
  }
};
class Hook final : public PublicNetworkTestHook {
 public:
  explicit Hook(std::string out) : out_(std::move(out)) {}
  td::actor::ActorOwn<liteclient::ExtClient> decorate(td::actor::ActorOwn<liteclient::ExtClient> real,
                                                     td::uint32 generation) override {
    auto proxy = td::actor::create_actor<Proxy>("Q01PublicProxy", std::move(real), generation, out_);
    proxy_ = proxy.get(); return std::move(proxy);
  }
  void arm(td::uint64 id, std::string nonce, td::Promise<QueryTraceContext> ack) override {
    if (proxy_.empty()) return ack.set_error(td::Status::Error("Q01 factory absent"));
    td::actor::send_closure(proxy_, &Proxy::arm, id, std::move(nonce), std::move(ack));
  }
  void send_bound_query(QueryTraceContext context, td::BufferSlice data, td::Timestamp deadline,
                         td::Promise<td::BufferSlice> promise) override {
    td::actor::send_closure(proxy_, &Proxy::bound, context, std::move(data), deadline, std::move(promise));
  }
 private:
  std::string out_; td::actor::ActorId<Proxy> proxy_;
};
}
int main(int argc, char** argv) {
  // A separate ticketed wrapper owns server/clone/stop/recovery/OS receipts.
  if (argc != 3) { std::cerr << "config output; stdin: public_id nonce\n"; return 2; }
  auto config = td::read_file(td::CSlice(argv[1])).move_as_ok();
  std::string out = argv[2];
  toslib::Client::execute({1, toslib_api::make_object<toslib_api::setLogVerbosityLevel>(5)});
  auto hook = std::make_shared<Hook>(out);
  toslib::Client client(hook);
  client.send({1, toslib_api::make_object<toslib_api::init>(toslib_api::make_object<toslib_api::options>(
    toslib_api::make_object<toslib_api::config>(config.as_slice().str(), "", false, true),
    toslib_api::make_object<toslib_api::keyStoreTypeInMemory>()))});
  auto receive = [&](td::uint64 wanted) {
    auto limit = td::Timestamp::in(20);
    while (!limit.is_in_past()) {
      auto r = client.receive(0.1);
      if (!r.object) continue;
      td::write_file(out + "/public-" + std::to_string(r.id) + ".txt", to_string(r.object)).ensure();
      if (r.id == wanted) return r;
    }
    std::abort();
  };
  auto init = receive(1); if (init.object->get_id() == toslib_api::error::ID) return 3;
  std::cout << "Q01_PUBLIC_READY" << std::endl;
  td::uint64 id; std::string nonce;
  while (std::cin >> id >> nonce) {
  if (id < 2) return 2;
  std::mutex mutex; std::condition_variable cv; bool ready = false;
  td::Result<QueryTraceContext> armed = td::Status::Error("not armed");
  client.test_arm(id, nonce, td::Promise<QueryTraceContext>([&](td::Result<QueryTraceContext> r) {
    std::lock_guard<std::mutex> guard(mutex); armed = std::move(r); ready = true; cv.notify_one();
  }));
  { std::unique_lock<std::mutex> lock(mutex); if (!cv.wait_for(lock, std::chrono::seconds(5), [&] { return ready; })) std::abort(); }
  if (armed.is_error()) return 4;
  auto context = armed.move_as_ok();
  std::cout << "Q01_PUBLIC_ARM id=" << context.public_request_id << " generation="
            << context.transport_generation << " token=" << context.arm_token << " nonce=" << nonce << std::endl;
  client.send({id, toslib_api::make_object<toslib_api::blocks_getMasterchainInfo>(), context});
  auto response = receive(id);
  // Error retained, not called application success. Wrapper checks expected route.
  if (response.object->get_id() != toslib_api::error::ID &&
      response.object->get_id() != toslib_api::blocks_masterchainInfo::ID) return 6;
  std::cout << to_string(response.object) << std::endl;
  std::cout << "Q01_PUBLIC_TERMINAL id=" << id << " nonce=" << nonce << " error="
            << (response.object->get_id() == toslib_api::error::ID) << std::endl;
  }
  return 0;
}
