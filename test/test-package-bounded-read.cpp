#include "validator/db/package.hpp"
#include "td/utils/Random.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"

namespace {
std::string path() {
  auto p=PSTRING()<<"test-package-bounded-"<<td::Random::fast_uint32()<<".pack";
  td::unlink(p).ignore();
  return p;
}
}
TEST(PackageBoundedRead, refuses_before_payload_allocation_and_preserves_normal_read) {
  auto p=path();
  {
    auto package=tos::Package::open(p,false,true).move_as_ok();
    std::string payload(4096,'x');
    auto offset=package.append("block",payload);
    auto denied=package.read_bounded(offset,4095);
    ASSERT_TRUE(denied.is_error());
    ASSERT_TRUE(denied.error().message().str().find("bounded read allowance")!=std::string::npos);
    auto exact=package.read_bounded(offset,4096);
    ASSERT_TRUE(exact.is_ok());
    ASSERT_EQ(exact.ok().first,std::string("block"));
    ASSERT_EQ(exact.ok().second.size(),static_cast<size_t>(4096));
    auto ordinary=package.read(offset);
    ASSERT_TRUE(ordinary.is_ok());
    ASSERT_EQ(ordinary.ok().second.size(),static_cast<size_t>(4096));
  }
  td::unlink(p).ignore();
}
