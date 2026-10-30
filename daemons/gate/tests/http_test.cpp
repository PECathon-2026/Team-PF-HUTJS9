// HTTP helper tests (owner: LNX).
#include <gtest/gtest.h>

#include "pl/gate/http.hpp"

namespace {

TEST(GateHttp, ParsesConnectAndAbsoluteForm) {
  auto r = pl::gate::parse_request_head("CONNECT shop.example:443 HTTP/1.1\r\nHost: shop.example:443\r\n\r\nxyz");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->method, "CONNECT");
  EXPECT_EQ(r->target, "shop.example:443");
  EXPECT_EQ(r->headers["host"], "shop.example:443");
  EXPECT_EQ(r->rest, "xyz");
  EXPECT_FALSE(pl::gate::parse_request_head("GET / HTTP/2\r\n\r\n"));
  EXPECT_FALSE(pl::gate::parse_request_head("GET / HTTP/1.1\r\n"));
}

TEST(GateHttp, SplitHostPort) {
  auto hp = pl::gate::split_host_port("Shop.Example:8080", 80);
  ASSERT_TRUE(hp);
  EXPECT_EQ(hp->first, "shop.example");
  EXPECT_EQ(hp->second, 8080);
  EXPECT_EQ(pl::gate::split_host_port("sites", 80)->second, 80);
  EXPECT_FALSE(pl::gate::split_host_port("a:0", 80));
  EXPECT_FALSE(pl::gate::split_host_port("a:99999", 80));
  EXPECT_FALSE(pl::gate::split_host_port("evil host:80", 80));
  EXPECT_FALSE(pl::gate::split_host_port(":80", 80));
}

}  // namespace
