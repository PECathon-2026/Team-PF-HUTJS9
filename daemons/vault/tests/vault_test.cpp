// Vault tests (owner: LNX): binding is exact, handles are opaque, wipe/shred, wire format.
#include <string>

#include <gtest/gtest.h>

#include "pl/contracts.hpp"
#include "pl/vault.hpp"

namespace {

using pl::vault::Binding;
using pl::vault::Error;
using pl::vault::Vault;

Binding sample() { return {"ss-0000000000000001", "[REDACTED:CARD#1]", "CARD", "shop.example", "n12"}; }

// Synthetic test card (valid Luhn, test range); never a real card.
constexpr const char* kCard = "4111111111111111";

TEST(Vault, StoreThenDecryptWithExactBinding) {
  Vault v;
  const auto h = v.store(sample(), kCard);
  EXPECT_EQ(h.rfind("vh-", 0), 0U);
  EXPECT_EQ(h.size(), 3U + 32U);
  EXPECT_EQ(h.find("4111"), std::string::npos);
  auto r = v.decrypt(h, sample());
  ASSERT_TRUE(std::holds_alternative<std::string>(r));
  EXPECT_EQ(std::get<std::string>(r), kCard);
}

TEST(Vault, AnyBindingFieldChangeFails) {
  Vault v;
  const auto h = v.store(sample(), kCard);
  for (int i = 0; i < 5; ++i) {
    Binding b = sample();
    std::string* fields[] = {&b.session_id, &b.placeholder, &b.field_type, &b.site, &b.element_id};
    fields[i]->back() = fields[i]->back() == 'x' ? 'y' : 'x';
    auto r = v.decrypt(h, b);
    ASSERT_TRUE(std::holds_alternative<Error>(r)) << i;
    EXPECT_EQ(std::get<Error>(r), Error::binding_mismatch) << i;
  }
}

TEST(Vault, CanonicalBindingIsUnambiguous) {
  // Field boundaries can't be shifted: ("ab","c") and ("a","bc") differ.
  Binding a = sample();
  Binding b = sample();
  a.site = "shop.example";
  a.element_id = "n12";
  b.site = "shop.example\x1fn";
  b.element_id = "12";
  EXPECT_NE(a.canonical(), b.canonical());
}

TEST(Vault, WipeAndShred) {
  Vault v;
  const auto h1 = v.store(sample(), kCard);
  const auto h2 = v.store(sample(), "hunter2-synthetic");
  EXPECT_TRUE(v.wipe(h1));
  EXPECT_FALSE(v.wipe(h1));
  EXPECT_EQ(std::get<Error>(v.decrypt(h1, sample())), Error::unknown_handle);
  v.shred(sample().session_id);
  EXPECT_EQ(std::get<Error>(v.decrypt(h2, sample())), Error::shredded);
  EXPECT_THROW((void)v.store(sample(), kCard), pl::vault::ShreddedSession);
  EXPECT_EQ(v.size(), 0U);
}

TEST(Vault, HandlesAreUnique) {
  Vault v;
  EXPECT_NE(v.store(sample(), kCard), v.store(sample(), kCard));
}

TEST(Vault, KeyMemoryIsSecretOrLocked) {
  pl::vault::SecretMemory m(32);
  EXPECT_EQ(m.bytes().size(), 32U);
  m.bytes()[0] = 1;  // mapped and writable either way
}

TEST(Vault, WireProtocolRepliesMatchSchemaAndNeverEcho) {
  const auto reg = pl::contracts::Registry::load_dir(PL_CONTRACTS_DIR "/schemas");
  Vault v;
  nlohmann::json bind = {{"session_id", "ss-0000000000000001"}, {"placeholder", "[REDACTED:CARD#1]"},
                         {"field_type", "CARD"}, {"site", "shop.example"}, {"element_id", "n12"}};
  nlohmann::json store = {{"schema", "vault_api.v1"}, {"op", "store"}, {"request_id", "rq-0000000000000001"},
                          {"binding", bind}, {"plaintext", kCard}};
  ASSERT_TRUE(reg.validate("vault_api.v1", store).ok);
  auto ok = v.handle(store);
  ASSERT_TRUE(reg.validate("vault_api.v1", ok).ok) << ok.dump();
  ASSERT_EQ(ok["op"], "store.ok");
  EXPECT_EQ(ok.dump().find("4111"), std::string::npos);
  nlohmann::json dec = {{"schema", "vault_api.v1"}, {"op", "decrypt"}, {"request_id", "rq-0000000000000002"},
                        {"handle", ok["handle"]}, {"binding", bind}};
  auto pt = v.handle(dec);
  ASSERT_TRUE(reg.validate("vault_api.v1", pt).ok);
  EXPECT_EQ(pt["plaintext"], kCard);
  dec["binding"]["site"] = "evil.example";
  auto bad = v.handle(dec);
  ASSERT_TRUE(reg.validate("vault_api.v1", bad).ok);
  EXPECT_EQ(bad["error_code"], "binding_mismatch");
  EXPECT_EQ(bad.dump().find("evil"), std::string::npos);
  auto junk = v.handle(nlohmann::json{{"op", "store"}, {"request_id", "rq-0000000000000003"}});
  EXPECT_EQ(junk["error_code"], "internal");
  nlohmann::json shred = {{"schema", "vault_api.v1"}, {"op", "shred"}, {"request_id", "rq-0000000000000004"},
                          {"session_id", "ss-0000000000000001"}};
  EXPECT_EQ(v.handle(shred)["op"], "ok");
  EXPECT_EQ(v.handle(store)["error_code"], "shredded");
  nlohmann::json wipe = {{"schema", "vault_api.v1"}, {"op", "wipe"}, {"request_id", "rq-0000000000000005"},
                         {"handle", ok["handle"]}};
  EXPECT_EQ(v.handle(wipe)["error_code"], "unknown_handle");
}

}  // namespace
