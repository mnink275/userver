#include <exception>
#include <string_view>
#include <vector>

#include <userver/utest/utest.hpp>

#include <userver/server/handlers/auth/auth_digest_checker_standalone.hpp>
#include <userver/server/handlers/auth/auth_params_parsing.hpp>
#include <userver/server/handlers/auth/digest_checker_base.hpp>
#include <userver/server/handlers/auth/digest_context.hpp>
#include <userver/utils/datetime.hpp>
#include <userver/utils/mock_now.hpp>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth::test {

using HA1 = utils::NonLoggable<class HA1Tag, std::string>;
using NonceCache = cache::ExpirableLruCache<std::string, TimePoint>;
using ValidateResult = DigestCheckerBase::ValidateResult;

constexpr std::size_t kWays = 4;
constexpr std::size_t kWaySize = 25000;

// hash of `username:realm:password` for testing
// each user is considered registered
const auto kValidHA1 = HA1{"939e7578ed9e3c518a452acee763bce9"};
const std::string kValidNonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
constexpr auto kNonceTTL = std::chrono::milliseconds{1000};

class StandAloneChecker final : public AuthCheckerDigestBaseStandalone {
 public:
  StandAloneChecker(const AuthDigestSettings& digest_settings,
                    std::string&& realm)
      : AuthCheckerDigestBaseStandalone(digest_settings, std::move(realm),
                                        kWays, kWaySize) {}

  std::optional<HA1> GetHA1(std::string_view) const override {
    return kValidHA1;
  }
};

class StandAloneCheckerTest : public ::testing::Test {
 public:
  StandAloneCheckerTest()
      : digest_settings_(AuthDigestSettings{
            "MD5",                             // algorithm
            std::vector<std::string>{"/"},     // domains
            std::vector<std::string>{"auth"},  // qops
            false,                             // is_proxy
            false,                             // is_session
            kNonceTTL                          // nonce_ttl
        }),
        checker_(digest_settings_, "testrealm@host.com"),
        client_context_(DigestContextFromClient{
            "Mufasa",                            // username
            "testrealm@host.com",                // realm
            kValidNonce,                         // nonce
            "/dir/index.html",                   // uri
            "6629fae49393a05397450978507c4ef1",  // response
            "MD5",                               // algorithm
            "0a4f113b",                          // cnonce
            "5ccc069c403ebaf9f0171e9517f40e41",  // opaque
            "auth",                              // qop
            "00000001",                          // nc
            "auth-param"                         // authparam
        }),
        user_data_from_storage_(UserData{
            kValidHA1,                           // HA1
            kValidNonce,                         // nonce
            utils::datetime::Now(),              // nonce_creation_time
            0                                    // nonce_count
        }) {}

  AuthDigestSettings digest_settings_;
  StandAloneChecker checker_;
  DigestContextFromClient client_context_;
  UserData user_data_from_storage_;
};

UTEST_F(StandAloneCheckerTest, NonceTTL) {
  utils::datetime::MockNowSet(utils::datetime::Now());
  checker_.PushUnnamedNonce(kValidNonce);

  utils::datetime::MockSleep(kNonceTTL - std::chrono::milliseconds(100));
  EXPECT_EQ(checker_.ValidateUserData(client_context_, user_data_from_storage_),
            ValidateResult::kOk);

  utils::datetime::MockSleep(kNonceTTL + std::chrono::milliseconds(100));
  EXPECT_EQ(checker_.ValidateUserData(client_context_, user_data_from_storage_),
            ValidateResult::kWrongUserData);
}

UTEST_F(StandAloneCheckerTest, NonceCount) {
  checker_.PushUnnamedNonce(kValidNonce);

  EXPECT_EQ(checker_.ValidateUserData(client_context_, user_data_from_storage_),
            ValidateResult::kOk);

  user_data_from_storage_.nonce_count = 1;
  EXPECT_EQ(checker_.ValidateUserData(client_context_, user_data_from_storage_),
            ValidateResult::kDuplicateRequest);

  client_context_.nc = "00000002";
  EXPECT_EQ(checker_.ValidateUserData(client_context_, user_data_from_storage_),
            ValidateResult::kOk);
}

UTEST_F(StandAloneCheckerTest, InvalidNonce) {
  std::string wrong_nonce = "3ab3a5e23c925428b089e11e3f3a8369";
  user_data_from_storage_.nonce = wrong_nonce;
  EXPECT_EQ(checker_.ValidateUserData(client_context_, user_data_from_storage_),
            ValidateResult::kWrongUserData);

  user_data_from_storage_.nonce = kValidNonce;
  EXPECT_EQ(checker_.ValidateUserData(client_context_, user_data_from_storage_),
            ValidateResult::kOk);
}

UTEST_F(StandAloneCheckerTest, NonceCountConvertingThrow) {
  client_context_.nc = "not-a-hex-number";
  EXPECT_THROW(checker_.ValidateUserData(client_context_, user_data_from_storage_),
               std::runtime_error);
}

}  // namespace server::handlers::auth::test

USERVER_NAMESPACE_END
