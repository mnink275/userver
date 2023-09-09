#include <gtest/gtest.h>
#include <userver/server/handlers/auth/auth_params_parsing.hpp>
#include <userver/server/handlers/auth/digest_directives.hpp>
#include <userver/server/handlers/auth/exception.hpp>
#include <userver/utest/utest.hpp>

#include <exception>
#include <string_view>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth::test {

TEST(DirectivesParser, MandatoryDirectives) {
  std::string_view header_value = R"(
        username="Mufasa",
        realm="testrealm@host.com",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        response="6629fae49393a05397450978507c4ef1"
    )";
  DigestParser parser;
  DigestContextFromClient auth_context;
  EXPECT_NO_THROW(auth_context = parser.ParseAuthInfo(header_value));

  EXPECT_EQ(auth_context.username, "Mufasa");
  EXPECT_EQ(auth_context.realm, "testrealm@host.com");
  EXPECT_EQ(auth_context.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
  EXPECT_EQ(auth_context.uri, "/dir/index.html");
  EXPECT_EQ(auth_context.response, "6629fae49393a05397450978507c4ef1");
}

TEST(DirectivesParser, WithPartialOptionalDirectives) {
  std::string_view header_value = R"(
        username="Mufasa",
        realm="testrealm@host.com",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        response="6629fae49393a05397450978507c4ef1",
        algorithm=MD5
    )";
  DigestParser parser;
  DigestContextFromClient auth_context;
  EXPECT_NO_THROW(auth_context = parser.ParseAuthInfo(header_value));

  EXPECT_EQ(auth_context.username, "Mufasa");
  EXPECT_EQ(auth_context.realm, "testrealm@host.com");
  EXPECT_EQ(auth_context.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
  EXPECT_EQ(auth_context.uri, "/dir/index.html");
  EXPECT_EQ(auth_context.response, "6629fae49393a05397450978507c4ef1");
  EXPECT_EQ(auth_context.algorithm, "MD5");
  EXPECT_TRUE(auth_context.opaque.empty());
  EXPECT_TRUE(auth_context.nc.empty());
  EXPECT_TRUE(auth_context.cnonce.empty());
  EXPECT_TRUE(auth_context.qop.empty());
  EXPECT_TRUE(auth_context.authparam.empty());
}

TEST(DirectivesParser, WithAllOptionalDirectives) {
  std::string_view header_value = R"(
        username="Mufasa",
        realm="testrealm@host.com",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        algorithm=MD5,
        qop=auth,
        nc=00000001,
        cnonce="0a4f113b",
        response="6629fae49393a05397450978507c4ef1",
        opaque="5ccc069c403ebaf9f0171e9517f40e41",
        auth-param="fictional parameter"
    )";
  DigestParser parser;
  DigestContextFromClient auth_context;
  EXPECT_NO_THROW(auth_context = parser.ParseAuthInfo(header_value));

  EXPECT_EQ(auth_context.username, "Mufasa");
  EXPECT_EQ(auth_context.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
  EXPECT_EQ(auth_context.realm, "testrealm@host.com");
  EXPECT_EQ(auth_context.uri, "/dir/index.html");
  EXPECT_EQ(auth_context.response, "6629fae49393a05397450978507c4ef1");
  EXPECT_EQ(auth_context.algorithm, "MD5");
  EXPECT_EQ(auth_context.opaque, "5ccc069c403ebaf9f0171e9517f40e41");
  EXPECT_EQ(auth_context.nc, "00000001");
  EXPECT_EQ(auth_context.cnonce, "0a4f113b");
  EXPECT_EQ(auth_context.qop, "auth");
  EXPECT_EQ(auth_context.authparam, "fictional parameter");
}

TEST(DirectivesParser, MandatoryRealmDirectiveMissing) {
  std::string_view header_value = R"(
        username="Mufasa",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        algorithm=MD5,
        qop=auth,
        nc=00000001,
        cnonce="0a4f113b",
        response="6629fae49393a05397450978507c4ef1",
        opaque="5ccc069c403ebaf9f0171e9517f40e41",
        auth-param="fictional parameter"
    )";
  DigestParser parser;
  try {
    parser.ParseAuthInfo(header_value);
  } catch (const MissingDirectivesException& ex) {
    const auto& missing_directives = ex.GetMissingDirectives();
    EXPECT_EQ(missing_directives.size(), 1);
    
    auto it = std::find(missing_directives.begin(), missing_directives.end(), directives::kRealm);
    EXPECT_TRUE(it != missing_directives.end());
  }
}

TEST(DirectivesParser, MultipleMandatoryDirectivesMissing) {
  std::string_view header_value = R"(
        algorithm=MD5,
        qop=auth,
        nc=00000001,
        cnonce="0a4f113b",
        response="6629fae49393a05397450978507c4ef1",
        opaque="5ccc069c403ebaf9f0171e9517f40e41",
        auth-param="fictional parameter"
    )";
  DigestParser parser;
  try {
    parser.ParseAuthInfo(header_value);
  } catch (const MissingDirectivesException& ex) {
    const auto& missing_directives = ex.GetMissingDirectives();
    EXPECT_EQ(missing_directives.size(), 4);
    
    auto it = std::find(missing_directives.begin(), missing_directives.end(), directives::kRealm);
    EXPECT_TRUE(it != missing_directives.end());
    
    it = std::find(missing_directives.begin(), missing_directives.end(), directives::kRealm);
    EXPECT_TRUE(it != missing_directives.end());

    it = std::find(missing_directives.begin(), missing_directives.end(), directives::kNonce);
    EXPECT_TRUE(it != missing_directives.end());

    it = std::find(missing_directives.begin(), missing_directives.end(), directives::kUri);
    EXPECT_TRUE(it != missing_directives.end());
  }
}

TEST(DirectivesParser, InvalidHeader) {
  std::string_view header_value = R"(
        username=="Mufasa",
        realm="testrea=lm@host.com",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        response="6629fae49393a05397450978507c4ef1",
    )";
  DigestParser parser;
  EXPECT_THROW(parser.ParseAuthInfo(header_value),
               ParseException);
}

TEST(DirectivesParser, UnknownDirective) {
  std::string_view header_value = R"(
        username="Mufasa",
        realm="testrealm@host.com",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        response="6629fae49393a05397450978507c4ef1",
        unknown="some-value"
    )";
  DigestParser parser;
  EXPECT_THROW(parser.ParseAuthInfo(header_value),
               ParseException);
}

TEST(DirectivesParser, InvalidMandatoryDirective) {
  std::string_view header_value = R"(
        usergame="Mubasa",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        algorithm=MD5,
        response="6629fae49393a05397450978507c4ef1"
    )";
  DigestParser parser;
  EXPECT_THROW(parser.ParseAuthInfo(header_value),
               Exception);
}

TEST(DirectivesParser, DuplicateDirectives) {
  std::string_view header_value = R"(
        username="Mubasa",
        realm="testrealm@host.com",
        username="Alex",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        algorithm=MD5,
        response="6629fae49393a05397450978507c4ef1"
    )";
  DigestParser parser;
  EXPECT_THROW(parser.ParseAuthInfo(header_value),
               DuplicateDirectiveException);
}

}  // namespace server::handlers::auth::test

USERVER_NAMESPACE_END