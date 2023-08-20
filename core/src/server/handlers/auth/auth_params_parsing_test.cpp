#include <userver/server/handlers/auth/auth_params_parsing.hpp>
#include <userver/utest/utest.hpp>

#include <gtest/gtest.h>

#include <exception>
#include <string_view>

USERVER_NAMESPACE_BEGIN

// Correst Parsing and Directory Tests
TEST(AuthenticationInfoCorrectParsing, WithoutOptional) {
    std::string_view correctInfo = R"(username="Mufasa",
        realm="testrealm@host.com",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        response="6629fae49393a05397450978507c4ef1"
    )";
    userver::server::handlers::auth::DigestParsing parser;
    EXPECT_NO_THROW(parser.ParseAuthInfo(correctInfo));
    auto auth_context = parser.GetClientContext();

    EXPECT_EQ(auth_context.username, "Mufasa");
    EXPECT_EQ(auth_context.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
    EXPECT_EQ(auth_context.realm, "testrealm@host.com");
    EXPECT_EQ(auth_context.uri, "/dir/index.html");
    EXPECT_EQ(auth_context.response, "6629fae49393a05397450978507c4ef1");
}

TEST(AuthenticationInfo, WithOptionalPartial) {
    std::string_view correctInfo = R"(username="Mufasa",
        realm="testrealm@host.com",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        response="6629fae49393a05397450978507c4ef1",
        algorithm="MD5"
    )";
    userver::server::handlers::auth::DigestParsing parser;
    EXPECT_NO_THROW(parser.ParseAuthInfo(correctInfo));

    auto auth_context = parser.GetClientContext();

    EXPECT_EQ(auth_context.username, "Mufasa");

    EXPECT_EQ(auth_context.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");

    EXPECT_EQ(auth_context.realm, "testrealm@host.com");

    EXPECT_EQ(auth_context.uri, "/dir/index.html");

    EXPECT_EQ(auth_context.response, "6629fae49393a05397450978507c4ef1");

    EXPECT_EQ(auth_context.algorithm, "MD5");
}

TEST(AuthenticationInfo, WithOptionalAll) {

    std::string_view correctInfo = R"(username="Mufasa",
        realm="testrealm@host.com",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        algorithm="MD5",
        qop=auth,
        nc=00000001,
        cnonce="0a4f113b",
        response="6629fae49393a05397450978507c4ef1",
        auth-param="fictional parameter"
    )";
    userver::server::handlers::auth::DigestParsing parser;
    EXPECT_NO_THROW(parser.ParseAuthInfo(correctInfo));

    auto auth_context = parser.GetClientContext();
    
    EXPECT_EQ(auth_context.username, "Mufasa");

    EXPECT_EQ(auth_context.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");

    EXPECT_EQ(auth_context.realm, "testrealm@host.com");

    EXPECT_EQ(auth_context.uri, "/dir/index.html");

    EXPECT_EQ(auth_context.response, "6629fae49393a05397450978507c4ef1");

    EXPECT_TRUE(!auth_context.algorithm.empty());
    EXPECT_EQ(auth_context.algorithm, "MD5");

    EXPECT_TRUE(!auth_context.nc.empty());
    EXPECT_EQ(auth_context.nc, "00000001");

    EXPECT_TRUE(!auth_context.cnonce.empty());
    EXPECT_EQ(auth_context.cnonce, "0a4f113b");

    EXPECT_TRUE(!auth_context.qop.empty());
    EXPECT_EQ(auth_context.qop, "auth");

    EXPECT_TRUE(!auth_context.authparam.empty());
    EXPECT_EQ(auth_context.authparam, "fictional parameter"); 
}

TEST(AuthenticationInfo, MandatoryDirectivesMissing) {

    std::string_view correctInfo = R"(algorithm="MD5",
        qop=auth,
        nc=00000001,
        cnonce="0a4f113b",
        response="6629fae49393a05397450978507c4ef1",
        auth-param="fictional parameter"
    )";
    userver::server::handlers::auth::DigestParsing parser;
    EXPECT_NO_THROW(parser.ParseAuthInfo(correctInfo));
    EXPECT_THROW(parser.GetClientContext(), std::runtime_error);
}

TEST(AuthenticationInfo, MandatoryDirectiveMissing) {

    std::string_view correctInfo = R"(username="Mufasa",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        algorithm="MD5",
        qop=auth,
        nc=00000001,
        cnonce="0a4f113b",
        response="6629fae49393a05397450978507c4ef1",
        auth-param="fictional parameter"
    )";
    userver::server::handlers::auth::DigestParsing parser;
    EXPECT_NO_THROW(parser.ParseAuthInfo(correctInfo));
    EXPECT_THROW(parser.GetClientContext(), std::runtime_error);
}

TEST(AuthenticationInfo, MandatoryDirectiveMissingExtended) {

    std::string_view correctInfo = R"(username="Mufasa",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        algorithm="MD5",
        qop=auth,
        nc=00000001,
        cnonce="0a4f113b",
        response="6629fae49393a05397450978507c4ef1",
        auth-param="fictional parameter"
    )";
    userver::server::handlers::auth::DigestParsing parser;
    EXPECT_NO_THROW(parser.ParseAuthInfo(correctInfo));
    EXPECT_THROW(parser.GetClientContext(), std::runtime_error);
}

// Value Parsing Errors
TEST(AuthenticationInfo, MandatoryDirectiveNoValue) {

    std::string_view correctInfo = R"(username=,
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        algorithm="MD5",
        response="6629fae49393a05397450978507c4ef1",
    )";
    userver::server::handlers::auth::DigestParsing parser;
    EXPECT_THROW(parser.ParseAuthInfo(correctInfo), std::runtime_error);
}

TEST(AuthenticationInfo, OptionalDirectiveNoValue) {

    std::string_view correctInfo = R"(username="Mufasa",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        algorithm="MD5",
        response="6629fae49393a05397450978507c4ef1",
        qop=,
    )";
    userver::server::handlers::auth::DigestParsing parser;
    EXPECT_THROW(parser.ParseAuthInfo(correctInfo), std::runtime_error);
}

// Directory Parsing Errors
TEST(AuthenticationInfo, InvalidMandatoryDirectory) {

    std::string_view correctInfo = R"(usergame="Mubasa",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        algorithm="MD5",
        response="6629fae49393a05397450978507c4ef1"
    )";
    userver::server::handlers::auth::DigestParsing parser;
    EXPECT_NO_THROW(parser.ParseAuthInfo(correctInfo));
    EXPECT_THROW(parser.GetClientContext(), std::runtime_error);
}

USERVER_NAMESPACE_END