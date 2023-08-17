#pragma once

#include <userver/formats/json/value.hpp>
#include <userver/formats/json/value_builder.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth {

// www-authenticate response header from server
// realm, nonce are mandatory
// domain, opaque, stale, algorithm, qop, auth-param are optional
struct DigestContextFromServer {
  std::string realm;
  std::string nonce;
  std::string algorithm;
  bool stale;
  std::string authparam;
  std::string qop;
  std::string opaque;
};

// authorizion request header from client
// username, realm, nonce, digest-uri, response are mandatory
// algorithm, cnonce, opaque, qop, nc, auth-param are optional
struct DigestContextFromClient {
  std::string username;
  std::string realm;
  std::string nonce;
  std::string uri;  // digest-uri
  std::string response;
  std::string algorithm;
  std::string cnonce;
  std::string opaque;
  std::string qop;        // message-qop
  std::string nc;       // nonce-count
  std::string authparam;  // auth-param
};

DigestContextFromClient Parse(
    const userver::formats::json::Value& json,
    userver::formats::parse::To<DigestContextFromClient>);

}  // namespace server::handlers::auth

USERVER_NAMESPACE_END