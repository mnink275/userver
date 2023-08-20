#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <userver/formats/json/value.hpp>
#include <userver/formats/json/value_builder.hpp>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth {

// WWW-Authenticate response header from server
// realm, nonce are mandatory
// domain, stale, algorithm, qop, auth-param are optional
struct DigestContextFromServer {
  std::string realm;
  std::string nonce;
  std::string algorithm;
  bool stale{false};
  std::string authparam;
  std::string qop;
};

// authorization request header from client
// username, realm, nonce, digest-uri, response are mandatory
// algorithm, cnonce, qop, nc, auth-param are optional
struct DigestContextFromClient {
  std::string username;
  std::string realm;
  std::string nonce;
  std::string uri;  
  std::string response;
  std::string algorithm;
  std::string cnonce;
<<<<<<< HEAD
  std::string qop;        // message-qop
  std::string nc;       // nonce-count
  std::string authparam;  // auth-param
=======
  std::string opaque;
  std::string qop;        
  std::string nc;       
  std::string authparam; 
>>>>>>> parsing
};

DigestContextFromClient Parse(
    std::unordered_map<std::string, std::string> directive_mapping);

}  // namespace server::handlers::auth

USERVER_NAMESPACE_END