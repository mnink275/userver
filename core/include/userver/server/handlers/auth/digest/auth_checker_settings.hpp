#pragma once

/// @file userver/server/handlers/auth/digest/digest_checker_settings.hpp
/// @brief @copybrief server::handlers::auth::digest::AuthCheckerSettings

#include <chrono>
#include <optional>
#include <string>
#include <vector>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth::digest {

/// @brief The structure that the
/// `server::handlers::auth::digest::AuthCheckerSettingsComponent`
/// uses to store settings received from the `static_config.yaml` for the
/// digest-authentication checkers derived from
/// `server::handlers::auth::digest::AuthCheckerBase`. You can read more about
/// the fields here: https://datatracker.ietf.org/doc/html/rfc7616#section-3.3
struct AuthCheckerSettings {
  /// Space-separated list of URIs that define the protection space.
  std::string domain;
  /// Space-separated list of tokens indicating the "quality of protection"
  /// values supported by the server.
  std::string qop;
  /// TTL for nonces.
  std::chrono::milliseconds nonce_ttl{0};
  /// Used to indicate the encoding scheme server supports.
  std::string charset;
  /// A string indicating an algorithm used to produce the digest.
  std::string algorithm;
  /// Used to indicate that the authentication server is a proxy. Affects the
  /// headers used for authentication. See:
  /// https://datatracker.ietf.org/doc/html/rfc7616#section-3.8
  bool is_proxy{false};
  /// Shows whether algorithm Session variant is enabled.
  bool is_session{false};
  /// Used to indicate that server supports username hashing.
  bool userhash{false};
};

}  // namespace server::handlers::auth::digest

USERVER_NAMESPACE_END
