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
  /// A string indicating an algorithm used to produce the digest.
  std::string algorithm;
  /// Space-separated list of URIs that define the protection space
  std::vector<std::string> domain;
  /// Array of one or more tokens indicating the "quality of protection" values
  /// supported by the server.
  std::vector<std::string> qops;
  /// Used to indicate that the authentication server is a proxy. Affects the
  /// headers used for authentication. See:
  /// https://datatracker.ietf.org/doc/html/rfc7616#section-3.8
  bool is_proxy{false};
  /// Shows whether algorithm Session variant is enabled
  bool is_session{false};
  /// TTL for nonces.
  std::chrono::milliseconds nonce_ttl{0};
  /// Used to indicate the encoding scheme server supports.
  std::optional<std::string> charset;
};

}  // namespace server::handlers::auth::digest

USERVER_NAMESPACE_END
