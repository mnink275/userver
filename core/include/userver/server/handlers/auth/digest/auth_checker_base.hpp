#pragma once

/// @file userver/server/handlers/auth/digest/auth_checker_base.hpp
/// @brief @copybrief server::handlers::auth::digest::AuthCheckerBase

#include <userver/server/handlers/auth/auth_checker_base.hpp>

#include <chrono>
#include <functional>
#include <optional>
#include <random>
#include <string_view>

#include <userver/crypto/hash.hpp>
#include <userver/http/predefined_header.hpp>
#include <userver/rcu/rcu_map.hpp>
#include <userver/server/handlers/auth/digest/auth_checker_settings.hpp>
#include <userver/server/handlers/auth/digest/directives_parser.hpp>
#include <userver/server/http/http_request.hpp>
#include <userver/server/http/http_response.hpp>
#include <userver/server/http/http_status.hpp>
#include <userver/server/request/request_context.hpp>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth::digest {

using TimePoint = std::chrono::time_point<std::chrono::system_clock>;

/// Used for data hashing and "nonce" generating.
class Hasher final {
 public:
  /// Constructor from the hash algorithm name from "crypto" namespace.
  /// Subsequently, all methods of the class will use this algorithm for
  /// hashing.
  Hasher(std::string_view algorithm);

  /// Returns "nonce" directive value in hexadecimal format.
  std::string GenerateNonce(std::string_view etag) const;

  /// Returns data hashed according to the specified in constructor
  /// algorithm.
  std::string GetHash(std::string_view data) const;

 private:
  using HashAlgorithm = std::function<std::string(
      std::string_view, crypto::hash::OutputEncoding)>;
  HashAlgorithm hash_algorithm_;
};

/// Contains information about the user.
struct UserData final {
  using HA1 = utils::NonLoggable<class HA1Tag, std::string>;

  UserData(HA1 ha1, std::string nonce, TimePoint timestamp,
           std::int64_t nonce_count);

  HA1 ha1;
  std::string nonce;
  TimePoint timestamp;
  std::int64_t nonce_count{};
};

/// @ingroup userver_base_classes
///
/// @brief Base class for digest authentication checkers. Implements a
/// digest-authentication logic.
class AuthCheckerBase : public auth::AuthCheckerBase {
 public:
  /// Assepts digest-authentication settings from
  /// @ref server::handlers::auth::digest::AuthCheckerSettingsComponent and
  /// "realm" from handler config in static_config.yaml.
  AuthCheckerBase(const AuthCheckerSettings& digest_settings,
                  std::string&& realm);

  AuthCheckerBase(const AuthCheckerBase&) = delete;
  AuthCheckerBase(AuthCheckerBase&&) = delete;
  AuthCheckerBase& operator=(const AuthCheckerBase&) = delete;
  AuthCheckerBase& operator=(AuthCheckerBase&&) = delete;

  ~AuthCheckerBase() override;

  /// The main checking function that is called for each request.
  [[nodiscard]] AuthCheckResult CheckAuth(
      const http::HttpRequest& request,
      request::RequestContext& request_context) const final;

  /// Returns "true" if the checker is allowed to write authentication
  /// information about the user to the RequestContext.
  [[nodiscard]] bool SupportsUserAuth() const noexcept override { return true; }

  /// The implementation should return std::nullopt if the user is not
  /// registered. If the user is registered, but he is not in storage, the
  /// implementation can create him with arbitrary data.
  ///
  /// Note that if the "userhash" field is "true", "username" is hashed by the
  /// client according to the rule:
  /// username = H( unq(username) ":" unq(realm) )
  /// See: https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.4
  virtual std::optional<UserData> FetchUserData(
      const std::string& username) const = 0;

  /// Sets user authentication data to storage.
  virtual void SetUserData(const std::string& username,
                           const std::string& nonce, std::int64_t nonce_count,
                           TimePoint nonce_creation_time) const = 0;

  /// Pushes "nonce" not tied to username to "Nonce Pool".
  virtual void PushUnnamedNonce(std::string nonce) const = 0;

  /// Returns "nonce" creation time from "Nonce Pool" if exists.
  virtual std::optional<TimePoint> GetUnnamedNonceCreationTime(
      const std::string& nonce) const = 0;

  /// @cond
  enum class ValidateResult { kOk, kWrongUserData, kDuplicateRequest };
  ValidateResult ValidateUserData(const ContextFromClient& client_context,
                                  const UserData& user_data) const;
  /// @endcond
 private:
  std::string CalculateDigest(std::string_view ha1, std::string_view ha2,
                              const ContextFromClient& client_context) const;

  std::string ConstructAuthInfoHeaderValue(std::string_view ha1, std::string_view ha2, const ContextFromClient& client_context,
                                      std::string_view etag) const;

  std::string ConstructResponseHeaderValue(std::string_view nonce,
                                          bool stale) const;

  AuthCheckResult StartNewAuthSession(std::string username, std::string&& nonce,
                                      bool stale,
                                      http::HttpResponse& response) const;

  std::string GetHA1(const UserData::HA1& ha1_non_loggable,
                     const ContextFromClient& client_context) const;

  std::string GetHA2(std::string_view http_method, std::string_view uri) const;

  const std::string realm_;

  const std::string& domain_;
  const std::string& qop_;
  const std::chrono::milliseconds nonce_ttl_;
  const std::string& charset_;
  const std::string& algorithm_;
  const bool is_session_;
  const bool is_proxy_;
  const bool userhash_;

  const http::HttpStatus unauthorized_status_;

  using PredefinedHeader = USERVER_NAMESPACE::http::headers::PredefinedHeader;
  const PredefinedHeader& authenticate_header_;
  const PredefinedHeader& authorization_header_;
  const PredefinedHeader& authenticate_info_header_;

  const Hasher digest_hasher_;
};

}  // namespace server::handlers::auth::digest

USERVER_NAMESPACE_END
