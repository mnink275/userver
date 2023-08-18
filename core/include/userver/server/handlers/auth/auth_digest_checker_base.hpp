#pragma once

#include "auth_checker_base.hpp"

#include <chrono>
#include <functional>
#include <random>
#include <string_view>

#include <userver/crypto/hash.hpp>
#include <userver/rcu/rcu_map.hpp>
#include <userver/server/handlers/auth/auth_digest_settings.hpp>
#include <userver/server/handlers/auth/auth_params_parsing.hpp>
#include <userver/server/http/http_request.hpp>
#include <userver/server/http/http_response.hpp>
#include <userver/server/http/http_status.hpp>
#include <userver/server/request/request_context.hpp>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth {

using Nonce = std::string;
using Username = std::string;
using NonceCount = std::uint32_t;

using QopsString = std::string;
using Qops = std::vector<std::string>;
using Realm = std::string;
using Domains = std::vector<std::string>;
using DomainsString = std::string;
using Algorithm = std::string;

class DigestHasher {
 public:
  DigestHasher(const Algorithm& algorithm);
  std::string Opaque() const;
  std::string Nonce() const;
  std::string GetHash(std::string_view data) const;

 private:
  using HashAlgorithm = std::function<std::string(
      std::string_view, crypto::hash::OutputEncoding)>;
  HashAlgorithm hash_algorithm_;
};

struct ClientData {
  using TimePoint = std::chrono::time_point<std::chrono::system_clock>;
  
  ClientData() = default;
  ClientData(const std::string& nonce, const std::string& opaque, TimePoint timestamp)
      : nonce(nonce), opaque(opaque), timestamp(timestamp) {}

  std::string nonce;
  std::string opaque;
  TimePoint timestamp;
};

class AuthCheckerDigestBase : public server::handlers::auth::AuthCheckerBase {
 public:
  using AuthCheckResult = server::handlers::auth::AuthCheckResult;

  AuthCheckerDigestBase(const AuthDigestSettings& digest_settings, Realm realm);

  [[nodiscard]] AuthCheckResult CheckAuth(
      const server::http::HttpRequest& request,
      server::request::RequestContext& request_context) const final;

  [[nodiscard]] bool SupportsUserAuth() const noexcept override { return true; }

  using HA1 = utils::NonLoggable<class HA1Tag, std::string>;
  virtual std::optional<HA1> GetHA1(const std::string& username) const = 0;

 private:
  std::string ConstructResponseDirectives(std::string_view nonce,
                                          std::string_view opaque,
                                          bool stale) const;
  std::string ConstructAuthInfoHeader(
    std::string_view ha1, const DigestContextFromClient& client_context) const;
  AuthCheckResult StartNewAuthSession(
      const std::string& username, const std::string& nonce_from_client,
      const std::string& opaque_from_client, bool stale,
      server::http::HttpResponse& response) const;
  bool IsNonceExpired(const std::string& username,
                      std::string_view nonce_from_client) const;
  // TODO: protect the values with std::atomic
  mutable rcu::RcuMap<Nonce, NonceCount> nonce_counts_;
  mutable rcu::RcuMap<Username, ClientData> client_data_;

  const Qops& qops_;
  const QopsString qops_str_;
  const Realm realm_;
  const DomainsString domains_str_;
  const Algorithm& algorithm_;
  const bool is_session_;
  const bool is_proxy_;
  const std::chrono::milliseconds nonce_ttl_;

  const DigestHasher digest_hasher_;

  const std::string authenticate_header_;
  const std::string authorization_header_;
  const userver::server::http::HttpStatus unauthorized_status_;
};

}  // namespace server::handlers::auth

USERVER_NAMESPACE_END