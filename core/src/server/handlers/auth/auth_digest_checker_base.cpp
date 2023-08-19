#include <userver/server/handlers/auth/auth_digest_checker_base.hpp>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

#include <fmt/core.h>
#include <fmt/format.h>

#include <userver/crypto/algorithm.hpp>
#include <userver/crypto/hash.hpp>
#include <userver/http/common_headers.hpp>
#include <userver/logging/log.hpp>
#include <userver/server/handlers/auth/auth_checker_base.hpp>
#include <userver/server/handlers/auth/digest_algorithms.hpp>
#include <userver/server/handlers/auth/digest_directives.hpp>
#include <userver/server/handlers/exceptions.hpp>
#include <userver/server/handlers/fallback_handlers.hpp>
#include <userver/utils/algo.hpp>
#include <userver/utils/datetime.hpp>
#include "userver/server/http/http_response.hpp"

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth {

constexpr std::string_view kDigestWord = "Digest";

constexpr std::string_view kAuthenticationInfo = "Authentication-Info";
constexpr std::string_view kProxyAuthenticationInfo =
    "Proxy-Authentication-Info";

DigestHasher::DigestHasher(const Algorithm& algorithm) {
  switch (
      kHashAlgToType.TryFindICase(algorithm).value_or(HashAlgTypes::kUnknown)) {
    case HashAlgTypes::kMD5:
      hash_algorithm_ = &crypto::hash::weak::Md5;
      break;
    case HashAlgTypes::kSHA256:
      hash_algorithm_ = &crypto::hash::Sha256;
      break;
    case HashAlgTypes::kSHA512:
      hash_algorithm_ = &crypto::hash::Sha512;
      break;
    default:
      throw std::runtime_error("Unknown hash algorithm");
  }
}

std::string DigestHasher::Opaque() const {
  return GetHash(std::to_string(
      std::chrono::system_clock::now().time_since_epoch().count()));
}
std::string DigestHasher::Nonce() const {
  return GetHash(std::to_string(
      std::chrono::system_clock::now().time_since_epoch().count()));
}
std::string DigestHasher::GetHash(std::string_view data) const {
  return hash_algorithm_(data, crypto::hash::OutputEncoding::kHex);
}

AuthCheckerDigestBase::AuthCheckerDigestBase(
    const AuthDigestSettings& digest_settings, Realm realm)
    : qops_(digest_settings.qops),
      qops_str_(fmt::format("{}", fmt::join(qops_, ","))),
      realm_(std::move(realm)),
      domains_str_(fmt::format("{}", fmt::join(digest_settings.domains, ", "))),
      algorithm_(digest_settings.algorithm),
      is_session_(digest_settings.is_session.value_or(false)),
      is_proxy_(digest_settings.is_proxy.value_or(false)),
      nonce_ttl_(digest_settings.nonce_ttl),
      digest_hasher_(algorithm_),
      authenticate_header_(is_proxy_
                               ? userver::http::headers::kProxyAuthenticate
                               : userver::http::headers::kWWWAuthenticate),
      authorization_header_(is_proxy_
                                ? userver::http::headers::kProxyAuthorization
                                : userver::http::headers::kAuthorization),
      authenticate_info_header_(is_proxy_ ? kProxyAuthenticationInfo
                                          : kAuthenticationInfo),
      unauthorized_status_(
          is_proxy_ ? server::http::HttpStatus::kProxyAuthenticationRequired
                    : server::http::HttpStatus::kUnauthorized) {}

AuthCheckResult AuthCheckerDigestBase::CheckAuth(
    const server::http::HttpRequest& request,
    server::request::RequestContext&) const {
  auto& response = request.GetHttpResponse();

  const auto& auth_value = request.GetHeader(authorization_header_);
  if (auth_value.empty()) {
    response.SetStatus(unauthorized_status_);
    response.SetHeader(
        authenticate_header_,
        ConstructResponseDirectives(digest_hasher_.Nonce(),
                                    digest_hasher_.Opaque(), false));
    return AuthCheckResult{AuthCheckResult::Status::kInvalidToken};
  }

  DigestParsing parser;
  parser.ParseAuthInfo(auth_value.substr(kDigestWord.size() + 1));
  const auto& client_context = parser.GetClientContext();

  auto validate_result = ValidateClientData(client_context);
  switch (validate_result) {
    case ValidateClientDataResult::kWrongUserData:
      return StartNewAuthSession(client_context.username,
                                 digest_hasher_.Nonce(),
                                 digest_hasher_.Opaque(), true, response);
    case ValidateClientDataResult::kUserNotRegistred:
      response.SetStatus(unauthorized_status_);
      return AuthCheckResult{AuthCheckResult::Status::kTokenNotFound};
    case ValidateClientDataResult::kOk:
      break;
  }

  auto digest = CalculateDigest(request, client_context);
  if (!digest.has_value()) {
    return AuthCheckResult{AuthCheckResult::Status::kForbidden};
  }

  if (!crypto::algorithm::AreStringsEqualConstTime(digest.value(),
                                                   client_context.response)) {
    response.SetStatus(unauthorized_status_);
    response.SetHeader(authenticate_header_,
                       ConstructResponseDirectives(
                           client_context.nonce, client_context.opaque, false));
    return AuthCheckResult{AuthCheckResult::Status::kInvalidToken};
  }

  auto info_header_directives = ConstructAuthInfoHeader(client_context);
  response.SetHeader(authenticate_info_header_, info_header_directives);

  return {};
};

ValidateClientDataResult AuthCheckerDigestBase::ValidateClientData(
    const DigestContextFromClient& client_context) const {
  auto user_data_opt = GetUserData(client_context.username);
  if (!user_data_opt.has_value()) {
    return ValidateClientDataResult::kWrongUserData;
  }
  LOG_DEBUG() << "User is known";

  const auto& user_data = user_data_opt.value();

  if (IsNonceExpired(client_context.nonce, user_data)) {
    return ValidateClientDataResult::kWrongUserData;
  }
  LOG_DEBUG() << "NONCE IS OK";

  auto client_nc = std::stoul(client_context.nc, nullptr, 16);
  if (user_data.nonce_count < client_nc) {
    UserData user_data{client_context.nonce, client_context.opaque,
                       utils::datetime::MockNow()};
    SetUserData(client_context.username, std::move(user_data));
  } else {
    return ValidateClientDataResult::kUserNotRegistred;
  }
  LOG_DEBUG() << "NONCE_COUNT IS OK";

  if (!crypto::algorithm::AreStringsEqualConstTime(client_context.opaque,
                                                   user_data.opaque)) {
    return ValidateClientDataResult::kWrongUserData;
  }
  LOG_DEBUG() << "OPAQUE IS OK";

  return ValidateClientDataResult::kOk;
}

std::string AuthCheckerDigestBase::ConstructAuthInfoHeader(
    const DigestContextFromClient& client_context) const {
  auto next_nonce = digest_hasher_.Nonce();

  UserData user_data{next_nonce, client_context.opaque,
                     userver::utils::datetime::MockNow()};
  SetUserData(client_context.username, std::move(user_data));

  return fmt::format("{}=\"{}\"", directives::kNextNonce, next_nonce);
}

AuthCheckResult AuthCheckerDigestBase::StartNewAuthSession(
    const std::string& username, const std::string& nonce_from_client,
    const std::string& opaque_from_client, bool stale,
    server::http::HttpResponse& response) const {
  UserData user_data{nonce_from_client, opaque_from_client,
                     userver::utils::datetime::MockNow()};
  SetUserData(username, std::move(user_data));
  response.SetStatus(unauthorized_status_);
  response.SetHeader(authenticate_header_,
                     ConstructResponseDirectives(nonce_from_client,
                                                 opaque_from_client, stale));

  return AuthCheckResult{AuthCheckResult::Status::kInvalidToken};
}

// clang-format off
std::string AuthCheckerDigestBase::ConstructResponseDirectives(
    std::string_view nonce, std::string_view opaque, bool stale) const {
  return utils::StrCat(
      "Digest ",
      fmt::format("{}=\"{}\", ", directives::kRealm, realm_),
      fmt::format("{}=\"{}\", ", directives::kNonce, nonce),
      fmt::format("{}=\"{}\", ", directives::kStale, stale),
      fmt::format("{}=\"{}\", ", directives::kDomain, domains_str_),
      fmt::format("{}=\"{}\", ", directives::kOpaque, opaque),
      fmt::format("{}=\"{}\", ", directives::kAlgorithm, algorithm_),
      fmt::format("{}=\"{}\"", directives::kQop, qops_str_));
}
// clang-format on

bool AuthCheckerDigestBase::IsNonceExpired(std::string_view nonce_from_client,
                                           const UserData& user_data) const {
  LOG_DEBUG() << "NONCE: " << user_data.nonce;
  LOG_DEBUG() << "NONCE_FROM_CLIENT: " << nonce_from_client;
  if (!crypto::algorithm::AreStringsEqualConstTime(user_data.nonce,
                                                   nonce_from_client)) {
    return true;
  }

  LOG_DEBUG() << "USER NONCE CREATION TIMESTAMP: " << user_data.timestamp;
  LOG_DEBUG() << "USER NONCE CREATION TIMESTAMP: " << userver::utils::datetime::MockNow();
  return user_data.timestamp + nonce_ttl_ < userver::utils::datetime::MockNow();
}

std::optional<std::string> AuthCheckerDigestBase::CalculateDigest(
    const server::http::HttpRequest& request,
    const DigestContextFromClient& client_context) const {
  auto ha1_opt = GetHA1(client_context.username);
  if (!ha1_opt.has_value()) {
    return std::nullopt;
  }

  auto ha1 = ha1_opt.value().GetUnderlying();
  if (is_session_) {
    ha1 = fmt::format("{}:{}:{}", ha1, client_context.nonce,
                      client_context.cnonce);
  }

  auto a2 =
      fmt::format("{}:{}", ToString(request.GetMethod()), client_context.uri);
  if (client_context.qop == "auth-int") {
    a2 += fmt::format(":{}", digest_hasher_.GetHash(request.RequestBody()));
  }
  std::string ha2 = digest_hasher_.GetHash(a2);

  // digest_value = H(HA1:nonce:nc:cnonce:qop:HA2)
  std::string digest_value = fmt::format(
      "{}:{}:{}:{}:{}:{}", ha1, client_context.nonce, client_context.nc,
      client_context.cnonce, client_context.qop, ha2);
  return digest_hasher_.GetHash(digest_value);
}

}  // namespace server::handlers::auth

USERVER_NAMESPACE_END
