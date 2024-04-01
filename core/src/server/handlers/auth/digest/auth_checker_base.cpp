#include <userver/server/handlers/auth/digest/auth_checker_base.hpp>

#include <chrono>
#include <exception>
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
#include <userver/server/handlers/auth/digest/directives.hpp>
#include <userver/server/handlers/auth/digest/exception.hpp>
#include <userver/server/handlers/auth/digest/types.hpp>
#include <userver/server/handlers/exceptions.hpp>
#include <userver/server/handlers/fallback_handlers.hpp>
#include <userver/server/http/http_response.hpp>
#include <userver/utils/algo.hpp>
#include <userver/utils/assert.hpp>
#include <userver/utils/datetime.hpp>
#include <userver/utils/from_string.hpp>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth::digest {

UserData::UserData(HA1 ha1, std::string nonce, TimePoint timestamp,
                   std::int64_t nonce_count)
    : ha1(std::move(ha1)),
      nonce(std::move(nonce)),
      timestamp(timestamp),
      nonce_count(nonce_count) {}

Hasher::Hasher(std::string_view algorithm) {
  auto algorithm_type = kHashAlgorithmsMap.TryFind(algorithm);
  if (!algorithm_type.has_value()) {
    constexpr std::string_view error_msg =
        "The presence of the algorithm should have been checked in "
        "digest::AuthCheckerSettingsComponent";
    UASSERT_MSG(false, error_msg);
    throw std::runtime_error(fmt::format("Algorithm is not supported: {}. {}",
                                         algorithm, error_msg));
  }
  switch (algorithm_type.value()) {
    case HashAlgorithmsTypes::kMD5:
      hash_algorithm_ = &crypto::hash::weak::Md5;
      break;
    case HashAlgorithmsTypes::kSHA256:
      hash_algorithm_ = &crypto::hash::Sha256;
      break;
    case HashAlgorithmsTypes::kSHA512:
      hash_algorithm_ = &crypto::hash::Sha512;
      break;
  }
}

// TODO: Implement the recommended nonce hashing algorithm:
// nonce = hash(timestamp:ETag:server-private-key)
std::string Hasher::GenerateNonce(std::string_view etag) const {
  auto timestamp = std::to_string(
      std::chrono::system_clock::now().time_since_epoch().count());
  if (etag.empty()) return GetHash(timestamp);
  return GetHash(fmt::format("{}:{}", timestamp, etag));
}

std::string Hasher::GetHash(std::string_view data) const {
  return hash_algorithm_(data, crypto::hash::OutputEncoding::kHex);
}

AuthCheckerBase::AuthCheckerBase(const AuthCheckerSettings& digest_settings,
                                 std::string&& realm)
    : realm_(std::move(realm)),
      domain_(digest_settings.domain),
      qop_(digest_settings.qop),
      nonce_ttl_(digest_settings.nonce_ttl),
      charset_(digest_settings.charset),
      algorithm_(digest_settings.algorithm),
      is_session_(digest_settings.is_session),
      is_proxy_(digest_settings.is_proxy),
      userhash_(digest_settings.userhash),
      unauthorized_status_(is_proxy_
                               ? http::HttpStatus::kProxyAuthenticationRequired
                               : http::HttpStatus::kUnauthorized),
      authenticate_header_(
          is_proxy_ ? USERVER_NAMESPACE::http::headers::kProxyAuthenticate
                    : USERVER_NAMESPACE::http::headers::kWWWAuthenticate),
      authorization_header_(
          is_proxy_ ? USERVER_NAMESPACE::http::headers::kProxyAuthorization
                    : USERVER_NAMESPACE::http::headers::kAuthorization),
      authenticate_info_header_(
          is_proxy_ ? USERVER_NAMESPACE::http::headers::kProxyAuthenticationInfo
                    : USERVER_NAMESPACE::http::headers::kAuthenticationInfo),
      digest_hasher_(algorithm_) {}

AuthCheckerBase::~AuthCheckerBase() = default;

AuthCheckResult AuthCheckerBase::CheckAuth(const http::HttpRequest& request,
                                           request::RequestContext&) const {
  // RFC 7616: https://datatracker.ietf.org/doc/html/rfc7616
  // Digest Access Authentication.
  auto& response = request.GetHttpResponse();
  const auto& etag = request.GetHeader(USERVER_NAMESPACE::http::headers::kETag);

  const auto& auth_value = request.GetHeader(authorization_header_);
  if (auth_value.empty()) {
    // If there is no authorization header, we save the "nonce" to temporary
    // storage.
    auto nonce = digest_hasher_.GenerateNonce(etag);

    response.SetStatus(unauthorized_status_);
    response.SetHeader(authenticate_header_,
                       ConstructResponseHeaderValue(nonce, true));

    PushUnnamedNonce(std::move(nonce));

    LOG_WARNING() << fmt::format("Missing {} header from client",
                                 authorization_header_);

    return AuthCheckResult{AuthCheckResult::Status::kInvalidToken};
  }

  Parser parser;
  ContextFromClient client_context;
  try {
    client_context = parser.ParseAuthInfo(auth_value);
  } catch (const Exception& ex) {
    response.SetStatus(http::HttpStatus::kBadRequest);
    LOG_WARNING() << "Directives parser exception: " << ex;
    throw handlers::ClientError();
  }

  // Check if user have been registered.
  auto user_data_opt = FetchUserData(client_context.username);
  if (!user_data_opt.has_value()) {
    LOG_WARNING() << fmt::format("User with username {} is not registered.",
                                 client_context.username);
    if (userhash_) {
      LOG_WARNING() << "Note: username above was hashed by the client";
    }
    return AuthCheckResult{AuthCheckResult::Status::kForbidden};
  }

  const auto& user_data = user_data_opt.value();
  auto validate_result = ValidateUserData(client_context, user_data);
  switch (validate_result) {
    case ValidateResult::kWrongUserData:
      return StartNewAuthSession(client_context.username,
                                 digest_hasher_.GenerateNonce(etag), true,
                                 response);
    case ValidateResult::kDuplicateRequest:
      response.SetStatus(unauthorized_status_);
      return AuthCheckResult{AuthCheckResult::Status::kTokenNotFound};
    case ValidateResult::kOk:
      break;
    default:
      UASSERT_MSG(false, "Found unhandled type of ValidateResult enum");
  }

  // Server MUST perform the same digest operation (e.g. SHA-256) performed
  // by the client and compare the result to the given 'response' value.
  auto ha1 = GetHA1(user_data.ha1, client_context);
  auto ha2 = GetHA2(ToString(request.GetMethod()), client_context.uri);
  auto digest =
      CalculateDigest(ha1, ha2, client_context);
  if (!crypto::algorithm::AreStringsEqualConstTime(digest,
                                                   client_context.response)) {
    response.SetStatus(unauthorized_status_);
    response.SetHeader(authenticate_header_, ConstructResponseHeaderValue(
                                                 client_context.nonce, false));
    return AuthCheckResult{AuthCheckResult::Status::kInvalidToken};
  }

  // Authentication-Info contains the "nextnonce" required for subsequent
  // authentication.
  // https://datatracker.ietf.org/doc/html/rfc7616#section-3.5
  //
  // 'rspauth' value is calculated in the same way as 'response' except
  // A2 = ":" request-uri
  ha2 = GetHA2("", client_context.uri);
  auto info_header_directives = ConstructAuthInfoHeaderValue(ha1, ha2, client_context, etag);
  response.SetHeader(authenticate_info_header_, info_header_directives);

  return {};
}

AuthCheckerBase::ValidateResult AuthCheckerBase::ValidateUserData(
    const ContextFromClient& client_context, const UserData& user_data) const {
  bool are_nonces_equal = crypto::algorithm::AreStringsEqualConstTime(
      user_data.nonce, client_context.nonce);
  if (!are_nonces_equal) {
    // "nonce" may be in temporary storage.
    auto nonce_creation_time =
        GetUnnamedNonceCreationTime(client_context.nonce);
    if (!nonce_creation_time.has_value()) {
      LOG_WARNING() << "Nonces aren't equal and no equivalent nonce found in "
                       "\"nonce pool\".";
      return ValidateResult::kWrongUserData;
    }

    SetUserData(client_context.username, client_context.nonce, 0,
                nonce_creation_time.value());
  }

  bool is_nonce_expired =
      user_data.timestamp + nonce_ttl_ < utils::datetime::Now();
  if (is_nonce_expired) {
    LOG_WARNING() << "Nonces are equal, but expired.";
    return ValidateResult::kWrongUserData;
  }

  LOG_DEBUG() << "Nonce is OK";

  std::int64_t client_nc{};
  try {
    client_nc = utils::FromHexString(client_context.nc);
  } catch (std::runtime_error& ex) {
    LOG_WARNING() << "Nonce_count from string to std::int64_t casting error: "
                  << ex;
    throw server::handlers::ClientError();
  }
  if (user_data.nonce_count >= client_nc) {
    LOG_WARNING() << "The current request is a duplicate.";
    return ValidateResult::kDuplicateRequest;
  }

  SetUserData(client_context.username, user_data.nonce, client_nc,
              user_data.timestamp);

  LOG_DEBUG() << "Nonce_count is OK";
  return ValidateResult::kOk;
}

std::string AuthCheckerBase::ConstructAuthInfoHeaderValue(
    std::string_view ha1, std::string_view ha2,
    const ContextFromClient& client_context,
    std::string_view etag) const {
  auto nextnonce = digest_hasher_.GenerateNonce(etag);
  SetUserData(client_context.username, nextnonce, 0, utils::datetime::Now());

  auto rspath = CalculateDigest(ha1, ha2, client_context);

  return utils::StrCat(
      fmt::format("{}=\"{}\", ", directives::kNextNonce, std::move(nextnonce)),
      fmt::format("{}={}, ", directives::kQop, client_context.qop),
      fmt::format("{}=\"{}\", ", directives::kResponseAuth, std::move(rspath)),
      fmt::format("{}=\"{}\", ", directives::kCnonce, client_context.cnonce),
      fmt::format("{}={}", directives::kNonceCount, client_context.nc));
}

AuthCheckResult AuthCheckerBase::StartNewAuthSession(
    std::string username, std::string&& nonce, bool stale,
    http::HttpResponse& response) const {
  response.SetStatus(unauthorized_status_);
  response.SetHeader(authenticate_header_,
                     ConstructResponseHeaderValue(nonce, stale));

  SetUserData(std::move(username), std::move(nonce), 0, utils::datetime::Now());

  return AuthCheckResult{AuthCheckResult::Status::kInvalidToken};
}

std::string AuthCheckerBase::ConstructResponseHeaderValue(std::string_view nonce,
                                                         bool stale) const {
  // The WWW-Authenticate Response Header Field.
  // https://datatracker.ietf.org/doc/html/rfc7616#section-3.3
  auto algorithm = algorithm_;
  if (is_session_) algorithm.append(kSessSuffix);

  return utils::StrCat(
      "Digest ", fmt::format("{}=\"{}\", ", directives::kRealm, realm_),
      fmt::format("{}=\"{}\", ", directives::kDomain, domain_),
      fmt::format("{}=\"{}\", ", directives::kNonce, nonce),
      fmt::format("{}={}, ", directives::kStale, stale),
      fmt::format("{}={}, ", directives::kAlgorithm, algorithm),
      fmt::format("{}=\"{}\", ", directives::kQop, qop_),
      fmt::format("{}={}, ", directives::kCharset, charset_),
      fmt::format("{}={}, ", directives::kUserhash, userhash_));
}

std::string AuthCheckerBase::CalculateDigest(
    std::string_view ha1, std::string_view ha2,
    const ContextFromClient& client_context) const {
  // 'digest' value is calculated in the same way as 'response'
  // https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.1
  auto digest = fmt::format("{}:{}:{}:{}:{}:{}", ha1, client_context.nonce,
                            client_context.nc, client_context.cnonce,
                            client_context.qop, ha2);
  return digest_hasher_.GetHash(digest);
}

std::string AuthCheckerBase::GetHA1(
    const UserData::HA1& ha1_non_loggable,
    const ContextFromClient& client_context) const {
  auto ha1 = ha1_non_loggable.GetUnderlying();
  if (is_session_) {
    // If algorithm Session variant enabled, then A1 is calculated using the
    // 'nonce' and 'cnonce' values.
    // https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.2
    ha1.append(
        fmt::format(":{}:{}", client_context.nonce, client_context.cnonce));
  }

  return ha1;
}

std::string AuthCheckerBase::GetHA2(std::string_view http_method,
                                    std::string_view uri) const {
  // If the qop value is "auth":
  // A2 = Method ":" request-uri
  //
  // If the qop value is "auth-int" (сurrently not supported):
  // A2 = Method ":" request-uri ":" H(entity-body)
  // https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.3
  return digest_hasher_.GetHash(fmt::format("{}:{}",  http_method, uri));
}

}  // namespace server::handlers::auth::digest

USERVER_NAMESPACE_END
