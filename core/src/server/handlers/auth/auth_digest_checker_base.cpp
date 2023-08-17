#include <userver/server/handlers/auth/auth_digest_checker_base.hpp>

#include <chrono>
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
#include <userver/server/handlers/exceptions.hpp>
#include <userver/server/handlers/fallback_handlers.hpp>
#include <userver/utils/algo.hpp>
#include <userver/server/handlers/auth/digest_directives.hpp>
#include <userver/server/handlers/auth/digest_algorithms.hpp>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth {

constexpr std::string_view kDigestWord = "Digest";

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

using Nonce = std::string;
using Username = std::string;
using NonceCount = std::uint32_t;

AuthCheckerDigestBase::AuthCheckerDigestBase(
    const AuthDigestSettings& digest_settings, Realm realm)
    : qops_(digest_settings.qops),
      qops_str_({}),
      realm_(std::move(realm)),
      domains_(digest_settings.domains),
      domains_str_({}),
      algorithm_(digest_settings.algorithm),
      is_session_(digest_settings.is_session.value_or(false)),
      is_proxy_(digest_settings.is_proxy.value_or(false)),
      nonce_ttl_(digest_settings.nonce_ttl),
      digest_hasher_(algorithm_) {
  qops_str_ = fmt::format("{}", fmt::join(qops_, ","));
  domains_str_ = fmt::format("{}", fmt::join(domains_, ", "));
}

AuthCheckResult AuthCheckerDigestBase::CheckAuth(
    const server::http::HttpRequest& request,
    server::request::RequestContext&) const {
  auto& response = request.GetHttpResponse();

  const auto& auth_value =
      request.GetHeader(userver::http::headers::kAuthorization);
  if (auth_value.empty()) {
    throw CustomHandlerException(impl::CustomHandlerExceptionData{
        server::handlers::HandlerErrorCode::kUnauthorized,
        ConstructResponseDirectives(digest_hasher_.Nonce(),
                                    digest_hasher_.Opaque(), false)});
  }

  DigestParsing parser;
  parser.ParseAuthInfo(auth_value.substr(kDigestWord.size() + 1));
  const auto& client_context = parser.GetClientContext();
  auto client_server_data_ptr = client_data_.Get(client_context.username);
  if (!client_server_data_ptr) {
    StartNewAuthSession(client_context.username, digest_hasher_.Nonce(),
                        digest_hasher_.Opaque(), true);
  }
  LOG_DEBUG() << "USER IS OK";

  if (IsNonceExpired(client_context.username, client_context.nonce)) {
    StartNewAuthSession(client_context.username, digest_hasher_.Nonce(),
                        digest_hasher_.Opaque(), true);
  }
  LOG_DEBUG() << "NONCE IS OK";

  auto client_nc = std::stoul(client_context.nc, nullptr, 16);
  if (*nonce_counts_[client_context.nonce] < client_nc) {
    *nonce_counts_[client_context.nonce] = client_nc;
  } else {
    return AuthCheckResult{AuthCheckResult::Status::kTokenNotFound};
  }
  LOG_DEBUG() << "NONCE_COUNT IS OK";

  if (!crypto::algorithm::AreStringsEqualConstTime(client_context.opaque, client_data_[client_context.username]->opaque)) {
    StartNewAuthSession(client_context.username, digest_hasher_.Nonce(),
                        digest_hasher_.Opaque(), true);
  }
  LOG_DEBUG() << "OPAQUE IS OK";

  auto ha1_opt = GetHA1(client_context.username);
  if (!ha1_opt.has_value()) {
    throw CustomHandlerException(
        server::handlers::HandlerErrorCode::kForbidden);
  }
  LOG_DEBUG() << "HA1 IS OK";

  auto ha1 = ha1_opt.value().GetUnderlying();
  if (is_session_) {
    ha1 = fmt::format("{}:{}:{}", ha1, client_context.nonce,
                      client_context.cnonce);
  }

  auto a2 =
      fmt::format("{}:{}", ToString(request.GetMethod()), client_context.uri);
  if (client_context.qop == "auth-int") {
    a2.append(digest_hasher_.GetHash(request.RequestBody()));
  }
  std::string ha2 = digest_hasher_.GetHash(a2);

  // digest_value = H(HA1:nonce:nc:cnonce:qop:HA2)
  std::string digest_value = fmt::format("{}:{}:{}:{}:{}:{}",
  ha1, client_context.nonce, client_context.nc,
  client_context.cnonce, client_context.qop, ha2);
  auto digest = digest_hasher_.GetHash(digest_value);
  LOG_DEBUG() << "DIGEST: " << digest << " " << client_context.response;

  if (!crypto::algorithm::AreStringsEqualConstTime(digest, client_context.response)) {
    throw CustomHandlerException(impl::CustomHandlerExceptionData{
        server::handlers::HandlerErrorCode::kUnauthorized,
        ConstructResponseDirectives(client_context.nonce, client_context.opaque,
                                    false)});
  }

  // successful authorization
  // create and add auth-info header with 200 OK code
  auto info_header = ConstructAuthInfoHeader(ha1, client_context);
  std::string_view st = "Authentication-Info";
  response.SetHeader(st, info_header);
  return {};
};

void AuthCheckerDigestBase::StartNewAuthSession(std::string_view username,
                                                std::string_view client_nonce,
                                                std::string_view client_opaque,
                                                bool stale) const {
  client_data_.Emplace(username.data(),
                       ClientData{client_nonce.data(), client_opaque.data(),
                                  std::chrono::system_clock::now()});
  throw CustomHandlerException(impl::CustomHandlerExceptionData{
      server::handlers::HandlerErrorCode::kUnauthorized,
      ConstructResponseDirectives(client_nonce, client_opaque, stale)});
}

// clang-format off
ExtraHeaders AuthCheckerDigestBase::ConstructResponseDirectives(
    std::string_view nonce, std::string_view opaque, bool stale) const {
  ExtraHeaders extra_headers;
  extra_headers.headers["WWW-Authenticate"] = utils::StrCat(
      "Digest ",
      fmt::format("{}=\"{}\", ", kTypesToDirectives.TryFind(DirectiveTypes::kRealm).value(), realm_),
      fmt::format("{}=\"{}\", ", kTypesToDirectives.TryFind(DirectiveTypes::kNonce).value(), nonce),
      fmt::format("{}=\"{}\", ", kTypesToDirectives.TryFind(DirectiveTypes::kStale).value(), stale),
      fmt::format("{}=\"{}\", ", kTypesToDirectives.TryFind(DirectiveTypes::kDomain).value(), domains_str_),
      fmt::format("{}=\"{}\", ", kTypesToDirectives.TryFind(DirectiveTypes::kOpaque).value(), opaque),
      fmt::format("{}=\"{}\", ", kTypesToDirectives.TryFind(DirectiveTypes::kAlgorithm).value(), algorithm_),
      fmt::format("{}=\"{}\"", kTypesToDirectives.TryFind(DirectiveTypes::kQop).value(), qops_str_));
  return extra_headers;
}

std::string AuthCheckerDigestBase::ConstructAuthInfoHeader(
    std::string_view ha1, DigestContextFromClient client_context) const {
  auto nextnonce = digest_hasher_.Nonce();
  // qop = auth
  auto a2 = fmt::format(":{}", client_context.uri);
  // qop = auth-int 
  // auto a2 = fmt::format("{}:{}", client_context.uri, entity-body);
  std::string ha2 = digest_hasher_.GetHash(a2);
  std::string digest_value = fmt::format("{}:{}:{}:{}:{}:{}",
    ha1, client_context.nonce, client_context.nc,
    client_context.cnonce, client_context.qop, ha2);
  auto response_digest = digest_hasher_.GetHash(digest_value);
  return utils::StrCat(
      fmt::format("{}=\"{}\", ", "nextnonce", nextnonce),
      fmt::format("{}=\"{}\", ", kTypesToDirectives.TryFind(DirectiveTypes::kQop).value(), client_context.qop),
      fmt::format("{}=\"{}\", ", "rspauth", response_digest),
      fmt::format("{}=\"{}\", ", "cnonce", client_context.cnonce),
      fmt::format("{}=\"{}\", ", "nc", client_context.nc));
}
// clang-format on

bool AuthCheckerDigestBase::IsNonceExpired(
    const std::string& username, std::string_view nonce_from_client) const {
  const auto& client_data = client_data_[username];
  if (client_data->timestamp + nonce_ttl_ < std::chrono::system_clock::now()) {
    return false;
  }
  LOG_DEBUG() << "TIMESTAMP IS OK";
  LOG_DEBUG() << "NONCE: " << client_data->nonce;
  LOG_DEBUG() << "NONCE_FROM_CLIENT: " << nonce_from_client;
  return !crypto::algorithm::AreStringsEqualConstTime(client_data->nonce, nonce_from_client);
}

}  // namespace server::handlers::auth

USERVER_NAMESPACE_END
