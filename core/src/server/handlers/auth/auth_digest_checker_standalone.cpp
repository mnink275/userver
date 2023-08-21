#include <userver/server/handlers/auth/auth_digest_checker_standalone.hpp>

#include <memory>
#include <optional>
#include <string_view>

#include <userver/server/handlers/auth/auth_digest_settings.hpp>
#include "userver/server/handlers/auth/auth_digest_checker_base.hpp"
#include "userver/utils/datetime.hpp"

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth {

AuthCheckerDigestBaseStandalone::AuthCheckerDigestBaseStandalone(
    const AuthDigestSettings& digest_settings, Realm&& realm)
    : AuthCheckerDigestBase(digest_settings, std::move(realm)){};

std::optional<UserData> AuthCheckerDigestBaseStandalone::GetUserData(
    const std::string& username) const {
  auto ha1 = GetHA1(username);
  if (!ha1) {
    // If ha1 is not found, we return an empty UserData
    return std::nullopt;
  }

  auto nonce_info = user_data_.Get(username);
  if (nonce_info) {
    // If nonce_info is found by username, we return UserData
    UserData user_data{ha1.value(), nonce_info->nonce,
                       nonce_info->nonce_creation_time,
                       nonce_info->nonce_count};
    return user_data;
  }

  // If nonce_info is not found by username, we create NonceInfo for username,
  // push to user_data_ and return UserData
  NonceInfo nonce_info_temp{"", utils::datetime::Now(), 0};
  SetUserData(username, nonce_info_temp.nonce, nonce_info_temp.nonce_count,
              nonce_info_temp.nonce_creation_time);
  UserData user_data{ha1.value(), nonce_info_temp.nonce,
                     nonce_info_temp.nonce_creation_time,
                     nonce_info_temp.nonce_count};
  return user_data;
}

void AuthCheckerDigestBaseStandalone::SetUserData(
    const std::string& username, const Nonce& nonce, std::int32_t nonce_count,
    TimePoint nonce_creation_time) const {
  auto nonce_info = std::make_shared<NonceInfo>(
      std::move(nonce), std::move(nonce_creation_time), std::move(nonce_count));
  user_data_.InsertOrAssign(username, nonce_info);
}

}  // namespace server::handlers::auth

USERVER_NAMESPACE_END