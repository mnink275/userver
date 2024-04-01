#pragma once

/// @file userver/server/handlers/auth/digest/types.hpp
/// @brief Types for validating directive values

#include <userver/utils/trivial_map.hpp>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth::digest {

/// @brief Supported hashing algorithms
enum class HashAlgorithmsTypes {
  kMD5,     ///< MD5 algorithm (not recommended, for backward compatibility)
  kSHA256,  ///< SHA-256 algorithm (default)
  kSHA512,  ///< SHA-512 algorithm
};

/// @brief Supported `qop` field values. See 'qop' from
/// https://datatracker.ietf.org/doc/html/rfc7616#section-3.3
enum class QopTypes {
  kAuth,  ///< The value "auth" indicates authentication (default)
};

/// @cond
// To handle algorithm Session variant. See: 'algorithm' from
// https://datatracker.ietf.org/doc/html/rfc7616#section-3.3
constexpr std::string_view kSessSuffix = "-sess";
/// @endcond

inline constexpr utils::TrivialBiMap kHashAlgorithmsMap = [](auto selector) {
  return selector()
      .Case("MD5", HashAlgorithmsTypes::kMD5)
      .Case("SHA-256", HashAlgorithmsTypes::kSHA256)
      .Case("SHA-512", HashAlgorithmsTypes::kSHA512);
};

inline constexpr utils::TrivialBiMap kQopToType = [](auto selector) {
  return selector().Case("auth", QopTypes::kAuth);
};

inline constexpr utils::TrivialSet kSupportedCharsets = [](auto selector) {
  return selector().Case("UTF-8");
};

}  // namespace server::handlers::auth::digest

USERVER_NAMESPACE_END
