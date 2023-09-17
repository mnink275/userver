#pragma once

/// @file
/// userver/server/handlers/auth/digest/digest_checker_settings_component.hpp
/// @brief @copybrief
/// server::handlers::auth::digest::AuthCheckerSettingsComponent

#include <chrono>
#include <optional>
#include <string>

#include <userver/components/loggable_component_base.hpp>
#include <userver/dynamic_config/source.hpp>

#include "auth_checker_settings.hpp"

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth::digest {

// clang-format off

/// @brief Component that loads digest auth configuration settings from a
/// static_config.yaml
/// ## Static options:
///
/// Name       | Description                                    | Default value
/// ---------- | ---------------------------------------------- | -------------
/// algorithm  | Hashing algorithms. You can use Session variant with `-sess` suffix (e.g. SHA-265-sess). | SHA-256
/// domain     | List of URIs, that define the protection space | /
/// qop        | list of supported qop-options. Use `auth` for authentication and `auth-in` for authentication with integrity protection | auth
/// nonce-ttl  | ttl for nonce | 10s

/// ## Supported hashing algorithms:
///
/// Name       | Description                                
/// ---------- | -------------------------------------------
/// SHA-256    | Default                                    
/// SHA-512    |                                            
/// MD5        | Not recommended, for backward compatibility

// clang-format on

class AuthCheckerSettingsComponent : public components::LoggableComponentBase {
 public:
  /// @ingroup userver_component_names
  /// @brief The default name of
  /// server::handlers::auth::digest::AuthCheckerSettingsComponent
  static constexpr std::string_view kName = "auth-digest-checker-settings";

  AuthCheckerSettingsComponent(const components::ComponentConfig& config,
                               const components::ComponentContext& context);

  ~AuthCheckerSettingsComponent() override;

  const AuthCheckerSettings& GetSettings() const;

  static yaml_config::Schema GetStaticConfigSchema();

 private:
  AuthCheckerSettings settings_;
};

}  // namespace server::handlers::auth::digest

template <>
inline constexpr bool components::kHasValidate<
    server::handlers::auth::digest::AuthCheckerSettingsComponent> = true;

USERVER_NAMESPACE_END
