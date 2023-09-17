#include <userver/server/handlers/auth/digest/auth_checker_settings_component.hpp>

#include <cstddef>

#include <userver/components/component.hpp>
#include <userver/dynamic_config/storage/component.hpp>
#include <userver/dynamic_config/value.hpp>
#include <userver/server/handlers/auth/digest/types.hpp>
#include <userver/utils/async.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth::digest {

constexpr size_t kDefaultTtlMs = 10 * 1000;

AuthCheckerSettingsComponent::AuthCheckerSettingsComponent(
    const components::ComponentConfig& config,
    const components::ComponentContext& context)
    : components::LoggableComponentBase(config, context) {
  // Reading config values from static config
  // Check for valid algorithms
  auto parsed_algorithm = config["algorithm"].As<std::string>("SHA-256");

  std::string_view algorithm = parsed_algorithm;
  const auto dash_index = algorithm.size() - kSessSuffix.size();
  if (algorithm.size() > kSessSuffix.size() &&
      algorithm.substr(dash_index) == kSessSuffix) {
    algorithm = algorithm.substr(0, dash_index);
    settings_.is_session = true;
  }
  if (!kHashAlgorithmsMap.TryFind(algorithm).has_value()) {
    throw std::runtime_error(
        fmt::format("Algorithm '{}' is not supported", parsed_algorithm));
  }
  settings_.algorithm = algorithm;

  auto domains = config["domain"].As<std::vector<std::string>>(
      std::vector<std::string>{"/"});
  settings_.domain = fmt::format("{}", fmt::join(domains, " "));

  auto qops = config["qops"].As<std::vector<std::string>>(
      std::vector<std::string>{"auth"});
  // Check for valid qops
  for (const auto& qop : qops) {
    if (!kQopToType.TryFindICase(qop).has_value()) {
      throw std::runtime_error(fmt::format("Qop '{}' is not supported", qop));
    }
  }
  settings_.qop = fmt::format("{}", fmt::join(qops, ","));

  settings_.is_proxy = config["is-proxy"].As<bool>(false);
  settings_.nonce_ttl =
      config["nonce-ttl"].As<std::chrono::milliseconds>(kDefaultTtlMs);

  auto charset_opt = config["charset"].As<std::optional<std::string>>();
  if (charset_opt.has_value() &&
      !kSupportedCharsets.Contains(charset_opt.value())) {
    throw std::runtime_error(
        fmt::format("charset '{}' is not allowed", charset_opt.value()));
  }
  settings_.charset = std::move(charset_opt);

  settings_.userhash = config["userhash"].As<bool>(false);
}

AuthCheckerSettingsComponent::~AuthCheckerSettingsComponent() = default;

const AuthCheckerSettings& AuthCheckerSettingsComponent::GetSettings() const {
  return settings_;
}

yaml_config::Schema AuthCheckerSettingsComponent::GetStaticConfigSchema() {
  return yaml_config::MergeSchemas<components::LoggableComponentBase>(R"(
type: object
description: settings for digest authentication
additionalProperties: false
properties:
    algorithm:
      type: string
      description: algorithm for hashing nonce
    domain:
      type: array
      description: space-separated list of URIs that define the protection space
      defaultDescription: all URIs (i.e. "/")
      items:
          type: string
          description: list of URIs in the same protection space
    qops:
      type: array
      description: quality of protection
      items:
          type: string
          description: qop name
    is-proxy:
      type: boolean
      description: if set, the Proxy prefix is inserted into the header
      defaultDescription: false
    nonce-ttl:
        type: string
        description: TTL for nonces
        defaultDescription: 10s
    charset:
        type: string
        description: optional, indicates the encoding scheme server supports
        defaultDescription: The only allowed value is "UTF-8"
    userhash:
        type: boolean
        description: optional, indicates the encoding scheme server supports
        defaultDescription: false
)");
}

}  // namespace server::handlers::auth::digest

USERVER_NAMESPACE_END
