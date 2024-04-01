#include <userver/server/handlers/auth/digest/auth_checker_settings_component.hpp>

#include <cstddef>

#include <userver/components/component.hpp>
#include <userver/dynamic_config/storage/component.hpp>
#include <userver/dynamic_config/value.hpp>
#include <userver/server/handlers/auth/digest/types.hpp>
#include <userver/utils/async.hpp>
#include <userver/utils/text.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

USERVER_NAMESPACE_BEGIN

namespace server::handlers::auth::digest {

constexpr size_t kDefaultTtlMs = 10 * 1000;

AuthCheckerSettingsComponent::AuthCheckerSettingsComponent(
    const components::ComponentConfig& config,
    const components::ComponentContext& context)
    : components::LoggableComponentBase(config, context) {
  // Reading config values from static config
  auto parsed_algorithm = config["algorithm"].As<std::string>("SHA-256");

  std::string_view algorithm = parsed_algorithm;
  if (utils::text::EndsWith(algorithm, kSessSuffix)) {
    algorithm = algorithm.substr(0, algorithm.size() - kSessSuffix.size());
    settings_.is_session = true;
  }
  if (!kHashAlgorithmsMap.TryFind(algorithm).has_value()) {
    throw std::runtime_error(
        fmt::format("Algorithm '{}' is not supported", parsed_algorithm));
  }
  settings_.algorithm = algorithm;

  auto domains = config["domain"].As<std::vector<std::string>>(
      std::vector<std::string>{"/"});
  settings_.domain = fmt::format("{}", fmt::join(std::move(domains), " "));

  auto qops = config["qop"].As<std::vector<std::string>>(
      std::vector<std::string>{"auth"});
  for (const auto& qop : qops) {
    if (!kQopToType.TryFindICase(qop).has_value()) {
      throw std::runtime_error(fmt::format("Qop '{}' is not supported", qop));
    }
  }
  settings_.qop = fmt::format("{}", fmt::join(std::move(qops), ","));

  settings_.is_proxy = config["is-proxy"].As<bool>(false);

  settings_.nonce_ttl =
      config["nonce-ttl"].As<std::chrono::milliseconds>(kDefaultTtlMs);

  auto charset = config["charset"].As<std::string>("UTF-8");
  if (!kSupportedCharsets.Contains(charset)) {
    throw std::runtime_error(
        fmt::format("charset '{}' is not allowed", charset));
  }
  settings_.charset = std::move(charset);

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
    qop:
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
        description: indicates the encoding scheme server supports
        defaultDescription: The only allowed value is "UTF-8"
    userhash:
        type: boolean
        description: indicates that the username has been hashed by client
        defaultDescription: false
)");
}

}  // namespace server::handlers::auth::digest

USERVER_NAMESPACE_END
