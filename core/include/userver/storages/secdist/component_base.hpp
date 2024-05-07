#pragma once

/// @file userver/storages/secdist/component_base.hpp
/// @brief @copybrief components::SecdistComponentBase

#include <string>

#include <userver/components/loggable_component_base.hpp>
#include <userver/storages/secdist/secdist.hpp>

USERVER_NAMESPACE_BEGIN

namespace components {
// clang-format off

/// @ingroup userver_components
///
/// @brief Component that stores security related data (keys, passwords, ...).
///
/// The component must be configured in service config.
///
/// Secdist requires a provider storages::secdist::SecdistProvider
/// You can implement your own or use components::DefaultSecdistProvider
///
/// ## Static configuration example:
///
/// @snippet samples/redis_service/static_config.yaml Sample secdist static config
///
/// ## Static options:
/// Name | Description | Default value
/// ---- | ----------- | -------------
/// provider | optional secdist provider component name | 'default-secdist-provider'
/// config | path to the config file with data | ''
/// format | config format, either `json` or `yaml` | 'json'
/// missing-ok | do not terminate components load if no file found by the config option | false
/// environment-secrets-key | name of environment variable from which to load additional data | -
/// update-period | period between data updates in utils::StringToDuration() suitable format ('0s' for no updates) | 0s
/// blocking-task-processor | name of task processor for background blocking operations | --

// clang-format on

class SecdistComponentBase : public LoggableComponentBase {
 public:
  SecdistComponentBase(const ComponentConfig&, const ComponentContext&,
          storages::secdist::SecdistConfig::Settings&&);

  const storages::secdist::SecdistConfig& Get() const;

  rcu::ReadablePtr<storages::secdist::SecdistConfig> GetSnapshot() const;

  storages::secdist::Secdist& GetStorage();

  static yaml_config::Schema GetStaticConfigSchema();

 private:
  storages::secdist::Secdist secdist_;
};

}  // namespace components

USERVER_NAMESPACE_END
