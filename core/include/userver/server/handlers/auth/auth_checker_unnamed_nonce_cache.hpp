#pragma once 

#include <userver/cache/lru_cache_component_base.hpp>
#include <userver/components/component_list.hpp>
 
using Nonce = std::string;
using TimePoint = std::chrono::time_point<std::chrono::system_clock>;
 
class NonceCacheComponent final
    : public cache::LruCacheComponent<Nonce, TimePoint> {
 public:
  static constexpr auto kName = "nonce-cache";
 
  NonceCacheComponent(const components::ComponentConfig& config,
                        const components::ComponentContext& context)
      : ::cache::LruCacheComponent<Key, TimePoint>(config, context) {}
 
 private:
  TimePoint DoGetByKey(const Nonce& key) override {
    return GetValueForExpiredKeyFromRemote(key);
  }
 
  TimePoint GetValueForExpiredKeyFromRemote(const Key& key);
};
