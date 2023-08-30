#pragma once

#include <userver/components/component_context.hpp>
#include <userver/formats/json/inline.hpp>
#include <userver/formats/json/value.hpp>
#include <userver/server/handlers/http_handler_base.hpp>
#include <userver/server/handlers/http_handler_json_base.hpp>
#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/component.hpp>
#include <userver/storages/postgres/postgres_fwd.hpp>
#include "../../cache/articles_cache.hpp"

namespace real_medium::handlers::articles_slug::get {
class Handler final : public userver::server::handlers::HttpHandlerJsonBase {
 public:
  static constexpr std::string_view kName{"handler-get-article"};

  Handler(const userver::components::ComponentConfig& config,
          const userver::components::ComponentContext& context);

  userver::formats::json::Value HandleRequestJsonThrow(
      const userver::server::http::HttpRequest& request,
      const userver::formats::json::Value& request_json,
      userver::server::request::RequestContext& context) const override final;

 private:
  const userver::storages::postgres::ClusterPtr pg_cluster_;
  const real_medium::cache::articles_cache::ArticlesCache& cache_;
};
}  // namespace real_medium::handlers::articles_slug::get
