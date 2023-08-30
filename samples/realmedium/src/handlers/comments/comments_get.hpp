#pragma once

#include <fmt/format.h>
#include <string>
#include <string_view>
#include <tuple>

#include <userver/server/handlers/http_handler_base.hpp>
#include <userver/server/handlers/http_handler_json_base.hpp>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/component.hpp>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>

#include <userver/formats/json/value.hpp>

#include <userver/formats/serialize/common_containers.hpp>
#include "cache/articles_cache.hpp"
#include "cache/comments_cache.hpp"

namespace real_medium::handlers::comments::get {

class Handler final : public userver::server::handlers::HttpHandlerJsonBase {
 public:
  static constexpr std::string_view kName = "handler-comments-get";

  Handler(const userver::components::ComponentConfig& config,
          const userver::components::ComponentContext& component_context);
  userver::formats::json::Value HandleRequestJsonThrow(
      const userver::server::http::HttpRequest& request,
      const userver::formats::json::Value& request_json,
      userver::server::request::RequestContext& context) const override final;
  using HttpHandlerJsonBase::HttpHandlerJsonBase;

 private:
  userver::storages::postgres::ClusterPtr pg_cluster_;
  const real_medium::cache::comments_cache::CommentsCache& commentsCache_;
  const real_medium::cache::articles_cache::ArticlesCache& articlesCache_;
};

}  // namespace real_medium::handlers::comments::get
