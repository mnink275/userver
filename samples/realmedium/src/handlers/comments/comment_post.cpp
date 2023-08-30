
#include "comment_post.hpp"
#include "db/sql.hpp"
#include "dto/comment.hpp"
#include "models/comment.hpp"

#include "utils/errors.hpp"
#include "utils/make_error.hpp"
#include "validators/validators.hpp"

namespace real_medium::handlers::comments::post {

Handler::Handler(const userver::components::ComponentConfig& config,
                 const userver::components::ComponentContext& component_context)
    : HttpHandlerJsonBase(config, component_context),
      pg_cluster_(component_context
                      .FindComponent<userver::components::Postgres>(
                          "realmedium-database")
                      .GetCluster()) {}

userver::formats::json::Value Handler::HandleRequestJsonThrow(
    const userver::server::http::HttpRequest& request,
    const userver::formats::json::Value& request_json,
    userver::server::request::RequestContext& context) const {
  auto user_id = context.GetData<std::optional<std::string>>("id");

  const auto comment_json =
      userver::formats::json::FromString(request.RequestBody())["comment"]
          .As<dto::AddComment>();

  try {
    validator::validate(comment_json);
  } catch (const utils::error::ValidationException& err) {
    request.SetResponseStatus(
        userver::server::http::HttpStatus::kUnprocessableEntity);
    return err.GetDetails();
  }

  const auto& comment_body = comment_json.body;
  const auto& slug = request.GetPathArg("slug");

  const auto res_find_article = pg_cluster_->Execute(
      userver::storages::postgres::ClusterHostType::kMaster,
      sql::kFindIdArticleBySlug.data(), slug);

  if (res_find_article.IsEmpty()) {
    auto& response = request.GetHttpResponse();
    response.SetStatus(userver::server::http::HttpStatus::kNotFound);
    return utils::error::MakeError("article_id", "Invalid article_id.");
  }

  const auto article_id = res_find_article.AsSingleRow<std::string>();

  const auto res_ins_new_comment = pg_cluster_->Execute(
      userver::storages::postgres::ClusterHostType::kMaster,
      sql::kAddComment.data(), comment_body, user_id, article_id);

  if (res_ins_new_comment.IsEmpty()) {
    auto& response = request.GetHttpResponse();
    response.SetStatus(
        userver::server::http::HttpStatus::kNotImplemented);  // 501, мб надо
                                                              // заменить
    return utils::error::MakeError(
        "none", "Unknow error. The comment was not added to the database.");
  }

  auto comment_res_data =
      res_ins_new_comment.AsSingleRow<real_medium::dto::Comment>(
          userver::storages::postgres::kRowTag);

  userver::formats::json::ValueBuilder builder;
  builder["comment"] = comment_res_data;

  return builder.ExtractValue();
}

}  // namespace real_medium::handlers::comments::post
