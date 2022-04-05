#include <userver/storages/clickhouse/io/columns/datetime64_column.hpp>

#include <storages/clickhouse/io/columns/impl/column_includes.hpp>

#include <clickhouse/columns/date.h>

USERVER_NAMESPACE_BEGIN

namespace storages::clickhouse::io::columns {

namespace {

using NativeType = clickhouse::impl::clickhouse_cpp::ColumnDateTime64;

template <typename T>
struct ColumnDuration;

template <>
struct ColumnDuration<DateTime64ColumnMilli> {
  using type = std::chrono::milliseconds;
};

template <>
struct ColumnDuration<DateTime64ColumnMicro> {
  using type = std::chrono::microseconds;
};

template <>
struct ColumnDuration<DateTime64ColumnNano> {
  using type = std::chrono::nanoseconds;
};

template <typename T>
using ColumnDurationType = typename ColumnDuration<T>::type;

template <typename DateColumnType>
std::chrono::system_clock::time_point DoGetDate(const ColumnRef& column,
                                                size_t ind) {
  const auto tics = impl::NativeGetAt<NativeType>(column, ind);

  using clock = std::chrono::system_clock;
  return clock::time_point{std::chrono::duration_cast<clock::duration>(
      ColumnDurationType<DateColumnType>{tics})};
}

template <typename DateColumnType>
ColumnRef DoSerializeDate(
    const std::vector<std::chrono::system_clock::time_point>& from) {
  auto column = clickhouse::impl::clickhouse_cpp::ColumnDateTime64(
      DateColumnType::precision);
  for (const auto tp : from) {
    column.Append(
        std::chrono::duration_cast<ColumnDurationType<DateColumnType>>(
            tp.time_since_epoch())
            .count());
  }

  return std::make_shared<decltype(column)>(std::move(column));
}

template <typename ColumnType>
ColumnRef GetDatetimeColumn(const ColumnRef& column) {
  return impl::GetTypedColumn<ColumnType, NativeType>(column);
}

}  // namespace

template <>
DateTime64ColumnMilli::DateTime64Column(ColumnRef column)
    : ClickhouseColumn{GetDatetimeColumn<DateTime64ColumnMilli>(column)} {}

template <>
DateTime64ColumnMicro::DateTime64Column(ColumnRef column)
    : ClickhouseColumn{GetDatetimeColumn<DateTime64ColumnMilli>(column)} {}

template <>
DateTime64ColumnNano::DateTime64Column(ColumnRef column)
    : ClickhouseColumn{GetDatetimeColumn<DateTime64ColumnMilli>(column)} {}

template <>
DateTime64ColumnMilli::cpp_type
BaseIterator<DateTime64ColumnMilli>::DataHolder::Get() const {
  return DoGetDate<DateTime64ColumnMilli>(column_, ind_);
}

template <>
DateTime64ColumnMicro::cpp_type
BaseIterator<DateTime64ColumnMicro>::DataHolder::Get() const {
  return DoGetDate<DateTime64ColumnMicro>(column_, ind_);
}

template <>
DateTime64ColumnNano::cpp_type
BaseIterator<DateTime64ColumnNano>::DataHolder::Get() const {
  return DoGetDate<DateTime64ColumnNano>(column_, ind_);
}

template <>
ColumnRef DateTime64ColumnMilli::Serialize(const container_type& from) {
  return DoSerializeDate<DateTime64ColumnMilli>(from);
}

template <>
ColumnRef DateTime64ColumnMicro::Serialize(const container_type& from) {
  return DoSerializeDate<DateTime64ColumnMicro>(from);
}

template <>
ColumnRef DateTime64ColumnNano::Serialize(const container_type& from) {
  return DoSerializeDate<DateTime64ColumnNano>(from);
}

}  // namespace storages::clickhouse::io::columns

USERVER_NAMESPACE_END
