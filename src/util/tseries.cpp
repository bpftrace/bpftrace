#include <cstdint>
#include <cstring>

#include "util/tseries.h"

namespace bpftrace::util {

template <typename T>
struct tseries_data {
  T val;
  T meta;
  uint64_t epoch;
};

template <typename T>
std::pair<uint64_t, uint64_t> reduce_tseries_value(const OpaqueValue &value,
                                                   TSeriesAggFunc agg)
{
  // Combine values only from the same epoch and return the reduced value from
  // the latest epoch in this bucket.
  std::map<uint64_t, tseries_data<T>> epoch_to_value;
  uint64_t latest_epoch = 0;

  for (size_t i = 0; i < value.count<tseries_data<T>>(); i++) {
    const auto &v = value.bitcast<tseries_data<T>>(i);
    if (v.epoch == 0) {
      // Don't consider buckets where epoch is 0. This means it was never used.
      continue;
    }

    latest_epoch = std::max(v.epoch, latest_epoch);

    if (epoch_to_value.find(v.epoch) == epoch_to_value.end()) {
      epoch_to_value[v.epoch] = v;
      continue;
    }

    auto &current = epoch_to_value[v.epoch];
    switch (agg) {
      case TSeriesAggFunc::none:
        // If no aggregation function is specified, the most recently assigned
        // value wins. Use the timestamp to decide which is the most recent
        // value.
        if (v.meta > current.meta) {
          current.val = v.val;
          current.meta = v.meta;
        }
        break;
      case TSeriesAggFunc::avg: {
        current.val += v.val;
        current.meta += v.meta;
      } break;
      case TSeriesAggFunc::max:
      case TSeriesAggFunc::min: {
        if (agg == TSeriesAggFunc::min) {
          current.val = std::min(current.val, v.val);
        } else {
          current.val = std::max(current.val, v.val);
        }
      } break;
      case TSeriesAggFunc::sum:
        current.val += v.val;
        break;
    }
  }

  if (latest_epoch == 0) {
    return {};
  }

  auto &latest = epoch_to_value[latest_epoch];
  if (agg == TSeriesAggFunc::avg) {
    latest.val = static_cast<T>(latest.val / latest.meta);
  }

  return { latest.epoch, latest.val };
}

std::pair<uint64_t, OpaqueValue> reduce_tseries_value(
    const OpaqueValue &value,
    const SizedType &value_type,
    TSeriesAggFunc agg)
{
  if (value_type.IsSigned()) {
    auto v = reduce_tseries_value<int64_t>(value, agg);
    return { v.first, OpaqueValue::from(v.second) };
  } else {
    auto v = reduce_tseries_value<uint64_t>(value, agg);
    return { v.first, OpaqueValue::from(v.second) };
  }
}

} // namespace bpftrace::util
