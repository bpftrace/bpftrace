#include <cstdint>
#include <cstring>
#include <vector>

#include "util/stats.h"
#include "util/tseries.h"

namespace bpftrace::util {

template <typename T>
std::pair<T, uint64_t> reduce_tseries_value(const std::vector<uint8_t> &values,
                                            int nvalues,
                                            TSeriesAggFunc agg)
{
  constexpr size_t tseries_struct_member_sz = sizeof(uint64_t);
  constexpr size_t tseries_struct_sz = 3 * tseries_struct_member_sz;
  constexpr size_t meta_off = tseries_struct_member_sz;
  constexpr size_t epoch_off = tseries_struct_member_sz * 2;

  // Combine values only from the same epoch and return the reduced value from
  // the latest epoch in this bucket.
  std::map<uint64_t, std::pair<T, uint64_t>> epoch_to_value;
  uint64_t latest_epoch = 0;

  for (int i = 0; i < nvalues; i++) {
    const uint8_t *val = values.data() + (i * tseries_struct_sz);
    auto meta = read_data<uint64_t>(val + meta_off);
    auto epoch = read_data<uint64_t>(val + epoch_off);

    if (epoch == 0) {
      // Don't consider buckets where epoch is 0. This means it was never used.
      continue;
    }

    latest_epoch = std::max(epoch, latest_epoch);

    if (epoch_to_value.find(epoch) == epoch_to_value.end()) {
      epoch_to_value[epoch] = std::pair<T, uint64_t>(read_data<T>(val), meta);

      continue;
    }

    std::pair<T, uint64_t> &current = epoch_to_value[epoch];

    switch (agg) {
      case TSeriesAggFunc::none:
        // If no aggregation function is specified, the most recently assigned
        // value wins. Use the timestamp to decide which is the most recent
        // value.
        if (meta > current.second) {
          current.first = read_data<T>(val);
          current.second = meta;
        }
        break;
      case TSeriesAggFunc::avg: {
        T sum_val = read_data<T>(val);

        current.first += sum_val;
        current.second += meta;
      } break;
      case TSeriesAggFunc::max:
      case TSeriesAggFunc::min: {
        T mm_val = read_data<T>(val);

        if (agg == TSeriesAggFunc::min) {
          current.first = std::min(current.first, mm_val);
        } else {
          current.first = std::max(current.first, mm_val);
        }
      } break;
      case TSeriesAggFunc::sum:
        current.first += read_data<T>(val);
        break;
    }
  }

  if (latest_epoch == 0) {
    return std::pair<T, uint64_t>(0, 0);
  }

  std::pair<T, uint64_t> &latest = epoch_to_value[latest_epoch];
  if (agg == TSeriesAggFunc::avg) {
    latest.first = static_cast<T>(latest.first / latest.second);
  }

  latest.second = latest_epoch;

  return latest;
}

std::pair<std::vector<uint8_t>, uint64_t> reduce_tseries_value(
    const std::vector<uint8_t> &values,
    int nvalues,
    const SizedType &value_type,
    TSeriesAggFunc agg)
{
  std::pair<std::vector<uint8_t>, uint64_t> result(
      std::vector<uint8_t>(sizeof(uint64_t)), 0);

  if (value_type.IsSigned()) {
    auto v = reduce_tseries_value<int64_t>(values, nvalues, agg);
    std::memcpy(result.first.data(), &v.first, sizeof(int64_t));
    result.second = v.second;
  } else {
    auto v = reduce_tseries_value<uint64_t>(values, nvalues, agg);
    std::memcpy(result.first.data(), &v.first, sizeof(uint64_t));
    result.second = v.second;
  }

  return result;
}

} // namespace bpftrace::util
