#include <cstdint>
#include <cstring>
#include <vector>

#include "util/tseries.h"

namespace bpftrace::util {

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

uint64_t tseries_first_epoch(
    const std::map<uint64_t, std::vector<uint8_t>> &tseries,
    uint64_t last_epoch,
    uint64_t num_intervals)
{
  uint64_t first_epoch = 0;

  for (const auto &v : tseries) {
    const auto &epoch = v.first;

    if (epoch <= last_epoch - num_intervals) {
      continue;
    }

    if (!first_epoch || epoch < first_epoch) {
      first_epoch = epoch;
    }
  }

  return first_epoch;
}

uint64_t tseries_last_epoch(
    const std::map<std::vector<uint8_t>,
                   std::map<uint64_t, std::vector<uint8_t>>> &tseries_map)
{
  uint64_t last_epoch = 0;

  for (const auto &tseries : tseries_map) {
    for (const auto &bucket : tseries.second) {
      last_epoch = std::max(last_epoch, bucket.first);
    }
  }

  return last_epoch;
}

} // namespace bpftrace::util
