#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include "stats.h"
#include "types.h"

namespace bpftrace::util {

std::pair<std::vector<uint8_t>, uint64_t> reduce_tseries_value(
    const std::vector<uint8_t> &values,
    int nvalues,
    const SizedType &inner_type);

template <typename T>
std::pair<T, uint64_t> reduce_tseries_value(const std::vector<uint8_t> &values,
                                            int nvalues,
                                            const SizedType &inner_type)
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

    if (inner_type.IsIntegerTy()) {
      // If the inner type is simply an integer, the most recently assigned
      // value wins. Use the timestamp to decide which is the most recent
      // value.
      if (meta > current.second) {
        current.first = read_data<T>(val);
        current.second = meta;
      }
    } else if (inner_type.IsCountTy() || inner_type.IsSumTy()) {
      current.first += read_data<T>(val);
    } else if (inner_type.IsMaxTy() || inner_type.IsMinTy()) {
      T mm_val = read_data<T>(val);

      if (inner_type.IsMinTy()) {
        current.first = std::min(current.first, mm_val);
      } else if (inner_type.IsMaxTy()) {
        current.first = std::max(current.first, mm_val);
      }
    } else if (inner_type.IsAvgTy()) {
      T sum_val = read_data<T>(val);

      current.first += sum_val;
      current.second += meta;
    }
  }

  if (latest_epoch == 0) {
    return std::pair<T, uint64_t>(0, 0);
  }

  std::pair<T, uint64_t> &latest = epoch_to_value[latest_epoch];
  if (inner_type.IsAvgTy()) {
    latest.first = static_cast<T>(latest.first / latest.second);
  }

  latest.second = latest_epoch;

  return latest;
}

template <typename T>
std::pair<T, T> tseries_bounds(
    const std::map<uint64_t, std::vector<uint8_t>> &tseries,
    uint64_t first_epoch,
    uint64_t last_epoch,
    const SizedType &inner_type)
{
  std::pair<T, T> min_max(0, 0);
  bool mm_set = false;

  for (uint64_t epoch = first_epoch; epoch <= last_epoch; epoch++) {
    const auto &v = tseries.find(epoch);
    T val = 0;

    if (v != tseries.end()) {
      val = util::read_data<T>(v->second.data());
    } else if (!inner_type.IsCountTy() && !inner_type.IsSumTy()) {
      continue;
    }

    if (!mm_set) {
      mm_set = true;
      min_max.first = val;
      min_max.second = val;
      continue;
    }

    if (val < min_max.first) {
      min_max.first = val;
    }

    if (val > min_max.second) {
      min_max.second = val;
    }
  }

  return min_max;
}

uint64_t tseries_first_epoch(
    const std::map<uint64_t, std::vector<uint8_t>> &tseries,
    uint64_t last_epoch,
    uint64_t buckets);

uint64_t tseries_last_epoch(
    const std::map<std::vector<uint8_t>,
                   std::map<uint64_t, std::vector<uint8_t>>> &tseries_map);

} // namespace bpftrace::util
