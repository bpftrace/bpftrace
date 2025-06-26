#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include "util/opaque.h"

namespace bpftrace::util {

template <typename T>
T reduce_value(const OpaqueValue &value)
{
  T sum = 0;
  for (size_t i = 0; i < value.count<T>(); i++) {
    sum += value.bitcast<T>(i);
  }
  return sum;
}

template <typename T>
T min_max_value(const OpaqueValue &value, bool is_max)
{
  T mm_val = 0;
  bool mm_set = false;
  for (size_t i = 0; i < value.count<T>() / 2; i++) {
    T val = value.bitcast<T>(i * 2);
    auto is_set = value.bitcast<T>((i * 2) + 1);
    if (!is_set) {
      continue;
    }
    if (!mm_set) {
      mm_val = val;
      mm_set = true;
    } else if (is_max && val > mm_val) {
      mm_val = val;
    } else if (!is_max && val < mm_val) {
      mm_val = val;
    }
  }
  return mm_val;
}

template <typename T>
struct stats {
  T total;
  T count;
  T avg;
};

template <typename T>
stats<T> stats_value(const OpaqueValue &value)
{
  stats<T> ret = { 0, 0, 0 };
  for (size_t i = 0; i < value.count<T>() / 2; i++) {
    T val = value.bitcast<T>(i * 2);
    T cpu_count = value.bitcast<T>((i * 2) + 1);
    ret.count += cpu_count;
    ret.total += val;
  }
  if (ret.count > 0) {
    ret.avg = static_cast<T>(ret.total / ret.count);
  }
  return ret;
}

template <typename T>
T avg_value(const OpaqueValue &value)
{
  return stats_value<T>(value).avg;
}

} // namespace bpftrace::util
