#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace bpftrace::util {

namespace {
template <typename T>
T read_data(const void *src)
{
  T v;
  std::memcpy(&v, src, sizeof(v));
  return v;
}
} // namespace

template <typename T>
T reduce_value(const std::vector<uint8_t> &value, int nvalues)
{
  T sum = 0;
  for (int i = 0; i < nvalues; i++) {
    sum += read_data<T>(value.data() + i * sizeof(T));
  }
  return sum;
}

template <typename T>
T min_max_value(const std::vector<uint8_t> &value, int nvalues, bool is_max)
{
  T mm_val = 0;
  bool mm_set = false;
  for (int i = 0; i < nvalues; i++) {
    T val = read_data<T>(value.data() + i * (sizeof(T) * 2));
    auto is_set = read_data<uint32_t>(value.data() + sizeof(T) +
                                      i * (sizeof(T) * 2));
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
stats<T> stats_value(const std::vector<uint8_t> &value, int nvalues)
{
  stats<T> ret = { 0, 0, 0 };
  for (int i = 0; i < nvalues; i++) {
    T val = read_data<T>(value.data() + i * (sizeof(T) * 2));
    T cpu_count = read_data<T>(value.data() + sizeof(T) + i * (sizeof(T) * 2));
    ret.count += cpu_count;
    ret.total += val;
  }
  ret.avg = static_cast<T>(ret.total / ret.count);
  return ret;
}

template <typename T>
T avg_value(const std::vector<uint8_t> &value, int nvalues)
{
  return stats_value<T>(value, nvalues).avg;
}

} // namespace bpftrace::util
