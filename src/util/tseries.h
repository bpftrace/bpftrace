#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include "types.h"

namespace bpftrace::util {

std::pair<std::vector<uint8_t>, uint64_t> reduce_tseries_value(
    const std::vector<uint8_t> &values,
    int nvalues,
    const SizedType &value_type,
    TSeriesAggFunc agg);

} // namespace bpftrace::util
