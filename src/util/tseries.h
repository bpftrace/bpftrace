#pragma once

#include <cstring>

#include "bpfmap.h"
#include "types.h"
#include "util/opaque.h"

namespace bpftrace::util {

std::pair<uint64_t, OpaqueValue> reduce_tseries_value(
    const OpaqueValue &value,
    const SizedType &value_type,
    TSeriesAggFunc agg);

} // namespace bpftrace::util
