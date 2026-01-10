#include <algorithm>
#include <string>
#include <utility>

#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "log.h"
#include "required_resources.h"
#include "types_format.h"
#include "util/stats.h"

namespace bpftrace {

char TypeFormatError::ID;

void TypeFormatError::log(llvm::raw_ostream &OS) const
{
  OS << "unable to convert type: " << typestr(ty_);
}

std::string format_build_id_stack(uint64_t nr_stack_frames,
                                  const OpaqueValue &raw_stack)
{
  std::ostringstream stack;

  stack << "\n";
  for (uint64_t i = 0; i < nr_stack_frames; ++i) {
    auto build_id_struct = raw_stack.bitcast<bpf_stack_build_id>(i);
    if (build_id_struct.status == 1) {
      // Format build_id as a continuous hex string
      stack << std::hex << std::setfill('0');
      for (unsigned char j : build_id_struct.build_id) {
        stack << std::setw(2) << static_cast<unsigned int>(j);
      }
      stack << std::dec << " " << "0x" << std::setfill('0') << std::setw(2)
            << std::hex << build_id_struct.offset << std::dec << std::endl;
    } else {
      stack << std::hex << build_id_struct.ip << std::dec << std::endl;
    }
  }

  return stack.str();
}

Result<output::Primitive> format(BPFtrace &bpftrace,
                                 const ast::CDefinitions &c_definitions,
                                 const SizedType &type,
                                 const OpaqueValue &value,
                                 uint32_t div)
{
  switch (type.GetTy()) {
    case Type::timestamp_mode:
    case Type::hist_t:
    case Type::lhist_t:
    case Type::tseries_t:
      // These should never come in this way.
      return make_error<TypeFormatError>(type);
    case Type::none:
    case Type::voidtype:
      return std::monostate{};
    case Type::boolean:
      return value.bitcast<uint8_t>() != 0;
    case Type::pointer: {
      // Print a pointer as a clear hex value. This could optionally include
      // the type or other information, but for now leave the existing format
      // as is. We encode this as a symbolic value because the JSON backend
      // will emit the raw number as a numeric value explicitly.
      auto n = value.bitcast<uint64_t>();
      std::ostringstream res;
      res << "0x" << std::hex << n;
      return output::Primitive::Symbolic(res.str(), n);
    }
    case Type::kstack_t: {
      auto num_frames = value.bitcast<uint64_t>(0);
      auto limit = type.stack_type.limit;
      constexpr size_t stack_offset = sizeof(uint64_t);
      auto len = static_cast<size_t>(type.stack_type.elem_size() * limit);
      const auto raw_stack = value.slice(stack_offset, len);

      return bpftrace.get_stack(
          num_frames, raw_stack, -1, -1, false, type.stack_type, 8);
    }
    case Type::ustack_t: {
      auto pid = value.bitcast<int32_t>(0);
      auto probe_id = value.bitcast<int32_t>(1);
      auto num_frames =
          value.slice(sizeof(uint64_t), sizeof(uint64_t)).bitcast<uint64_t>(0);
      auto limit = type.stack_type.limit;
      constexpr size_t stack_offset = sizeof(uint64_t) * 2;

      auto len = static_cast<size_t>(type.stack_type.elem_size() * limit);
      const auto raw_stack = value.slice(stack_offset, len);

      if (type.stack_type.mode == StackMode::build_id) {
        return format_build_id_stack(num_frames, raw_stack);
      }

      return bpftrace.get_stack(
          num_frames, raw_stack, pid, probe_id, true, type.stack_type, 8);
    }
    case Type::ksym_t: {
      return bpftrace.resolve_ksym(value.bitcast<uint64_t>());
    }
    case Type::usym_t: {
      return bpftrace.resolve_usym(value.bitcast<uint64_t>(),
                                   value.slice(8, 4).bitcast<int32_t>(),
                                   value.slice(12, 4).bitcast<int32_t>());
    }
    case Type::inet: {
      return bpftrace.resolve_inet(value.bitcast<uint64_t>(),
                                   value.slice(8).data());
    }
    case Type::username: {
      return bpftrace.resolve_uid(value.bitcast<uint64_t>());
    }
    case Type::buffer: {
      auto buf = value.bitcast<AsyncEvent::Buf>();
      size_t length = buf.length;
      output::Primitive::Buffer v;
      v.data.resize(buf.length);
      const auto *content = value.slice(sizeof(AsyncEvent::Buf), length).data();
      memcpy(v.data.data(), content, length);
      return v;
    }
    case Type::string: {
      const char *p = value.data();
      std::string s(p, strnlen(p, type.GetSize()));
      // Add a trailer if string is truncated
      //
      // The heuristic we use is to check if the string exactly fits inside the
      // buffer (NUL included). If it does, we assume it was truncated. This is
      // a valid mechanism, with the string being "well-formed" essentially the
      // signal that it was not truncated.
      if (type.GetSize() == s.size()) {
        s += bpftrace.config_->str_trunc_trailer;
      }
      return s;
    }
    case Type::array: {
      size_t elem_size = type.GetElementTy()->GetSize();
      output::Primitive::Array array;
      for (size_t i = 0; i < type.GetNumElements(); i++) {
        auto elem_data = value.slice(i * elem_size, elem_size);
        auto val = format(
            bpftrace, c_definitions, *type.GetElementTy(), elem_data, div);
        if (!val) {
          return val.takeError();
        }
        array.values.emplace_back(std::move(*val));
      }
      return array;
    }
    case Type::record: {
      output::Primitive::Record record;
      for (auto &field : type.GetFields()) {
        auto elem_data = value.slice(field.offset, field.type.GetSize());
        auto val = format(bpftrace, c_definitions, field.type, elem_data, div);
        if (!val) {
          return val.takeError();
        }
        record.fields.emplace_back(field.name, std::move(*val));
      }
      return record;
    }
    case Type::tuple: {
      output::Primitive::Tuple tuple;
      for (auto &field : type.GetFields()) {
        auto elem_data = value.slice(field.offset, field.type.GetSize());
        auto val = format(bpftrace, c_definitions, field.type, elem_data, div);
        if (!val) {
          return val.takeError();
        }
        tuple.values.emplace_back(std::move(*val));
      }
      return tuple;
    }
    case Type::count_t: {
      return util::reduce_value<uint64_t>(value) / div;
    }
    case Type::integer: {
      if (type.IsEnumTy()) {
        const auto &enum_name = type.GetName();
        uint64_t enum_val;
        switch (type.GetIntBitWidth()) {
          case 64:
            enum_val = value.bitcast<uint64_t>();
            break;
          case 32:
            enum_val = value.bitcast<uint32_t>();
            break;
          case 16:
            enum_val = value.bitcast<uint16_t>();
            break;
          case 8:
            enum_val = value.bitcast<uint8_t>();
            break;
          default:
            return make_error<TypeFormatError>(type);
        }

        auto it = c_definitions.enum_defs.find(enum_name);
        if (it != c_definitions.enum_defs.end()) {
          auto val_it = it->second.find(enum_val);
          if (val_it != it->second.end()) {
            return output::Primitive::Symbolic(val_it->second, enum_val);
          }
        }
        // Fall back to something comprehensible in case user somehow
        // tricked the type system into accepting an invalid enum.
        return output::Primitive::Symbolic(std::to_string(enum_val), enum_val);
      }
      auto sign = type.IsSigned();
      switch (type.GetIntBitWidth()) {
          // clang-format off
          case 64:
            if (sign)
              return util::reduce_value<int64_t>(value) / static_cast<int64_t>(div);
            return util::reduce_value<uint64_t>(value) / div;
          case 32:
            if (sign)
              return static_cast<int64_t>(
                  util::reduce_value<int32_t>(value) / static_cast<int32_t>(div));
            return static_cast<uint64_t>(util::reduce_value<uint32_t>(value) / div);
          case 16:
            if (sign)
              return
                  static_cast<int64_t>(util::reduce_value<int16_t>(value) / static_cast<int16_t>(div));
            return static_cast<uint64_t>(util::reduce_value<uint16_t>(value) / div);
          case 8:
            if (sign)
              return
                  static_cast<int64_t>(util::reduce_value<int8_t>(value) / static_cast<int8_t>(div));
            return static_cast<uint64_t>(util::reduce_value<uint8_t>(value) / div);
          default:
            // This type cannot be handled.
            return make_error<TypeFormatError>(type);
          // clang-format on
      }
    }
    case Type::sum_t: {
      if (type.IsSigned())
        return util::reduce_value<int64_t>(value) / div;
      return util::reduce_value<uint64_t>(value) / div;
    }
    case Type::max_t:
    case Type::min_t: {
      if (value.count<uint64_t>() == 1) {
        // See avg_t below, this may be collapsed.
        if (type.IsSigned()) {
          return value.bitcast<int64_t>() / div;
        }
        return value.bitcast<uint64_t>() / div;
      }
      if (type.IsSigned()) {
        return util::min_max_value<int64_t>(value, type.IsMaxTy()) / div;
      }
      return util::min_max_value<uint64_t>(value, type.IsMaxTy()) / div;
    }
    case Type::timestamp: {
      // Although the "type" is timestamp, it somehow comes with a format
      // string. We could optionally store just a native nsec timestamp, and
      // allow the output to choose the format. We will leave this for a future
      // type. For now this both resolves and formats the time.
      auto s = value.bitcast<const AsyncEvent::Strftime>();
      const auto ts = bpftrace.resolve_timestamp(s.mode, s.nsecs);
      return bpftrace.format_timestamp(ts, s.strftime_id);
    }
    case Type::mac_address: {
      return bpftrace.resolve_mac_address(value.data());
    }
    case Type::cgroup_path_t: {
      auto c = value.bitcast<const AsyncEvent::CgroupPath>();
      return bpftrace.resolve_cgroup_path(c.cgroup_path_id, c.cgroup_id);
    }
    case Type::avg_t:
    case Type::stats_t: {
      if (type.IsAvgTy() && value.count<uint64_t>() == 1) {
        // on this code path, avg is calculated in the kernel while printing the
        // entire map is handled in a different function.
        if (type.IsSigned()) {
          return value.bitcast<int64_t>() / div;
        }
        return value.bitcast<uint64_t>() / div;
      }
      std::optional<output::Primitive> average, total, count;
      if (type.IsSigned()) {
        auto stats = util::stats_value<int64_t>(value);
        average.emplace(stats.avg / div);
        total.emplace(stats.total);
        count.emplace(stats.count);
      } else {
        auto stats = util::stats_value<uint64_t>(value);
        average.emplace(stats.avg / div);
        total.emplace(stats.total);
        count.emplace(stats.count);
      }
      if (type.IsStatsTy()) {
        output::Primitive::Record vals;
        vals.fields.emplace_back("count", std::move(*count));
        vals.fields.emplace_back("average", std::move(*average));
        vals.fields.emplace_back("total", std::move(*total));
        return vals;
      } else {
        return std::move(*average);
      }
    }
  }
  return make_error<TypeFormatError>(type);
}

// Translate the index into the starting value for the corresponding interval.
// Each power of 2 is mapped into N = 2**k intervals, each of size
// S = 1 << ((index >> k) - 1), and starting at S * N.
// The last k bits of index indicate which interval we want.
//
// For example, if k = 2 and index = 0b11011 (27) we have:
// - N = 2**2 = 4;
// - interval size S is 1 << ((0b11011 >> 2) - 1) = 1 << (6 - 1) = 32
// - starting value is S * N = 128
// - the last 2 bits 11 indicate the third interval so the
//   starting value is 128 + 32*3 = 224
static output::Primitive hist_index_label(uint32_t index, uint32_t k)
{
  const uint32_t n = (1 << k);
  const uint32_t interval = index & (n - 1);
  assert(index >= n);
  uint32_t power = (index >> k) - 1;
  uint64_t value = (1ULL << power) * (n + interval);

  // Choose the suffix for the largest power of 2^10
  const uint32_t decade = power / 10;
  const char suffix = "\0KMGTPE"[decade];
  power -= 10 * decade;

  std::ostringstream label;
  label << (1ULL << power) * (n + interval);
  if (suffix)
    label << suffix;
  return output::Primitive::Symbolic(label.str(), value);
}

static std::pair<int, int> indices(const std::vector<uint64_t> &values)
{
  int min_index = -1;
  int max_index = -1;
  for (size_t i = 0; i < values.size(); i++) {
    int v = values.at(i);
    if (v > 0) {
      if (min_index == -1)
        min_index = i;
      max_index = i;
    }
  }
  return { min_index, max_index };
}

static output::Value::Histogram build_histogram(
    const std::vector<uint64_t> &values,
    uint32_t div,
    uint32_t k)
{
  output::Value::Histogram hist;
  auto [min_index, max_index] = indices(values);
  if (min_index == -1) {
    return hist;
  }
  if (min_index != 0) {
    if (min_index - 1 <= (2 << k)) {
      hist.lower_bound = min_index - 1;
    } else {
      hist.lower_bound = hist_index_label(min_index - 1, k);
    }
  }

  for (int i = min_index; i <= max_index; i++) {
    // Index 0 is for negative values. Following that, each sequence
    // of N = 1 << k indexes represents one power of 2.
    // In particular:
    // - the first set of N indexes is for values 0..N-1
    //   (one value per index)
    // - the second and following sets of N indexes each contain
    //   <1, 2, 4 .. and subsequent powers of 2> values per index.
    //
    // Since the first and second set are closed intervals and the value
    // of each interval equals "index - 1", we print it directly.
    // Higher indexes contain multiple values and we use helpers to print
    // the range as open intervals.
    if (i == 0) {
      hist.labels.emplace_back(0);
    } else if (i <= (2 << k)) {
      hist.labels.emplace_back(i);
    } else {
      hist.labels.push_back(hist_index_label(i, k));
    }
    hist.counts.push_back(values.at(i) / div);
  }
  return hist;
}

static output::Primitive lhist_index_label(int number, int step)
{
  constexpr int kilo = 1024;
  constexpr int mega = 1024 * 1024;

  if (step % kilo != 0)
    return static_cast<int64_t>(number);

  std::ostringstream label;

  if (number == 0) {
    label << number;
  } else if (number % mega == 0) {
    label << number / mega << 'M';
  } else if (number % kilo == 0) {
    label << number / kilo << 'K';
  } else {
    label << number;
  }

  return output::Primitive::Symbolic(label.str(), number);
}

static output::Value::Histogram build_linear_histogram(
    const std::vector<uint64_t> &values,
    int min,
    int max,
    int step)
{
  output::Value::Histogram hist;
  auto [min_index, max_index] = indices(values);
  if (min_index == -1) {
    return hist;
  }
  if (min_index != 0) {
    hist.lower_bound = lhist_index_label(min + ((min_index - 1) * step), step);
  }

  for (int i = min_index; i <= max_index; i++) {
    // The final bucket represents values over the label, and we encode
    // this into the histogram structure by simply omitting the label.
    if (min + (i * step) <= max) {
      hist.labels.push_back(lhist_index_label(min + (i * step), step));
    }
    hist.counts.push_back(values.at(i));
  }
  return hist;
}

template <typename T>
void sort_by_key_type(
    std::vector<std::pair<OpaqueValue, OpaqueValue>> &values_by_key,
    size_t offset)
{
  std::ranges::stable_sort(values_by_key, [&](auto &a, auto &b) {
    return a.first.slice(offset).template bitcast<T>() <
           b.first.slice(offset).template bitcast<T>();
  });
}

void sort_by_key(
    const SizedType &key,
    std::vector<std::pair<OpaqueValue, OpaqueValue>> &values_by_key)
{
  if (key.IsTupleTy()) {
    // Sort the key arguments in reverse order so the results are sorted by
    // the first argument first, then the second, etc.
    auto &fields = key.GetFields();
    for (size_t i = key.GetFieldCount(); i-- > 0;) {
      const auto &field = fields.at(i);
      if (field.type.IsIntTy()) {
        if (field.type.GetSize() == 8) {
          sort_by_key_type<int64_t>(values_by_key, field.offset);
        } else if (field.type.GetSize() == 4) {
          sort_by_key_type<int32_t>(values_by_key, field.offset);
        } else if (field.type.GetSize() == 2) {
          sort_by_key_type<int16_t>(values_by_key, field.offset);
        } else if (field.type.GetSize() == 1) {
          sort_by_key_type<int8_t>(values_by_key, field.offset);
        } else {
          LOG(BUG)
              << "invalid integer argument size. 1, 2, 4, or 8 expected, but "
              << field.type.GetSize() << " provided";
        }
      } else if (field.type.IsStringTy()) {
        std::ranges::stable_sort(values_by_key, [&](auto &a, auto &b) {
          // This will actually do a string-like comparison between the opaque
          // value memory blocks, which is exactly what we want for a string.
          return a.first.slice(field.offset, field.type.GetSize()) <
                 b.first.slice(field.offset, field.type.GetSize());
        });
      }
    }
  } else if (key.IsIntTy()) {
    if (key.GetSize() == 8) {
      sort_by_key_type<int64_t>(values_by_key, 0);
    } else if (key.GetSize() == 4) {
      sort_by_key_type<int32_t>(values_by_key, 0);
    } else if (key.GetSize() == 2) {
      sort_by_key_type<int16_t>(values_by_key, 0);
    } else if (key.GetSize() == 1) {
      sort_by_key_type<int8_t>(values_by_key, 0);
    } else {
      LOG(BUG) << "invalid integer argument size. 1, 2, 4, or 8 expected, but "
               << key.GetSize() << " provided";
    }
  } else if (key.IsStringTy()) {
    std::ranges::stable_sort(values_by_key, [&](auto &a, auto &b) {
      return a.first < b.first; // See above.
    });
  }
}

static output::Value::TimeSeries build_time_series(
    BPFtrace &bpftrace,
    const std::map<uint64_t, output::Primitive> &values,
    const std::pair<uint64_t, uint64_t> epoch_range,
    const TSeriesArgs &args)
{
  output::Value::TimeSeries tseries;

  auto first_epoch = epoch_range.second;
  auto last_epoch = epoch_range.first;
  for (const auto &[epoch, _] : values) {
    if (epoch < epoch_range.first) {
      continue;
    }
    first_epoch = std::min(epoch, first_epoch);
    last_epoch = std::max(epoch, last_epoch);
  }
  for (auto epoch = epoch_range.first; epoch <= epoch_range.second; epoch++) {
    const auto &v = values.find(epoch);
    if (epoch >= first_epoch) {
      tseries.values.emplace_back(
          output::Primitive::Timestamp(bpftrace.resolve_timestamp(
              static_cast<uint64_t>(TimestampMode::tai),
              epoch * args.interval_ns)),
          v != values.end() ? v->second : std::monostate{});
    }
  }
  return tseries;
}

Result<output::Value> format(BPFtrace &bpftrace,
                             const ast::CDefinitions &c_definitions,
                             const BpfMap &map,
                             size_t top,
                             uint32_t div)
{
  uint32_t i = 0;
  const auto &map_info = bpftrace.resources.maps_info.at(map.name());
  const auto &key_type = map_info.key_type;
  const auto &value_type = map_info.value_type;
  uint64_t nvalues = map.is_per_cpu_type() ? bpftrace.ncpus_ : 1;
  output::Value::OrderedMap rval;

  if (value_type.IsHistTy() || value_type.IsLhistTy()) {
    // A hist-map adds an extra 8 bytes onto the end of its key for
    // storing the bucket number. e.g. A map defined as:
    //
    //  @x[1, 2] = @hist(3);
    //
    // Would actually be stored with the key:
    //  [1, 2, 3]
    auto values_by_key = map.collect_histogram_data(map_info, nvalues);
    if (!values_by_key) {
      return values_by_key.takeError();
    }

    // Sort based on sum of counts in all buckets.
    std::vector<std::pair<OpaqueValue, uint64_t>> total_counts_by_key;
    for (auto &[key, value] : *values_by_key) {
      int64_t sum = 0;
      for (unsigned long i : value) {
        sum += i;
      }
      total_counts_by_key.emplace_back(key, sum);
    }
    std::ranges::sort(total_counts_by_key,
                      [&](auto &a, auto &b) { return a.second < b.second; });
    if (div == 0) {
      div = 1;
    }

    for (const auto &[key, count] : total_counts_by_key) {
      if (top && total_counts_by_key.size() > top &&
          i++ < (total_counts_by_key.size() - top))
        continue;

      output::Value::Histogram hist;
      if (value_type.IsHistTy()) {
        if (!std::holds_alternative<HistogramArgs>(map_info.detail))
          LOG(BUG) << "call to hist with missing \"bits\" argument";
        hist = build_histogram((*values_by_key)[key],
                               div,
                               std::get<HistogramArgs>(map_info.detail).bits);
      } else {
        if (!std::holds_alternative<LinearHistogramArgs>(map_info.detail))
          LOG(BUG) << "call to lhist with missing arguments";
        const auto &args = std::get<LinearHistogramArgs>(map_info.detail);
        // N.B. div has no effect on linear histograms.
        hist = build_linear_histogram(
            (*values_by_key)[key], args.min, args.max, args.step);
      }

      // If this is a scalar map, then we just return the value.
      if (map_info.is_scalar) {
        return hist;
      }

      // Build out the value above.
      auto key_val = format(bpftrace, c_definitions, key_type, key);
      if (!key_val) {
        return key_val.takeError();
      }
      rval.values.emplace_back(std::move(*key_val), std::move(hist));
    }

    return rval;
  }

  if (value_type.IsTSeriesTy()) {
    const auto &args = std::get<TSeriesArgs>(map_info.detail);
    auto values_by_key = map.collect_tseries_data(map_info, nvalues);
    if (!values_by_key) {
      return values_by_key.takeError();
    }

    // Sort from least to most recently updated.
    std::vector<std::pair<OpaqueValue, uint64_t>> latest_epoch_by_key;
    for (const auto &tseries : *values_by_key) {
      uint64_t latest_epoch = 0;
      for (const auto &bucket : tseries.second) {
        latest_epoch = std::max(latest_epoch, bucket.first);
      }
      latest_epoch_by_key.emplace_back(tseries.first, latest_epoch);
    }
    std::ranges::sort(latest_epoch_by_key,
                      [&](auto &a, auto &b) { return a.second < b.second; });
    auto last_epoch = latest_epoch_by_key.empty()
                          ? std::numeric_limits<uint64_t>::max()
                          : latest_epoch_by_key.back().second;
    auto first_epoch = last_epoch - args.num_intervals + 1;
    auto range = std::make_pair(first_epoch, last_epoch);

    // Type for the reduction. Note that when the elements are collected
    // they have already been reduced, much like in the histogram case.
    SizedType reduced_type = args.value_type.IsSigned() ? CreateInt64()
                                                        : CreateUInt64();
    for (const auto &[key, value] : *values_by_key) {
      // Collect all the values for this specific key.
      std::map<uint64_t, output::Primitive> values;
      for (const auto &[epoch, v] : value) {
        auto p = format(bpftrace, c_definitions, reduced_type, v);
        if (!p) {
          return p.takeError();
        }
        values.emplace(epoch, std::move(*p));
      }
      auto key_res = format(bpftrace, c_definitions, key_type, key);
      if (!key_res) {
        return key_res.takeError();
      }
      auto ts = build_time_series(bpftrace, values, range, args);
      if (map_info.is_scalar) {
        return ts;
      }
      rval.values.emplace_back(std::move(*key_res), std::move(ts));
    }

    return rval;
  }

  auto values_by_key = map.collect_elements(nvalues);
  if (!values_by_key) {
    return values_by_key.takeError();
  }

  bool stats = false;
  if (value_type.IsCountTy() || value_type.IsSumTy() || value_type.IsIntTy()) {
    bool is_signed = value_type.IsSigned();
    std::ranges::sort(*values_by_key, [&](auto &a, auto &b) {
      if (is_signed)
        return util::reduce_value<int64_t>(a.second) <
               util::reduce_value<int64_t>(b.second);
      return util::reduce_value<uint64_t>(a.second) <
             util::reduce_value<uint64_t>(b.second);
    });
  } else if (value_type.IsMinTy() || value_type.IsMaxTy()) {
    std::ranges::sort(*values_by_key, [&](auto &a, auto &b) {
      return util::min_max_value<uint64_t>(a.second, value_type.IsMaxTy()) <
             util::min_max_value<uint64_t>(b.second, value_type.IsMaxTy());
    });
  } else if (value_type.IsAvgTy() || value_type.IsStatsTy()) {
    stats = true;
    if (value_type.IsSigned()) {
      std::ranges::sort(*values_by_key, [&](auto &a, auto &b) {
        return util::avg_value<int64_t>(a.second) <
               util::avg_value<int64_t>(b.second);
      });
    } else {
      std::ranges::sort(*values_by_key, [&](auto &a, auto &b) {
        return util::avg_value<uint64_t>(a.second) <
               util::avg_value<uint64_t>(b.second);
      });
    }
  } else {
    sort_by_key(map_info.key_type, *values_by_key);
  };
  if (div == 0) {
    div = 1;
  }

  // Print as a regular map.
  size_t done = 0;
  size_t total = values_by_key->size();
  for (auto &[key, value] : *values_by_key) {
    if (top && total > top && done++ < (total - top)) {
      continue;
    }

    auto val_res = format(bpftrace, c_definitions, value_type, value, div);
    if (!val_res) {
      return val_res.takeError();
    }

    if (map_info.is_scalar) {
      if (stats) {
        return output::Value(output::Value::Stats(std::move(*val_res)));
      }
      return std::move(*val_res);
    }

    auto key_res = format(bpftrace, c_definitions, key_type, key);
    if (!key_res) {
      return key_res.takeError();
    }
    rval.values.emplace_back(std::move(*key_res), std::move(*val_res));
  }

  if (stats) {
    return output::Value::Stats(std::move(rval));
  }
  return rval;
}

} // namespace bpftrace
