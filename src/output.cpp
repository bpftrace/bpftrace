#include "output.h"

#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "log.h"
#include "utils.h"

#include <bpf/libbpf.h>

namespace libbpf {
#define __BPF_NAME_FN(x) #x
const char *bpf_func_name[] = { __BPF_FUNC_MAPPER(__BPF_NAME_FN) };
#undef __BPF_NAME_FN
} // namespace libbpf

namespace bpftrace {

namespace {
bool is_quoted_type(const SizedType &ty)
{
  switch (ty.GetTy()) {
    case Type::buffer:
    case Type::cgroup_path:
    case Type::inet:
    case Type::kstack:
    case Type::ksym:
    case Type::probe:
    case Type::strerror:
    case Type::string:
    case Type::username:
    case Type::ustack:
    case Type::usym:
      return true;
    case Type::array:
    case Type::avg:
    case Type::count:
    case Type::hist:
    case Type::integer:
    case Type::lhist:
    case Type::mac_address:
    case Type::max:
    case Type::min:
    case Type::none:
    case Type::pointer:
    case Type::record:
    case Type::stack_mode:
    case Type::stats:
    case Type::sum:
    case Type::timestamp:
    case Type::timestamp_mode:
    case Type::tuple:
    case Type::voidtype:
      return false;
  }
  return false;
}
} // namespace

std::ostream &operator<<(std::ostream &out, MessageType type)
{
  switch (type) {
    case MessageType::map:
      out << "map";
      break;
    case MessageType::value:
      out << "value";
      break;
    case MessageType::hist:
      out << "hist";
      break;
    case MessageType::stats:
      out << "stats";
      break;
    case MessageType::printf:
      out << "printf";
      break;
    case MessageType::time:
      out << "time";
      break;
    case MessageType::cat:
      out << "cat";
      break;
    case MessageType::join:
      out << "join";
      break;
    case MessageType::syscall:
      out << "syscall";
      break;
    case MessageType::attached_probes:
      out << "attached_probes";
      break;
    case MessageType::lost_events:
      out << "lost_events";
      break;
    default:
      out << "?";
  }
  return out;
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

std::string TextOutput::hist_index_label(uint32_t index, uint32_t k)
{
  const uint32_t n = (1 << k), interval = index & (n - 1);
  assert(index >= n);
  uint32_t power = (index >> k) - 1;
  // Choose the suffix for the largest power of 2^10
  const uint32_t decade = power / 10;
  const char suffix = "\0KMGTPE"[decade];
  power -= 10 * decade;

  std::ostringstream label;
  label << (1 << power) * (n + interval);
  if (suffix)
    label << suffix;
  return label.str();
}

std::string TextOutput::lhist_index_label(int number, int step)
{
  constexpr int kilo = 1024;
  constexpr int mega = 1024 * 1024;

  if (step % kilo != 0)
    return std::to_string(number);

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

  return label.str();
}

void Output::hist_prepare(const std::vector<uint64_t> &values,
                          int &min_index,
                          int &max_index,
                          int &max_value) const
{
  min_index = -1;
  max_index = -1;
  max_value = 0;

  for (size_t i = 0; i < values.size(); i++) {
    int v = values.at(i);
    if (v > 0) {
      if (min_index == -1)
        min_index = i;
      max_index = i;
    }
    if (v > max_value)
      max_value = v;
  }
}

void Output::lhist_prepare(const std::vector<uint64_t> &values,
                           int min,
                           int max,
                           int step,
                           int &max_index,
                           int &max_value,
                           int &buckets,
                           int &start_value,
                           int &end_value) const
{
  max_index = -1;
  max_value = 0;
  buckets = (max - min) / step; // excluding lt and gt buckets

  for (size_t i = 0; i < values.size(); i++) {
    int v = values.at(i);
    if (v != 0)
      max_index = i;
    if (v > max_value)
      max_value = v;
  }

  if (max_index == -1)
    return;

  // trim empty values
  start_value = -1;
  end_value = 0;

  for (unsigned int i = 0; i <= static_cast<unsigned int>(buckets) + 1; i++) {
    if (values.at(i) > 0) {
      if (start_value == -1) {
        start_value = i;
      }
      end_value = i;
    }
  }

  if (start_value == -1) {
    start_value = 0;
  }
}

std::string Output::get_helper_error_msg(int func_id, int retcode) const
{
  std::string msg;
  if (func_id == libbpf::BPF_FUNC_map_update_elem && retcode == -E2BIG) {
    msg = "Map full; can't update element. Try increasing max_map_keys config";
  } else if (func_id == libbpf::BPF_FUNC_map_delete_elem &&
             retcode == -ENOENT) {
    msg = "Can't delete map element because it does not exist.";
  }
  // bpftrace sets the return code to 0 for map_lookup_elem failures
  // which is why we're not also checking the retcode
  else if (func_id == libbpf::BPF_FUNC_map_lookup_elem) {
    msg = "Can't lookup map element because it does not exist.";
  } else {
    msg = strerror(-retcode);
  }
  return msg;
}

std::string Output::value_to_str(BPFtrace &bpftrace,
                                 const SizedType &type,
                                 std::vector<uint8_t> &value,
                                 bool is_per_cpu,
                                 uint32_t div) const
{
  uint32_t nvalues = is_per_cpu ? bpftrace.ncpus_ : 1;
  if (type.IsKstackTy())
    return bpftrace.get_stack(read_data<uint64_t>(value.data()),
                              read_data<uint32_t>(value.data() + 8),
                              -1,
                              -1,
                              false,
                              type.stack_type,
                              8);
  else if (type.IsUstackTy())
    return bpftrace.get_stack(read_data<int64_t>(value.data()),
                              read_data<uint32_t>(value.data() + 8),
                              read_data<int32_t>(value.data() + 12),
                              read_data<int32_t>(value.data() + 16),
                              true,
                              type.stack_type,
                              8);
  else if (type.IsKsymTy())
    return bpftrace.resolve_ksym(read_data<uintptr_t>(value.data()));
  else if (type.IsUsymTy())
    return bpftrace.resolve_usym(read_data<uintptr_t>(value.data()),
                                 read_data<uintptr_t>(value.data() + 8),
                                 read_data<uint64_t>(value.data() + 16));
  else if (type.IsInetTy())
    return bpftrace.resolve_inet(read_data<uint64_t>(value.data()),
                                 (uint8_t *)(value.data() + 8));
  else if (type.IsUsernameTy())
    return bpftrace.resolve_uid(read_data<uint64_t>(value.data()));
  else if (type.IsBufferTy()) {
    return bpftrace.resolve_buf(
        reinterpret_cast<AsyncEvent::Buf *>(value.data())->content,
        reinterpret_cast<AsyncEvent::Buf *>(value.data())->length);

  } else if (type.IsStringTy()) {
    auto p = reinterpret_cast<const char *>(value.data());
    return std::string(p, strnlen(p, type.GetSize()));
  } else if (type.IsArrayTy()) {
    size_t elem_size = type.GetElementTy()->GetSize();
    std::vector<std::string> elems;
    for (size_t i = 0; i < type.GetNumElements(); i++) {
      std::vector<uint8_t> elem_data(value.begin() + i * elem_size,
                                     value.begin() + (i + 1) * elem_size);
      elems.push_back(value_to_str(
          bpftrace, *type.GetElementTy(), elem_data, is_per_cpu, div));
    }
    return array_to_str(elems);
  } else if (type.IsRecordTy()) {
    std::vector<std::string> elems;
    for (auto &field : type.GetFields()) {
      std::vector<uint8_t> elem_data(value.begin() + field.offset,
                                     value.begin() + field.offset +
                                         field.type.GetSize());
      elems.push_back(field_to_str(
          field.name,
          value_to_str(bpftrace, field.type, elem_data, is_per_cpu, div)));
    }
    return struct_to_str(elems);
  } else if (type.IsTupleTy()) {
    std::vector<std::string> elems;
    for (auto &field : type.GetFields()) {
      std::vector<uint8_t> elem_data(value.begin() + field.offset,
                                     value.begin() + field.offset +
                                         field.type.GetSize());
      elems.push_back(
          value_to_str(bpftrace, field.type, elem_data, is_per_cpu, div));
    }
    return tuple_to_str(elems);
  } else if (type.IsCountTy())
    return std::to_string(reduce_value<uint64_t>(value, nvalues) / div);
  else if (type.IsAvgTy()) {
    /*
     * on this code path, avg is calculated in the kernel while
     * printing the entire map is handled in a different function
     * which shouldn't call this
     */
    assert(!is_per_cpu);
    if (type.IsSigned()) {
      return std::to_string(read_data<int64_t>(value.data()) / div);
    }
    return std::to_string(read_data<uint64_t>(value.data()) / div);
  } else if (type.IsIntTy()) {
    auto sign = type.IsSigned();
    switch (type.GetIntBitWidth()) {
      // clang-format off
      case 64:
        if (sign)
          return std::to_string(reduce_value<int64_t>(value, nvalues) / (int64_t)div);
        return std::to_string(reduce_value<uint64_t>(value, nvalues) / div);
      case 32:
        if (sign)
          return std::to_string(
              reduce_value<int32_t>(value, nvalues) / (int32_t)div);
        return std::to_string(reduce_value<uint32_t>(value, nvalues) / div);
      case 16:
        if (sign)
          return std::to_string(
              reduce_value<int16_t>(value, nvalues) / (int16_t)div);
        return std::to_string(reduce_value<uint16_t>(value, nvalues) / div);
      case 8:
        if (sign)
          return std::to_string(
              reduce_value<int8_t>(value, nvalues) / (int8_t)div);
        return std::to_string(reduce_value<uint8_t>(value, nvalues) / div);
        // clang-format on
      default:
        LOG(BUG) << "value_to_str: Invalid int bitwidth: "
                 << type.GetIntBitWidth() << "provided";
        return {};
    }
  } else if (type.IsSumTy() || type.IsIntTy()) {
    if (type.IsSigned())
      return std::to_string(reduce_value<int64_t>(value, nvalues) / div);

    return std::to_string(reduce_value<uint64_t>(value, nvalues) / div);
  } else if (type.IsMinTy() || type.IsMaxTy()) {
    if (is_per_cpu) {
      if (type.IsSigned()) {
        return std::to_string(
            min_max_value<int64_t>(value, nvalues, type.IsMaxTy()) / div);
      }
      return std::to_string(
          min_max_value<uint64_t>(value, nvalues, type.IsMaxTy()) / div);
    }
    if (type.IsSigned()) {
      return std::to_string(read_data<int64_t>(value.data()) / div);
    }
    return std::to_string(read_data<uint64_t>(value.data()) / div);
  } else if (type.IsProbeTy())
    return bpftrace.resolve_probe(read_data<uint64_t>(value.data()));
  else if (type.IsTimestampTy())
    return bpftrace.resolve_timestamp(
        reinterpret_cast<AsyncEvent::Strftime *>(value.data())->mode,
        reinterpret_cast<AsyncEvent::Strftime *>(value.data())->strftime_id,
        reinterpret_cast<AsyncEvent::Strftime *>(value.data())->nsecs);
  else if (type.IsMacAddressTy())
    return bpftrace.resolve_mac_address(value.data());
  else if (type.IsCgroupPathTy())
    return bpftrace.resolve_cgroup_path(
        reinterpret_cast<AsyncEvent::CgroupPath *>(value.data())
            ->cgroup_path_id,
        reinterpret_cast<AsyncEvent::CgroupPath *>(value.data())->cgroup_id);
  else if (type.IsStrerrorTy())
    return strerror(read_data<uint64_t>(value.data()));
  else if (type.IsPtrTy()) {
    std::ostringstream res;
    res << "0x" << std::hex << read_data<uint64_t>(value.data());
    return res.str();
  } else {
    assert(type.IsNoneTy());
    return "";
  }
}

std::string Output::array_to_str(const std::vector<std::string> &elems) const
{
  return "[" + str_join(elems, ",") + "]";
}

std::string Output::struct_to_str(const std::vector<std::string> &elems) const
{
  return "{ " + str_join(elems, ", ") + " }";
}

void Output::map_contents(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key) const
{
  uint32_t i = 0;
  size_t total = values_by_key.size();
  const auto &map_type = bpftrace.resources.maps_info.at(map.name()).value_type;

  bool first = true;
  for (auto &pair : values_by_key) {
    auto key = pair.first;
    auto value = pair.second;

    if (top) {
      if (total > top && i++ < (total - top))
        continue;
    }

    if (first)
      first = false;
    else
      map_elem_delim(map_type);

    auto key_str = map_key_to_str(bpftrace, map, key);
    auto value_str = value_to_str(
        bpftrace, map_type, value, map.is_per_cpu_type(), div);
    map_key_val(map_type, key_str, value_str);
  }
}

void Output::map_hist_contents(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
    const std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
        &total_counts_by_key) const
{
  uint32_t i = 0;
  const auto &map_info = bpftrace.resources.maps_info.at(map.name());
  const auto &map_type = map_info.value_type;
  bool first = true;
  for (auto &key_count : total_counts_by_key) {
    auto &key = key_count.first;
    auto &value = values_by_key.at(key);

    if (top && values_by_key.size() > top && i++ < (values_by_key.size() - top))
      continue;

    if (first)
      first = false;
    else
      map_elem_delim(map_type);

    auto key_str = map_key_to_str(bpftrace, map, key);
    std::string val_str;
    if (map_type.IsHistTy()) {
      val_str = hist_to_str(value, div, *map_info.hist_bits_arg);
    } else {
      auto &args = map_info.lhist_args;
      val_str = lhist_to_str(value, args->min, args->max, args->step);
    }
    map_key_val(map_type, key_str, val_str);
  }
}

void Output::map_stats_contents(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key) const
{
  const auto &map_type = bpftrace.resources.maps_info.at(map.name()).value_type;
  uint32_t i = 0;
  size_t total = values_by_key.size();
  bool first = true;

  for (auto &[key, value] : values_by_key) {
    if (top && map_type.IsAvgTy()) {
      if (total > top && i++ < (total - top))
        continue;
    }

    if (first)
      first = false;
    else
      map_elem_delim(map_type);

    auto key_str = map_key_to_str(bpftrace, map, key);

    std::string total_str;
    std::string count_str;
    std::string avg_str;

    if (map_type.IsSigned()) {
      auto stats = stats_value<int64_t>(value, bpftrace.ncpus_);
      avg_str = std::to_string(stats.avg / div);
      total_str = std::to_string(stats.total);
      count_str = std::to_string(stats.count);
    } else {
      auto stats = stats_value<uint64_t>(value, bpftrace.ncpus_);
      avg_str = std::to_string(stats.avg / div);
      total_str = std::to_string(stats.total);
      count_str = std::to_string(stats.count);
    }

    std::string value_str;
    if (map_type.IsStatsTy()) {
      std::vector<std::pair<std::string, std::string>> stats = {
        { "count", std::move(count_str) },
        { "average", std::move(avg_str) },
        { "total", std::move(total_str) }
      };
      value_str = key_value_pairs_to_str(stats);
    } else {
      value_str = std::move(avg_str);
    }

    map_key_val(map_type, key_str, value_str);
  }
}

void TextOutput::map(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key) const
{
  map_contents(bpftrace, map, top, div, values_by_key);
  out_ << std::endl;
}

std::string TextOutput::hist_to_str(const std::vector<uint64_t> &values,
                                    uint32_t div,
                                    uint32_t k) const
{
  int min_index, max_index, max_value;
  hist_prepare(values, min_index, max_index, max_value);
  if (max_index == -1)
    return "";

  std::ostringstream res;
  for (int i = min_index; i <= max_index; i++) {
    std::ostringstream header;

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
      header << "(..., 0)";
    } else if (i <= (2 << k)) {
      header << "[" << (i - 1) << "]";
    } else {
      // Use a helper function to print the interval boundaries.
      header << "[" << hist_index_label(i - 1, k);
      header << ", " << hist_index_label(i, k) << ")";
    }

    int max_width = 52;
    int bar_width = values.at(i) / (float)max_value * max_width;
    std::string bar(bar_width, '@');

    res << std::setw(16) << std::left << header.str() << std::setw(8)
        << std::right << (values.at(i) / div) << " |" << std::setw(max_width)
        << std::left << bar << "|" << std::endl;
  }
  return res.str();
}

std::string TextOutput::lhist_to_str(const std::vector<uint64_t> &values,
                                     int min,
                                     int max,
                                     int step) const
{
  int max_index, max_value, buckets, start_value, end_value;
  lhist_prepare(values,
                min,
                max,
                step,
                max_index,
                max_value,
                buckets,
                start_value,
                end_value);
  if (max_index == -1)
    return "";

  std::ostringstream res;
  for (int i = start_value; i <= end_value; i++) {
    int max_width = 52;
    int bar_width = values.at(i) / (float)max_value * max_width;
    std::ostringstream header;
    if (i == 0) {
      header << "(..., " << lhist_index_label(min, step) << ")";
    } else if (i == (buckets + 1)) {
      header << "[" << lhist_index_label(max, step) << ", ...)";
    } else {
      header << "[" << lhist_index_label((i - 1) * step + min, step);
      header << ", " << lhist_index_label(i * step + min, step) << ")";
    }

    std::string bar(bar_width, '@');

    res << std::setw(16) << std::left << header.str() << std::setw(8)
        << std::right << values.at(i) << " |" << std::setw(max_width)
        << std::left << bar << "|" << std::endl;
  }
  return res.str();
}

void TextOutput::map_hist(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
    const std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
        &total_counts_by_key) const
{
  map_hist_contents(
      bpftrace, map, top, div, values_by_key, total_counts_by_key);
  out_ << std::endl;
}

void TextOutput::map_stats(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key) const
{
  map_stats_contents(bpftrace, map, top, div, values_by_key);
  out_ << std::endl << std::endl;
}

void TextOutput::value(BPFtrace &bpftrace,
                       const SizedType &ty,
                       std::vector<uint8_t> &value) const
{
  out_ << value_to_str(bpftrace, ty, value, false, 1) << std::endl;
}

void TextOutput::message(MessageType type __attribute__((unused)),
                         const std::string &msg,
                         bool nl) const
{
  out_ << msg;
  if (nl)
    out_ << std::endl;
}

void TextOutput::lost_events(uint64_t lost) const
{
  out_ << "Lost " << lost << " events" << std::endl;
}

void TextOutput::attached_probes(uint64_t num_probes) const
{
  if (num_probes == 1)
    out_ << "Attaching " << num_probes << " probe..." << std::endl;
  else
    out_ << "Attaching " << num_probes << " probes..." << std::endl;
}

void TextOutput::helper_error(int func_id,
                              int retcode,
                              const location &loc) const
{
  LOG(WARNING, loc, out_) << get_helper_error_msg(func_id, retcode)
                          << "\nAdditional Info - helper: "
                          << libbpf::bpf_func_name[func_id]
                          << ", retcode: " << retcode;
}

std::string TextOutput::field_to_str(const std::string &name,
                                     const std::string &value) const
{
  return "." + name + " = " + value;
}

std::string TextOutput::tuple_to_str(
    const std::vector<std::string> &elems) const
{
  return "(" + str_join(elems, ", ") + ")";
}

std::string TextOutput::map_key_to_str(BPFtrace &bpftrace,
                                       const BpfMap &map,
                                       const std::vector<uint8_t> &key) const
{
  const auto &map_key = bpftrace.resources.maps_info.at(map.name()).key;
  return map.name() + map_key.argument_value_list_str(bpftrace, key);
}

void TextOutput::map_key_val(const SizedType &map_type,
                             const std::string &key,
                             const std::string &val) const
{
  out_ << key + ": ";
  if (map_type.IsHistTy() || map_type.IsLhistTy())
    out_ << "\n";
  out_ << val;
}

void TextOutput::map_elem_delim(const SizedType &map_type) const
{
  if (!map_type.IsKstackTy() && !map_type.IsUstackTy() &&
      !map_type.IsKsymTy() && !map_type.IsUsymTy() && !map_type.IsInetTy())
    out_ << "\n";
}

std::string TextOutput::key_value_pairs_to_str(
    std::vector<std::pair<std::string, std::string>> &keyvals) const
{
  std::vector<std::string> elems;
  for (auto &e : keyvals)
    elems.push_back(e.first + " " + e.second);
  return str_join(elems, ", ");
}

std::string JsonOutput::json_escape(const std::string &str) const
{
  std::ostringstream escaped;
  for (const char &c : str) {
    switch (c) {
      case '"':
        escaped << "\\\"";
        break;

      case '\\':
        escaped << "\\\\";
        break;

      case '\n':
        escaped << "\\n";
        break;

      case '\r':
        escaped << "\\r";
        break;

      case '\t':
        escaped << "\\t";
        break;

      default:
        // c always >= '\x00'
        if (c <= '\x1f') {
          escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                  << (int)c;
        } else {
          escaped << c;
        }
    }
  }
  return escaped.str();
}

void JsonOutput::map(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key) const
{
  if (values_by_key.empty())
    return;

  const auto &map_key = bpftrace.resources.maps_info.at(map.name()).key;

  out_ << "{\"type\": \"" << MessageType::map << "\", \"data\": {";
  out_ << "\"" << json_escape(map.name()) << "\": ";
  if (map_key.size() > 0) // check if this map has keys
    out_ << "{";

  map_contents(bpftrace, map, top, div, values_by_key);

  if (map_key.size() > 0)
    out_ << "}";
  out_ << "}}" << std::endl;
}

std::string JsonOutput::hist_to_str(const std::vector<uint64_t> &values,
                                    uint32_t div,
                                    uint32_t k) const
{
  int min_index, max_index, max_value;
  hist_prepare(values, min_index, max_index, max_value);
  if (max_index == -1)
    return "[]";

  std::ostringstream res;
  res << "[";
  for (int i = min_index; i <= max_index; i++) {
    if (i > min_index)
      res << ", ";

    res << "{";
    // See description in TextOutput::hist_to_str():
    // first index is for negative values, the next 2 sets of
    // N = 2^k indexes have one value each (equal to i -1)
    // and remaining sets of N indexes each cover one power of 2,
    // whose ranges are computed as described in hist_index_label()
    if (i == 0) {
      res << "\"max\": -1, ";
    } else if (i <= (2 << k)) {
      res << "\"min\": " << i - 1 << ", \"max\": " << i - 1 << ", ";
    } else {
      const uint32_t n = 1 << k;
      uint32_t power = ((i - 1) >> k) - 1, bucket = (i - 1) & (n - 1);
      const long low = (1ULL << power) * (n + bucket);
      power = (i >> k) - 1;
      bucket = i & (n - 1);
      const long high = (1ULL << power) * (n + bucket) - 1;
      res << "\"min\": " << low << ", \"max\": " << high << ", ";
    }
    res << "\"count\": " << values.at(i) / div;
    res << "}";
  }
  res << "]";

  return res.str();
}

std::string JsonOutput::lhist_to_str(const std::vector<uint64_t> &values,
                                     int min,
                                     int max,
                                     int step) const
{
  int max_index, max_value, buckets, start_value, end_value;
  lhist_prepare(values,
                min,
                max,
                step,
                max_index,
                max_value,
                buckets,
                start_value,
                end_value);
  if (max_index == -1)
    return "[]";

  std::ostringstream res;
  res << "[";
  for (int i = start_value; i <= end_value; i++) {
    if (i > start_value)
      res << ", ";

    res << "{";
    if (i == 0) {
      res << "\"max\": " << min - 1 << ", ";
    } else if (i == (buckets + 1)) {
      res << "\"min\": " << max << ", ";
    } else {
      long low = (i - 1) * step + min;
      long high = i * step + min - 1;
      res << "\"min\": " << low << ", \"max\": " << high << ", ";
    }
    res << "\"count\": " << values.at(i);
    res << "}";
  }
  res << "]";

  return res.str();
}

void JsonOutput::map_hist(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
    const std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
        &total_counts_by_key) const
{
  if (total_counts_by_key.empty())
    return;

  const auto &map_key = bpftrace.resources.maps_info.at(map.name()).key;

  out_ << "{\"type\": \"" << MessageType::hist << "\", \"data\": {";
  out_ << "\"" << json_escape(map.name()) << "\": ";
  if (map_key.size() > 0) // check if this map has keys
    out_ << "{";

  map_hist_contents(
      bpftrace, map, top, div, values_by_key, total_counts_by_key);

  if (map_key.size() > 0)
    out_ << "}";
  out_ << "}}" << std::endl;
}

void JsonOutput::map_stats(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key) const
{
  if (values_by_key.empty())
    return;

  const auto &map_key = bpftrace.resources.maps_info.at(map.name()).key;

  out_ << "{\"type\": \"" << MessageType::stats << "\", \"data\": {";
  out_ << "\"" << json_escape(map.name()) << "\": ";
  if (map_key.size() > 0) // check if this map has keys
    out_ << "{";

  map_stats_contents(bpftrace, map, top, div, values_by_key);

  if (map_key.size() > 0)
    out_ << "}";
  out_ << "}}" << std::endl;
}

void JsonOutput::value(BPFtrace &bpftrace,
                       const SizedType &ty,
                       std::vector<uint8_t> &value) const
{
  out_ << "{\"type\": \"" << MessageType::value
       << "\", \"data\": " << value_to_str(bpftrace, ty, value, false, 1) << "}"
       << std::endl;
}

void JsonOutput::message(MessageType type,
                         const std::string &msg,
                         bool nl __attribute__((unused))) const
{
  out_ << "{\"type\": \"" << type << "\", \"data\": \"" << json_escape(msg)
       << "\"}" << std::endl;
}

void JsonOutput::message(MessageType type,
                         const std::string &field,
                         uint64_t value) const
{
  out_ << "{\"type\": \"" << type << "\", \"data\": "
       << "{\"" << field << "\": " << value << "}"
       << "}" << std::endl;
}

void JsonOutput::lost_events(uint64_t lost) const
{
  message(MessageType::lost_events, "events", lost);
}

void JsonOutput::attached_probes(uint64_t num_probes) const
{
  message(MessageType::attached_probes, "probes", num_probes);
}

void JsonOutput::helper_error(int func_id,
                              int retcode,
                              const location &loc) const
{
  out_ << "{\"type\": \"helper_error\", \"msg\": \""
       << get_helper_error_msg(func_id, retcode) << "\", \"helper\": \""
       << libbpf::bpf_func_name[func_id] << "\", \"retcode\": " << retcode
       << ", \"line\": " << loc.begin.line << ", \"col\": " << loc.begin.column
       << "}" << std::endl;
}

std::string JsonOutput::field_to_str(const std::string &name,
                                     const std::string &value) const
{
  return "\"" + name + "\": " + value;
}

std::string JsonOutput::tuple_to_str(
    const std::vector<std::string> &elems) const
{
  return "[" + str_join(elems, ",") + "]";
}

std::string JsonOutput::value_to_str(BPFtrace &bpftrace,
                                     const SizedType &type,
                                     std::vector<uint8_t> &value,
                                     bool is_per_cpu,
                                     uint32_t div) const
{
  auto str = Output::value_to_str(bpftrace, type, value, is_per_cpu, div);
  if (is_quoted_type(type))
    return "\"" + json_escape(str) + "\"";
  else
    return str;
}

std::string JsonOutput::map_key_to_str(BPFtrace &bpftrace,
                                       const BpfMap &map,
                                       const std::vector<uint8_t> &key) const
{
  const auto &map_key = bpftrace.resources.maps_info.at(map.name()).key;
  std::vector<std::string> args = map_key.argument_value_list(bpftrace, key);
  if (!args.empty()) {
    return "\"" + json_escape(str_join(args, ",")) + "\"";
  }
  return "";
}

void JsonOutput::map_key_val(const SizedType &map_type __attribute__((unused)),
                             const std::string &key,
                             const std::string &val) const
{
  out_ << (key.empty() ? val : key + ": " + val);
}

void JsonOutput::map_elem_delim(const SizedType &map
                                __attribute__((unused))) const
{
  out_ << ", ";
}

std::string JsonOutput::key_value_pairs_to_str(
    std::vector<std::pair<std::string, std::string>> &keyvals) const
{
  std::vector<std::string> elems;
  for (auto &e : keyvals)
    elems.push_back("\"" + e.first + "\": " + e.second);
  return "{" + str_join(elems, ", ") + "}";
}

} // namespace bpftrace
