#include "output.h"
#include "bpftrace.h"
#include "log.h"
#include "utils.h"
#include <async_event_types.h>

namespace bpftrace {

namespace {
bool is_quoted_type(const SizedType &ty)
{
  return ty.IsKstackTy() || ty.IsUstackTy() || ty.IsKsymTy() || ty.IsUsymTy() ||
         ty.IsInetTy() || ty.IsUsernameTy() || ty.IsStringTy() ||
         ty.IsBufferTy() || ty.IsProbeTy();
}
} // namespace

std::ostream& operator<<(std::ostream& out, MessageType type) {
  switch (type) {
    case MessageType::map: out << "map"; break;
    case MessageType::value:
      out << "value";
      break;
    case MessageType::hist: out << "hist"; break;
    case MessageType::stats: out << "stats"; break;
    case MessageType::printf: out << "printf"; break;
    case MessageType::time: out << "time"; break;
    case MessageType::cat: out << "cat"; break;
    case MessageType::join: out << "join"; break;
    case MessageType::syscall: out << "syscall"; break;
    case MessageType::attached_probes: out << "attached_probes"; break;
    case MessageType::lost_events: out << "lost_events"; break;
    default: out << "?";
  }
  return out;
}

std::string TextOutput::hist_index_label(int power)
{
  char suffix = '\0';
  if (power >= 40)
  {
    suffix = 'T';
    power -= 40;
  }
  else if (power >= 30)
  {
    suffix = 'G';
    power -= 30;
  }
  else if (power >= 20)
  {
    suffix = 'M';
    power -= 20;
  }
  else if (power >= 10)
  {
    suffix = 'K';
    power -= 10;
  }

  std::ostringstream label;
  label << (1<<power);
  if (suffix)
    label << suffix;
  return label.str();
}

std::string TextOutput::lhist_index_label(int number)
{
  int kilo = 1024;
  int mega = 1048576;

  std::ostringstream label;

  if (number == 0)
  {
    label << number;
  }
  else if (number % mega == 0)
  {
    label << number / mega << 'M';
  }
  else if (number % kilo == 0)
  {
    label << number / kilo << 'K';
  }
  else
  {
    label << number;
  }

  return label.str();
}

void Output::hist_prepare(const std::vector<uint64_t> &values, int &min_index, int &max_index, int &max_value) const
{
  min_index = -1;
  max_index = -1;
  max_value = 0;

  for (size_t i = 0; i < values.size(); i++)
  {
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

void Output::lhist_prepare(const std::vector<uint64_t> &values, int min, int max, int step, int &max_index, int &max_value, int &buckets, int &start_value, int &end_value) const
{
  max_index = -1;
  max_value = 0;
  buckets = (max - min) / step; // excluding lt and gt buckets

  for (size_t i = 0; i < values.size(); i++)
  {
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

  for (unsigned int i = 0; i <= static_cast<unsigned int>(buckets) + 1; i++)
  {
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

std::string Output::value_to_str(BPFtrace &bpftrace,
                                 const SizedType &type,
                                 std::vector<uint8_t> &value,
                                 bool is_per_cpu,
                                 uint32_t div) const
{
  uint32_t nvalues = is_per_cpu ? bpftrace.ncpus_ : 1;
  if (type.IsKstackTy())
    return bpftrace.get_stack(
        read_data<uint64_t>(value.data()), false, type.stack_type, 8);
  else if (type.IsUstackTy())
    return bpftrace.get_stack(
        read_data<uint64_t>(value.data()), true, type.stack_type, 8);
  else if (type.IsKsymTy())
    return bpftrace.resolve_ksym(read_data<uintptr_t>(value.data()));
  else if (type.IsUsymTy())
    return bpftrace.resolve_usym(read_data<uintptr_t>(value.data()),
                                 read_data<uintptr_t>(value.data() + 8));
  else if (type.IsInetTy())
    return bpftrace.resolve_inet(read_data<uint64_t>(value.data()),
                                 (uint8_t *)(value.data() + 8));
  else if (type.IsUsernameTy())
    return bpftrace.resolve_uid(read_data<uint64_t>(value.data()));
  else if (type.IsBufferTy())
    return bpftrace.resolve_buf(reinterpret_cast<char *>(value.data() + 1),
                                *reinterpret_cast<uint8_t *>(value.data()));
  else if (type.IsStringTy())
  {
    auto p = reinterpret_cast<const char *>(value.data());
    return std::string(p, strnlen(p, type.GetSize()));
  }
  else if (type.IsArrayTy())
  {
    size_t elem_size = type.GetElementTy()->GetSize();
    std::vector<std::string> elems;
    for (size_t i = 0; i < type.GetNumElements(); i++)
    {
      std::vector<uint8_t> elem_data(value.begin() + i * elem_size,
                                     value.begin() + (i + 1) * elem_size);
      elems.push_back(value_to_str(
          bpftrace, *type.GetElementTy(), elem_data, is_per_cpu, div));
    }
    return array_to_str(elems);
  }
  else if (type.IsRecordTy())
  {
    std::vector<std::string> elems;
    for (auto &field : type.GetFields())
    {
      std::vector<uint8_t> elem_data(value.begin() + field.offset,
                                     value.begin() + field.offset +
                                         field.type.GetSize());
      elems.push_back(field_to_str(
          field.name,
          value_to_str(bpftrace, field.type, elem_data, is_per_cpu, div)));
    }
    return struct_to_str(elems);
  }
  else if (type.IsTupleTy())
  {
    std::vector<std::string> elems;
    for (auto &field : type.GetFields())
    {
      std::vector<uint8_t> elem_data(value.begin() + field.offset,
                                     value.begin() + field.offset +
                                         field.type.GetSize());
      elems.push_back(
          value_to_str(bpftrace, field.type, elem_data, is_per_cpu, div));
    }
    return tuple_to_str(elems);
  }
  else if (type.IsCountTy())
    return std::to_string(reduce_value<uint64_t>(value, nvalues) / div);
  else if (type.IsIntTy())
  {
    auto sign = type.IsSigned();
    switch (type.GetIntBitWidth())
    {
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
        LOG(FATAL) << "value_to_str: Invalid int bitwidth: "
                   << type.GetIntBitWidth() << "provided";
        return {};
    }
    // lgtm[cpp/missing-return]
  }
  else if (type.IsSumTy() || type.IsIntTy())
  {
    if (type.IsSigned())
      return std::to_string(reduce_value<int64_t>(value, nvalues) / div);

    return std::to_string(reduce_value<uint64_t>(value, nvalues) / div);
  }
  else if (type.IsMinTy())
    return std::to_string(min_value(value, nvalues) / div);
  else if (type.IsMaxTy())
    return std::to_string(max_value(value, nvalues) / div);
  else if (type.IsProbeTy())
    return bpftrace.resolve_probe(read_data<uint64_t>(value.data()));
  else if (type.IsTimestampTy())
    return bpftrace.resolve_timestamp(
        reinterpret_cast<AsyncEvent::Strftime *>(value.data())->strftime_id,
        reinterpret_cast<AsyncEvent::Strftime *>(value.data())
            ->nsecs_since_boot);
  else if (type.IsMacAddressTy())
    return bpftrace.resolve_mac_address(value.data());
  else
    return std::to_string(read_data<int64_t>(value.data()) / div);
}

std::string Output::array_to_str(const std::vector<std::string> &elems) const
{
  return "[" + str_join(elems, ",") + "]";
}

std::string Output::struct_to_str(const std::vector<std::string> &elems) const
{
  return "{ " + str_join(elems, ", ") + " }";
}

std::string Output::map_to_str(
    BPFtrace &bpftrace,
    IMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key) const
{
  std::vector<std::string> elems;
  uint32_t i = 0;
  size_t total = values_by_key.size();
  for (auto &pair : values_by_key)
  {
    auto key = pair.first;
    auto value = pair.second;

    if (top)
    {
      if (total > top && i++ < (total - top))
        continue;
    }

    auto key_str = map_key_to_str(bpftrace, map, key);
    auto value_str = value_to_str(
        bpftrace, map.type_, value, map.is_per_cpu_type(), div);
    elems.push_back(map_keyval_to_str(map, key_str, value_str));
  }

  return str_join(elems, map_elem_delim_to_str(map));
}

std::string Output::map_hist_to_str(
    BPFtrace &bpftrace,
    IMap &map,
    uint32_t top,
    uint32_t div,
    const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
    const std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
        &total_counts_by_key) const
{
  std::vector<std::string> elems;
  uint32_t i = 0;
  for (auto &key_count : total_counts_by_key)
  {
    auto &key = key_count.first;
    auto &value = values_by_key.at(key);

    if (top && values_by_key.size() > top && i++ < (values_by_key.size() - top))
      continue;

    auto key_str = map_key_to_str(bpftrace, map, key);
    auto val_str = map.type_.IsHistTy()
                       ? hist_to_str(value, div)
                       : lhist_to_str(value, map.lqmin, map.lqmax, map.lqstep);

    elems.push_back(map_keyval_to_str(map, key_str, val_str));
  }
  return str_join(elems, map_elem_delim_to_str(map));
}

std::string Output::map_stats_to_str(
    BPFtrace &bpftrace,
    IMap &map,
    uint32_t top,
    uint32_t div,
    const std::map<std::vector<uint8_t>, std::vector<int64_t>> &values_by_key,
    const std::vector<std::pair<std::vector<uint8_t>, int64_t>>
        &total_counts_by_key) const
{
  std::vector<std::string> elems;
  uint32_t i = 0;
  for (auto &key_count : total_counts_by_key)
  {
    auto &key = key_count.first;
    auto &value = values_by_key.at(key);

    if (map.type_.IsAvgTy() && top && values_by_key.size() > top &&
        i++ < (values_by_key.size() - top))
      continue;

    auto key_str = map_key_to_str(bpftrace, map, key);

    int64_t count = (int64_t)value.at(0);
    int64_t total = value.at(1);
    int64_t average = 0;

    if (count != 0)
      average = total / count;

    std::string value_str;
    if (map.type_.IsStatsTy())
    {
      std::vector<std::pair<std::string, int64_t>> stats = {
        { "count", count }, { "average", average }, { "total", total }
      };
      value_str = key_value_pairs_to_str(stats);
    }
    else
      value_str = std::to_string(average / div);

    elems.push_back(map_keyval_to_str(map, key_str, value_str));
  }

  return str_join(elems, map_elem_delim_to_str(map));
}

void TextOutput::map(
    BPFtrace &bpftrace,
    IMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key) const
{
  out_ << map_to_str(bpftrace, map, top, div, values_by_key);
  out_ << std::endl;
}

std::string TextOutput::hist_to_str(const std::vector<uint64_t> &values,
                                    uint32_t div) const
{
  int min_index, max_index, max_value;
  hist_prepare(values, min_index, max_index, max_value);
  if (max_index == -1)
    return "";

  std::ostringstream res;
  for (int i = min_index; i <= max_index; i++)
  {
    std::ostringstream header;
    if (i == 0)
    {
      header << "(..., 0)";
    }
    else if (i == 1)
    {
      header << "[0]";
    }
    else if (i == 2)
    {
      header << "[1]";
    }
    else
    {
      header << "[" << hist_index_label(i-2);
      header << ", " << hist_index_label(i-2+1) << ")";
    }

    int max_width = 52;
    int bar_width = values.at(i)/(float)max_value*max_width;
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
  lhist_prepare(values, min, max, step, max_index, max_value, buckets, start_value, end_value);
  if (max_index == -1)
    return "";

  std::ostringstream res;
  for (int i = start_value; i <= end_value; i++)
  {
    int max_width = 52;
    int bar_width = values.at(i)/(float)max_value*max_width;
    std::ostringstream header;
    if (i == 0) {
      header << "(..., " << lhist_index_label(min) << ")";
    } else if (i == (buckets + 1)) {
      header << "[" << lhist_index_label(max) << ", ...)";
    } else {
      header << "[" << lhist_index_label((i - 1) * step + min);
      header << ", " << lhist_index_label(i * step + min) << ")";
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
    IMap &map,
    uint32_t top,
    uint32_t div,
    const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
    const std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
        &total_counts_by_key) const
{
  out_ << map_hist_to_str(
      bpftrace, map, top, div, values_by_key, total_counts_by_key);
  out_ << std::endl;
}

void TextOutput::map_stats(
    BPFtrace &bpftrace,
    IMap &map,
    uint32_t top,
    uint32_t div,
    const std::map<std::vector<uint8_t>, std::vector<int64_t>> &values_by_key,
    const std::vector<std::pair<std::vector<uint8_t>, int64_t>>
        &total_counts_by_key) const
{
  out_ << map_stats_to_str(
      bpftrace, map, top, div, values_by_key, total_counts_by_key);
  out_ << std::endl << std::endl;
}

void TextOutput::value(BPFtrace &bpftrace,
                       const SizedType &ty,
                       std::vector<uint8_t> &value) const
{
  out_ << value_to_str(bpftrace, ty, value, false, 1) << std::endl;
}

void TextOutput::message(MessageType type __attribute__((unused)), const std::string& msg, bool nl) const
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
                                       IMap &map,
                                       const std::vector<uint8_t> &key) const
{
  return map.name_ + map.key_.argument_value_list_str(bpftrace, key);
}

std::string TextOutput::map_keyval_to_str(IMap &map,
                                          const std::string &key,
                                          const std::string &val) const
{
  std::string res = key + ": ";
  if (map.type_.IsHistTy() || map.type_.IsLhistTy())
    res += "\n";
  res += val;
  return res;
}

std::string TextOutput::map_elem_delim_to_str(IMap &map) const
{
  if (map.type_.type != Type::kstack && map.type_.type != Type::ustack &&
      map.type_.type != Type::ksym && map.type_.type != Type::usym &&
      map.type_.type != Type::inet)
    return "\n";

  return "";
}

std::string TextOutput::key_value_pairs_to_str(
    std::vector<std::pair<std::string, int64_t>> &keyvals) const
{
  std::vector<std::string> elems;
  for (auto &e : keyvals)
    elems.push_back(e.first + " " + std::to_string(e.second));
  return str_join(elems, ", ");
}

std::string JsonOutput::json_escape(const std::string &str) const
{
  std::ostringstream escaped;
  for (const char &c : str)
  {
    switch (c)
    {
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
        if ('\x00' <= c && c <= '\x1f') {
          escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
        } else {
          escaped << c;
        }
    }
  }
  return escaped.str();
}

void JsonOutput::map(
    BPFtrace &bpftrace,
    IMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key) const
{
  if (values_by_key.empty())
    return;

  out_ << "{\"type\": \"" << MessageType::map << "\", \"data\": {";
  out_ << "\"" << json_escape(map.name_) << "\": ";
  if (map.key_.size() > 0) // check if this map has keys
    out_ << "{";

  out_ << map_to_str(bpftrace, map, top, div, values_by_key);

  if (map.key_.size() > 0)
    out_ << "}";
  out_ << "}}" << std::endl;
}

std::string JsonOutput::hist_to_str(const std::vector<uint64_t> &values,
                                    uint32_t div) const
{
  int min_index, max_index, max_value;
  hist_prepare(values, min_index, max_index, max_value);
  if (max_index == -1)
    return "";

  std::ostringstream res;
  res << "[";
  for (int i = min_index; i <= max_index; i++)
  {
    if (i > min_index)
      res << ", ";

    res << "{";
    if (i == 0)
    {
      res << "\"max\": -1, ";
    }
    else if (i == 1)
    {
      res << "\"min\": 0, \"max\": 0, ";
    }
    else if (i == 2)
    {
      res << "\"min\": 1, \"max\": 1, ";
    }
    else
    {
      long low = 1 << (i-2);
      long high = (1 << (i-2+1)) - 1;
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
  lhist_prepare(values, min, max, step, max_index, max_value, buckets, start_value, end_value);
  if (max_index == -1)
    return "";

  std::ostringstream res;
  res << "[";
  for (int i = start_value; i <= end_value; i++)
  {
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
    IMap &map,
    uint32_t top,
    uint32_t div,
    const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
    const std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
        &total_counts_by_key) const
{
  if (total_counts_by_key.empty())
    return;

  out_ << "{\"type\": \"" << MessageType::hist << "\", \"data\": {";
  out_ << "\"" << json_escape(map.name_) << "\": ";
  if (map.key_.size() > 0) // check if this map has keys
    out_ << "{";

  out_ << map_hist_to_str(
      bpftrace, map, top, div, values_by_key, total_counts_by_key);

  if (map.key_.size() > 0)
    out_ << "}";
  out_ << "}}" << std::endl;
}

void JsonOutput::map_stats(
    BPFtrace &bpftrace,
    IMap &map,
    uint32_t top,
    uint32_t div,
    const std::map<std::vector<uint8_t>, std::vector<int64_t>> &values_by_key,
    const std::vector<std::pair<std::vector<uint8_t>, int64_t>>
        &total_counts_by_key) const
{
  if (total_counts_by_key.empty())
    return;

  out_ << "{\"type\": \"" << MessageType::stats << "\", \"data\": {";
  out_ << "\"" << json_escape(map.name_) << "\": ";
  if (map.key_.size() > 0) // check if this map has keys
    out_ << "{";

  out_ << map_stats_to_str(
      bpftrace, map, top, div, values_by_key, total_counts_by_key);

  if (map.key_.size() > 0)
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

void JsonOutput::message(MessageType type, const std::string& msg, bool nl __attribute__((unused))) const
{
  out_ << "{\"type\": \"" << type << "\", \"data\": \"" << json_escape(msg) << "\"}" << std::endl;
}

void JsonOutput::message(MessageType type, const std::string& field, uint64_t value) const
{
  out_ << "{\"type\": \"" << type << "\", \"data\": " <<  "{\"" << field
       << "\": " << value << "}" << "}" << std::endl;
}

void JsonOutput::lost_events(uint64_t lost) const
{
  message(MessageType::lost_events, "events", lost);
}

void JsonOutput::attached_probes(uint64_t num_probes) const
{
  message(MessageType::attached_probes, "probes", num_probes);
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
                                       IMap &map,
                                       const std::vector<uint8_t> &key) const
{
  std::vector<std::string> args = map.key_.argument_value_list(bpftrace, key);
  if (!args.empty())
  {
    return "\"" + json_escape(str_join(args, ",")) + "\"";
  }
  return "";
}

std::string JsonOutput::map_keyval_to_str(IMap &map __attribute__((unused)),
                                          const std::string &key,
                                          const std::string &val) const
{
  return key.empty() ? val : key + ": " + val;
}

std::string JsonOutput::map_elem_delim_to_str(IMap &map
                                              __attribute__((unused))) const
{
  return ", ";
}

std::string JsonOutput::key_value_pairs_to_str(
    std::vector<std::pair<std::string, int64_t>> &keyvals) const
{
  std::vector<std::string> elems;
  for (auto &e : keyvals)
    elems.push_back("\"" + e.first + "\": " + std::to_string(e.second));
  return "{" + str_join(elems, ", ") + "}";
}

} // namespace bpftrace
