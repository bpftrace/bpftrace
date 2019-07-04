#include "output.h"
#include "bpftrace.h"
#include "utils.h"

namespace bpftrace {

std::ostream& operator<<(std::ostream& out, MessageType type) {
  switch (type) {
    case MessageType::map: out << "map"; break;
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

void TextOutput::map(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                     const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &values_by_key) const
{
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

    out_ << map.name_ << map.key_.argument_value_list_str(bpftrace, key) << ": ";
    out_ << bpftrace.map_value_to_str(map, value, div);

    if (map.type_.type != Type::kstack && map.type_.type != Type::ustack &&
        map.type_.type != Type::ksym && map.type_.type != Type::usym &&
        map.type_.type != Type::inet)
      out_ << std::endl;
  }
  if (i == 0)
    out_ << std::endl;
}

void TextOutput::hist(const std::vector<uint64_t> &values, uint32_t div) const
{
  int min_index, max_index, max_value;
  hist_prepare(values, min_index, max_index, max_value);
  if (max_index == -1)
    return;

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

    out_ << std::setw(16) << std::left << header.str()
         << std::setw(8) << std::right << (values.at(i) / div)
         << " |" << std::setw(max_width) << std::left << bar << "|"
         << std::endl;
  }
}

void TextOutput::lhist(const std::vector<uint64_t> &values, int min, int max, int step) const
{
  int max_index, max_value, buckets, start_value, end_value;
  lhist_prepare(values, min, max, step, max_index, max_value, buckets, start_value, end_value);
  if (max_index == -1)
    return;

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

    out_ << std::setw(16) << std::left << header.str()
         << std::setw(8) << std::right << values.at(i)
         << " |" << std::setw(max_width) << std::left << bar << "|"
         << std::endl;
  }
}

void TextOutput::map_hist(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                          const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                          const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const
{
  uint32_t i = 0;
  for (auto &key_count : total_counts_by_key)
  {
    auto &key = key_count.first;
    auto &value = values_by_key.at(key);

    if (top)
    {
      if (i++ < (values_by_key.size() - top))
        continue;
    }

    out_ << map.name_ << map.key_.argument_value_list_str(bpftrace, key) << ": " << std::endl;

    if (map.type_.type == Type::hist)
      hist(value, div);
    else
      lhist(value, map.lqmin, map.lqmax, map.lqstep);

    out_ << std::endl;
  }
}

void TextOutput::map_stats(BPFtrace &bpftrace, IMap &map,
                           const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                           const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const
{
  for (auto &key_count : total_counts_by_key)
  {
    auto &key = key_count.first;
    auto &value = values_by_key.at(key);
    out_ << map.name_ << map.key_.argument_value_list_str(bpftrace, key) << ": ";

    uint64_t count = value.at(0);
    uint64_t total = value.at(1);
    uint64_t average = 0;

    if (count != 0)
      average = total / count;

    if (map.type_.type == Type::stats)
      out_ << "count " << count << ", average " <<  average << ", total " << total << std::endl;
    else
      out_ << average << std::endl;
  }

  out_ << std::endl;
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

void JsonOutput::map(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                     const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &values_by_key) const
{
  out_ << "{\"type\": \"" << MessageType::map << "\", \"data\": {";
  out_ << "\"" << json_escape(map.name_) << "\": ";
  if (map.key_.size() > 0) // check if this map has keys
    out_ << "{";

  uint32_t i = 0;
  uint32_t j = 0;
  size_t total = values_by_key.size();
  for (auto &pair : values_by_key)
  {
    auto key = pair.first;
    auto value = pair.second;

    if (top)
    {
      if (total > top && j++ < (total - top))
        continue;
    }

    std::vector<std::string> args = map.key_.argument_value_list(bpftrace, key);
    if (i > 0)
      out_ << ", ";
    if (args.size() > 0) {
      out_ << "\"" << json_escape(str_join(args, ",")) << "\": ";
    }

    if (map.type_.type == Type::kstack || map.type_.type == Type::ustack || map.type_.type == Type::ksym ||
        map.type_.type == Type::usym || map.type_.type == Type::inet || map.type_.type == Type::username ||
        map.type_.type == Type::string || map.type_.type == Type::probe) {
        out_ << "\"" << json_escape(bpftrace.map_value_to_str(map, value, div)) << "\"";
    }
    else {
      out_ << bpftrace.map_value_to_str(map, value, div);
    }

    i++;
  }

  if (map.key_.size() > 0)
    out_ << "}";
  out_ << "}}" << std::endl;
}

void JsonOutput::hist(const std::vector<uint64_t> &values, uint32_t div) const
{
  int min_index, max_index, max_value;
  hist_prepare(values, min_index, max_index, max_value);
  if (max_index == -1)
    return;

  out_ << "[";
  for (int i = min_index; i <= max_index; i++)
  {
    if (i > min_index)
      out_ << ", ";

    out_ << "{";
    if (i == 0)
    {
      out_ << "\"max\": -1, ";
    }
    else if (i == 1)
    {
      out_ << "\"min\": 0, \"max\": 0, ";
    }
    else if (i == 2)
    {
      out_ << "\"min\": 1, \"max\": 1, ";
    }
    else
    {
      long low = 1 << (i-2);
      long high = (1 << (i-2+1)) - 1;
      out_ << "\"min\": " << low << ", \"max\": " << high << ", ";
    }
    out_ << "\"count\": " << values.at(i) / div;
    out_ << "}";
  }
  out_ << "]";
}

void JsonOutput::lhist(const std::vector<uint64_t> &values, int min, int max, int step) const
{
  int max_index, max_value, buckets, start_value, end_value;
  lhist_prepare(values, min, max, step, max_index, max_value, buckets, start_value, end_value);
  if (max_index == -1)
    return;

  out_ << "[";
  for (int i = start_value; i <= end_value; i++)
  {
    if (i > start_value)
      out_ << ", ";

    out_ << "{";
    if (i == 0) {
      out_ << "\"max\": " << min - 1 << ", ";

    } else if (i == (buckets + 1)) {
      out_ << "\"min\": " << max << ", ";
    } else {
      long low = (i - 1) * step + min;
      long high = i * step + min - 1;
      out_ << "\"min\": " << low << ", \"max\": " << high << ", ";
    }
    out_ << "\"count\": " << values.at(i);
    out_ << "}";
  }
  out_ << "]";
}

void JsonOutput::map_hist(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                          const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                          const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const
{
  out_ << "{\"type\": \"" << MessageType::hist << "\", \"data\": {";
  out_ << "\"" << json_escape(map.name_) << "\": ";
  if (map.key_.size() > 0) // check if this map has keys
    out_ << "{";

  uint32_t i = 0;
  uint32_t j = 0;
  for (auto &key_count : total_counts_by_key)
  {
    auto &key = key_count.first;
    auto &value = values_by_key.at(key);

    if (top)
    {
      if (j++ < (values_by_key.size() - top))
        continue;
    }

    std::vector<std::string> args = map.key_.argument_value_list(bpftrace, key);
    if (i > 0)
      out_ << ", ";
    if (args.size() > 0) {
      out_ << "\"" << json_escape(str_join(args, ",")) << "\": ";
    }

    if (map.type_.type == Type::hist)
      hist(value, div);
    else
      lhist(value, map.lqmin, map.lqmax, map.lqstep);

    i++;
  }

  if (map.key_.size() > 0)
    out_ << "}";
  out_ << "}}" << std::endl;
}

void JsonOutput::map_stats(BPFtrace &bpftrace, IMap &map,
                           const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                           const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const
{
  out_ << "{\"type\": \"" << MessageType::stats << "\", \"data\": {";
  out_ << "  \"" << json_escape(map.name_) << "\": ";
  if (map.key_.size() > 0) // check if this map has keys
    out_ << "{";

  uint32_t i = 0;
  for (auto &key_count : total_counts_by_key)
  {
    auto &key = key_count.first;
    auto &value = values_by_key.at(key);

    std::vector<std::string> args = map.key_.argument_value_list(bpftrace, key);
    if (i > 0)
      out_ << ", ";
    if (args.size() > 0) {
      out_ << "    \"" << json_escape(str_join(args, ",")) << "\": ";
    }

    uint64_t count = value.at(0);
    uint64_t total = value.at(1);
    uint64_t average = 0;

    if (count != 0)
      average = total / count;

    if (map.type_.type == Type::stats)
      out_ << "{\"count\": " << count << ", \"average\": " <<  average << ", \"total\": " << total << "}";
    else
      out_ << average;

    i++;
  }

  if (map.key_.size() > 0)
    out_ << "}";
  out_ << "}}" << std::endl;
}

void JsonOutput::message(MessageType type, const std::string& msg, bool nl __attribute__((unused))) const
{
  out_ << "{\"type\": \"" << type << "\", \"msg\": \"" << json_escape(msg) << "\"}" << std::endl;
}

void JsonOutput::message(MessageType type, const std::string& field, uint64_t value) const
{
  out_ << "{\"type\": \"" << type << "\", \"" << field << "\": " << value << "}" << std::endl;
}

void JsonOutput::lost_events(uint64_t lost) const
{
  message(MessageType::lost_events, "events", lost);
}

void JsonOutput::attached_probes(uint64_t num_probes) const
{
  message(MessageType::attached_probes, "probes", num_probes);
}

} // namespace bpftrace
