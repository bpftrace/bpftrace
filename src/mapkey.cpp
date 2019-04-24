#include "bpftrace.h"
#include "mapkey.h"

namespace bpftrace {

bool MapKey::operator!=(const MapKey &k) const
{
  return args_ != k.args_;
}

size_t MapKey::size() const
{
  size_t size = 0;
  for (auto &arg : args_)
    size += arg.size;
  return size;
}

std::string MapKey::argument_type_list() const
{
  std::ostringstream list;
  list << "[";
  for (size_t i = 0; i < args_.size(); i++)
  {
    if (i)
      list << ", ";
    list << args_[i];
  }
  list << "]";
  return list.str();
}

std::string MapKey::argument_value_list(BPFtrace &bpftrace,
    const std::vector<uint8_t> &data) const
{
  if (args_.empty())
    return "";
  std::string list = "[";
  int offset = 0;
  bool first = true;
  for (const SizedType &arg : args_)
  {
    if (first)
      first = false;
    else
      list += ", ";
    list += argument_value(bpftrace, arg, &data[offset]);
    offset += arg.size;
  }
  return list + "]";
}

std::string MapKey::argument_value(BPFtrace &bpftrace,
    const SizedType &arg,
    const void *data)
{
  auto arg_data = static_cast<const uint8_t*>(data);
  std::ostringstream ptr;
  switch (arg.type)
  {
    case Type::integer:
      switch (arg.size)
      {
        case 1:
          return std::to_string(*(const int8_t*)data);
        case 2:
          return std::to_string(*(const int16_t*)data);
        case 4:
          return std::to_string(*(const int32_t*)data);
        case 8:
          return std::to_string(*(const int64_t*)data);
        default:
          break;
      }
      break;
    case Type::kstack:
      return bpftrace.get_stack(*(const uint64_t*)data, false, arg.stack_type, 4);
    case Type::ustack:
      return bpftrace.get_stack(*(const uint64_t*)data, true, arg.stack_type, 4);
    case Type::ksym:
      return bpftrace.resolve_ksym(*(const uint64_t*)data);
    case Type::usym:
      return bpftrace.resolve_usym(*(const uint64_t*)data, *(const uint64_t*)(arg_data + 8));
    case Type::inet:
      return bpftrace.resolve_inet(*(const int32_t*)data, (uint8_t*)(arg_data + 8));
    case Type::username:
      return bpftrace.resolve_uid(*(const uint64_t*)data);
    case Type::probe:
      return bpftrace.probe_ids_[*(const uint64_t*)data];
    case Type::string:
      return std::string((const char*)data);
    case Type::cast:
      if (arg.is_pointer) {
        // use case: show me these pointer values
        ptr << "0x" << std::hex << *(const int64_t*)data;
        return ptr.str();
      }
      // fall through
    default:
      std::cerr << "invalid mapkey argument type" << std::endl;
  }
  abort();
}

} // namespace bpftrace
