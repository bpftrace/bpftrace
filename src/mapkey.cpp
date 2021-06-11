#include <cstring>

#include "async_event_types.h"
#include "bpftrace.h"
#include "log.h"
#include "mapkey.h"
#include "utils.h"

namespace bpftrace {

bool MapKey::operator!=(const MapKey &k) const
{
  return args_ != k.args_;
}

size_t MapKey::size() const
{
  size_t size = 0;
  for (auto &arg : args_)
    size += arg.GetSize();
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

std::vector<std::string> MapKey::argument_value_list(BPFtrace &bpftrace,
    const std::vector<uint8_t> &data) const
{
  std::vector<std::string> list;
  int offset = 0;
  for (const SizedType &arg : args_)
  {
    list.push_back(argument_value(bpftrace, arg, &data[offset]));
    offset += arg.GetSize();
  }
  return list;
}

std::string MapKey::argument_value_list_str(BPFtrace &bpftrace,
    const std::vector<uint8_t> &data) const
{
  if (args_.empty())
    return "";
  return "[" + str_join(argument_value_list(bpftrace, data), ", ") + "]";
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
      switch (arg.GetSize())
      {
        case 1:
          return std::to_string(read_data<int8_t>(data));
        case 2:
          return std::to_string(read_data<int16_t>(data));
        case 4:
          return std::to_string(read_data<int32_t>(data));
        case 8:
          return std::to_string(read_data<int64_t>(data));
        default:
          break;
      }
      break;
    case Type::kstack:
      return bpftrace.get_stack(
          read_data<uint64_t>(data), false, arg.stack_type, 4);
    case Type::ustack:
      return bpftrace.get_stack(
          read_data<uint64_t>(data), true, arg.stack_type, 4);
    case Type::timestamp:
    {
      auto p = static_cast<const AsyncEvent::Strftime *>(data);
      return bpftrace.resolve_timestamp(p->strftime_id, p->nsecs_since_boot);
    }
    case Type::ksym:
      return bpftrace.resolve_ksym(read_data<uint64_t>(data));
    case Type::usym:
      return bpftrace.resolve_usym(read_data<uint64_t>(data),
                                   read_data<uint64_t>(arg_data + 8));
    case Type::inet:
      return bpftrace.resolve_inet(read_data<int64_t>(data),
                                   (const uint8_t *)(arg_data + 8));
    case Type::username:
      return bpftrace.resolve_uid(read_data<uint64_t>(data));
    case Type::probe:
      return bpftrace.resources.probe_ids[read_data<uint64_t>(data)];
    case Type::string:
    {
      auto p = static_cast<const char *>(data);
      return std::string(p, strnlen(p, arg.GetSize()));
    }
    case Type::buffer:
    {
      auto p = static_cast<const char *>(data) + 1;
      return hex_format_buffer(p, arg.GetSize() - 1);
    }
    case Type::pointer:
    {
      // use case: show me these pointer values
      ptr << "0x" << std::hex << read_data<int64_t>(data);
      return ptr.str();
    }
    case Type::array:
    {
      std::vector<std::string> elems;
      for (size_t i = 0; i < arg.GetNumElements(); i++)
        elems.push_back(argument_value(bpftrace,
                                       *arg.GetElementTy(),
                                       (const uint8_t *)data +
                                           i * arg.GetElementTy()->GetSize()));
      return "[" + str_join(elems, ",") + "]";
    }
    case Type::record:
    {
      std::vector<std::string> elems;
      for (auto &field : arg.GetFields())
      {
        elems.push_back("." + field.name + "=" +
                        argument_value(bpftrace,
                                       field.type,
                                       (const uint8_t *)data + field.offset));
      }
      return "{" + str_join(elems, ",") + "}";
    }
    case Type::mac_address:
    {
      auto p = static_cast<const uint8_t *>(data);
      return bpftrace.resolve_mac_address(p);
    }
    default:
      LOG(ERROR) << "invalid mapkey argument type";
  }
  abort();
}

} // namespace bpftrace
