#include "bpftrace.h"

namespace ebpf {
namespace bpftrace {

std::string typestr(Type t)
{
  switch (t)
  {
    case Type::none:     return "none";     break;
    case Type::integer:  return "integer";  break;
    case Type::quantize: return "quantize"; break;
    case Type::count:    return "count";    break;
    default: abort();
  }
}

} // namespace bpftrace
} // namespace ebpf
