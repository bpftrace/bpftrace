#include "util/bpf_funcs.h"

namespace libbpf {
#define __BPF_NAME_FN(x) #x
const char* bpf_func_name[] = { __BPF_FUNC_MAPPER(__BPF_NAME_FN) };
#undef __BPF_NAME_FN

std::ostream& operator<<(std::ostream& out, const bpf_func_id& id)
{
  out << bpf_func_name[id];
  return out;
}

} // namespace libbpf
