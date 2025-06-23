#include <bpf/libbpf.h>

namespace libbpf {
#define __BPF_NAME_FN(x) #x
const char *bpf_func_name[] = { __BPF_FUNC_MAPPER(__BPF_NAME_FN) };
#undef __BPF_NAME_FN
} // namespace libbpf

namespace bpftrace {

std::string helper_func_name(int func_id){ libbpf::bpf_func_name[info.func_id] }

std::string get_helper_error_msg(int func_id, int retcode) const
{
  std::string msg;
  if (func_id == libbpf::BPF_FUNC_map_update_elem && retcode == -E2BIG) {
    msg = "Map full; can't update element. Try increasing max_map_keys config "
          "or manually setting the max entries in a map declaration e.g. `let "
          "@a = hash(5000)`";
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

void JsonOutput::helper_error(int retcode, const HelperErrorInfo &info) const
{
  out_ << R"({"type": "helper_error", "msg": ")"
       << get_helper_error_msg(info.func_id, retcode) << R"(", "helper": ")"
       << libbpf::bpf_func_name[info.func_id] << R"(", "retcode": )" << retcode
       << R"(, "filename": ")" << info.filename << R"(", "line": )" << info.line
       << R"(, "col": )" << info.column << "}" << std::endl;
}

} // namespace bpftrace
