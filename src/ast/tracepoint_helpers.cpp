#include "tracepoint_helpers.h"

namespace bpftrace::ast {

constexpr std::string_view TRACEPOINT_STRUCT_PREFIX = "struct _tracepoint_";

std::string get_tracepoint_struct_name(const std::string &category,
                                       const std::string &event_name)
{
  return std::string(TRACEPOINT_STRUCT_PREFIX) + category + "_" + event_name;
}

std::string get_tracepoint_struct_name(const ast::AttachPoint &ap)
{
  return get_tracepoint_struct_name(ap.target, ap.func);
}

bool is_tracepoint_struct(const std::string &name)
{
  return name.starts_with(TRACEPOINT_STRUCT_PREFIX);
}

} // namespace bpftrace::ast
