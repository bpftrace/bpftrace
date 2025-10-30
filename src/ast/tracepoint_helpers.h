#pragma once

#include <string>

#include "ast/ast.h"

namespace bpftrace::ast {

std::string get_tracepoint_struct_name(const std::string &category,
                                       const std::string &event_name);
std::string get_tracepoint_struct_name(const ast::AttachPoint &ap);
bool is_tracepoint_struct(const std::string &name);

} // namespace bpftrace::ast
