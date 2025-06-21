#pragma once

#include "ast/pass_manager.h"
#include "types.h"

namespace bpftrace::ast {

struct NamedParamDefault {
  std::string value;
  bool is_bool = false;
  Type type;
};

class NamedParamDefaults : public ast::State<"named_params_defaults"> {
public:
  std::unordered_map<std::string, NamedParamDefault> defaults;
};

Pass CreateNamedParamPass();

} // namespace bpftrace::ast
