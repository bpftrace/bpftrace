#pragma once

#include "ast/pass_manager.h"
#include "globalvars.h"

namespace bpftrace::ast {

class NamedParamDefaults : public ast::State<"named_params_defaults"> {
public:
  std::unordered_map<std::string, globalvars::GlobalVarValue> defaults;
};

Pass CreateNamedParamsPass();

} // namespace bpftrace::ast
