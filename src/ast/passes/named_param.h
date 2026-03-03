#pragma once

#include "ast/pass_manager.h"
#include "globalvars.h"

namespace bpftrace::ast {

class NamedParamInfo : public ast::State<"named_param_info"> {
public:
  std::unordered_map<std::string, globalvars::GlobalVarInfo> defaults;
  std::unordered_map<std::string, SizedType> map_val_types;
};

Pass CreateNamedParamsPass();

} // namespace bpftrace::ast
