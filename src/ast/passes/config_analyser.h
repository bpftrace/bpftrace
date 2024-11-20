#pragma once

#include <iostream>
#include <sstream>
#include <unordered_set>

#include "ast/pass_manager.h"
#include "ast/visitor.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "config.h"
#include "types.h"

namespace bpftrace {
namespace ast {

class ConfigAnalyser : public Visitor<ConfigAnalyser> {
public:
  explicit ConfigAnalyser(Program &program,
                          BPFtrace &bpftrace,
                          std::ostream &out = std::cerr)
      : program_(program),
        bpftrace_(bpftrace),
        config_setter_(ConfigSetter(bpftrace.config_, ConfigSource::script)),
        out_(out)
  {
  }

  using Visitor<ConfigAnalyser>::visit;
  void visit(Integer &integer);
  void visit(String &string);
  void visit(StackMode &mode);
  void visit(AssignConfigVarStatement &assignment);

  bool analyse();

private:
  Program &program_;
  BPFtrace &bpftrace_;
  ConfigSetter config_setter_;
  std::ostream &out_;
  std::ostringstream err_;

  void set_uint64_config(AssignConfigVarStatement &assignment,
                         ConfigKeyInt key);
  void set_bool_config(AssignConfigVarStatement &assignment, ConfigKeyBool key);
  void set_string_config(AssignConfigVarStatement &assignment,
                         ConfigKeyString key);
  void set_stack_mode_config(AssignConfigVarStatement &assignment);
  void set_user_symbol_cache_type_config(AssignConfigVarStatement &assignment);
  void set_symbol_source_config(AssignConfigVarStatement &assignment);
  void set_missing_probes_config(AssignConfigVarStatement &assignment);

  void log_type_error(SizedType &type,
                      Type expected_type,
                      AssignConfigVarStatement &assignment);
};

Pass CreateConfigPass();
} // namespace ast
} // namespace bpftrace
