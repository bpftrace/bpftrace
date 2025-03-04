#pragma once

#include "ast/pass_manager.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "config.h"
#include "types.h"

namespace bpftrace::ast {

class ConfigAnalyser : public Visitor<ConfigAnalyser> {
public:
  explicit ConfigAnalyser(BPFtrace &bpftrace)
      : bpftrace_(bpftrace),
        config_setter_(ConfigSetter(*bpftrace.config_, ConfigSource::script))
  {
  }

  using Visitor<ConfigAnalyser>::visit;
  void visit(Integer &integer);
  void visit(String &string);
  void visit(StackMode &mode);
  void visit(AssignConfigVarStatement &assignment);

private:
  BPFtrace &bpftrace_;
  ConfigSetter config_setter_;

  void set_config(AssignConfigVarStatement &assignment, ConfigKeyInt key);
  void set_config(AssignConfigVarStatement &assignment, ConfigKeyBool key);
  void set_config(AssignConfigVarStatement &assignment, ConfigKeyString key);
  void set_config(AssignConfigVarStatement &assignment,
                  ConfigKeyUserSymbolCacheType key);
  void set_config(AssignConfigVarStatement &assignment,
                  ConfigKeySymbolSource key);
  void set_config(AssignConfigVarStatement &assignment, ConfigKeyStackMode key);
  void set_config(AssignConfigVarStatement &assignment,
                  ConfigKeyMissingProbes key);

  void log_type_error(SizedType &type,
                      Type expected_type,
                      AssignConfigVarStatement &assignment);
};

Pass CreateConfigPass();

} // namespace bpftrace::ast
