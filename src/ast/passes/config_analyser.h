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
  explicit ConfigAnalyser(ASTContext &ctx,
                          BPFtrace &bpftrace,
                          std::ostream &out = std::cerr)
      : Visitor<ConfigAnalyser>(ctx),
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
  BPFtrace &bpftrace_;
  ConfigSetter config_setter_;
  std::ostream &out_;
  std::ostringstream err_;

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
} // namespace ast
} // namespace bpftrace
