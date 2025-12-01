#pragma once

#include "ast/pass_manager.h"
#include "probe_types.h"

namespace bpftrace::ast {

class ArgParseError : public ErrorInfo<ArgParseError> {
public:
  static char ID;
  ArgParseError(std::string probe_name, std::string &&detail)
      : probe_name_(std::move(probe_name)), detail_(std::move(detail)) {};
  ArgParseError(std::string_view probe_name, std::string &&detail)
      : ArgParseError(std::string(probe_name), std::move(detail)) {};
  ArgParseError(std::string probe_name,
                std::string arg_name,
                std::string &&detail)
      : probe_name_(std::move(probe_name)),
        arg_name_(std::move(arg_name)),
        detail_(std::move(detail)) {};
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string probe_name_;
  std::string arg_name_;
  std::string detail_;
};

Pass CreateArgsResolverPass();

} // namespace bpftrace::ast
