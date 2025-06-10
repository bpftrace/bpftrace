#pragma once

#include "ast/pass_manager.h"
#include "util/result.h"

namespace bpftrace::ast {

class CliOptsError : public ErrorInfo<CliOptsError> {
public:
  CliOptsError(std::string err) : err_(std::move(err)) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

  const std::string &err() const
  {
    return err_;
  }

private:
  std::string err_;
};

Pass CreateCLIOptsPass(
    const std::unordered_map<std::string, std::string> &named_args);

} // namespace bpftrace::ast
