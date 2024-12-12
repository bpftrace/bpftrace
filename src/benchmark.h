#pragma once

#include <iostream>

#include "ast/pass_manager.h"
#include "util/result.h"

namespace bpftrace {

class TimerError : public ErrorInfo<TimerError> {
public:
  TimerError(int err) : err_(err) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  int err_;
};

Result<OK> benchmark(std::ostream &out, ast::PassManager &mgr);

} // namespace bpftrace
