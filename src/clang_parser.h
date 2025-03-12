#pragma once

#include "ast/pass_manager.h"

namespace bpftrace {

class ClangParseError : public ErrorInfo<ClangParseError> {
public:
  static char ID;
  void log(llvm::raw_ostream &OS) const override;
};

ast::Pass CreateClangPass(std::vector<std::string> &&extra_flags = {});

} // namespace bpftrace
