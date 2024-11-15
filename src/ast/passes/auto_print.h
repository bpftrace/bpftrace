#pragma once

#include <iostream>
#include <sstream>

#include "ast/pass_manager.h"
#include "ast/visitors.h"

namespace bpftrace {
namespace ast {

// Automatically promotes bare identifier statements to print statements.
class AutoPrintAnalyser : public Visitor {
public:
  AutoPrintAnalyser(ASTContext &ctx);

private:
  void visit(ExprStatement &statement) override;

  ASTContext &ctx_;
};

Pass CreateAutoPrintPass();

} // namespace ast
} // namespace bpftrace
