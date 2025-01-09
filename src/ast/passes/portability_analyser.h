#pragma once

#include <iostream>
#include <sstream>

#include "ast/pass_manager.h"
#include "ast/visitor.h"

namespace bpftrace {
namespace ast {

// Checks if a script uses any non-portable bpftrace features that AOT
// cannot handle.
//
// Over time, we expect to relax these restrictions as AOT supports more
// features.
class PortabilityAnalyser : public Visitor<PortabilityAnalyser> {
public:
  PortabilityAnalyser(ASTContext &ctx, std::ostream &out = std::cerr);
  int analyse();

  using Visitor<PortabilityAnalyser>::visit;
  void visit(PositionalParameter &param);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Cast &cast);
  void visit(AttachPoint &ap);

private:
  std::ostream &out_;
  std::ostringstream err_;
};

Pass CreatePortabilityPass();

} // namespace ast
} // namespace bpftrace
