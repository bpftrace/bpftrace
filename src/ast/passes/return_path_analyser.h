#pragma once

#include "ast/pass_manager.h"
#include "ast/visitor.h"

namespace bpftrace {
namespace ast {

class ReturnPathAnalyser : public Visitor<ReturnPathAnalyser, bool> {
public:
  explicit ReturnPathAnalyser(ASTContext &ctx);

  // visit methods return true iff all return paths of the analyzed code
  // (represented by the given node) return a value
  // For details for concrete node type see the implementations
  using Visitor<ReturnPathAnalyser, bool>::visit;
  bool visit(Program &prog);
  bool visit(Subprog &subprog);
  bool visit(Jump &jump);
  bool visit(If &if_stmt);
};

Pass CreateReturnPathPass();

} // namespace ast
} // namespace bpftrace
