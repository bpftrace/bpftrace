#pragma once

#include <iostream>
#include <sstream>
#include <unordered_set>

#include "ast/pass_manager.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace {
namespace ast {

// Load imports & resolve types, maps, etc.
class ResolveImports : public Visitor<ResolveImports> {
public:
  ResolveImports(ASTContext &ctx, BPFtrace &bpftrace);

  using Visitor<ResolveImports>::visit;
  void visit(Import &imp);
  void visit(Map &map);

  std::string error() { return err_.str(); }

private:
  BPFtrace &bpftrace_;
  std::ostringstream err_;
  std::unordered_set<std::string> maps_;
};

Pass CreateResolveImportsPass();

} // namespace ast
} // namespace bpftrace
