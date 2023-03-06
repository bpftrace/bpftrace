#pragma once

#include "ast/pass_manager.h"
#include "ast/visitors.h"

namespace bpftrace {
namespace ast {

class ReturnPathAnalyser : public Dispatcher<bool> {
public:
  explicit ReturnPathAnalyser(Node *root, std::ostream &out = std::cerr);

  // visit methods return true iff all return paths of the analyzed code
  // (represented by the given node) return a value
  // For details for concrete node type see the implementations
  bool visit(Program &prog) override;
  bool visit(Subprog &subprog) override;
  bool visit(Jump &jump) override;
  bool visit(If &if_stmt) override;

  // For nodes that neither directly return a value or have children with
  // semantics such that the code represented by the node always returns
  // a value, false is returned
  bool default_visitor(Node &node) override;

  int analyse();

private:
  Node *root_;
  std::ostream &out_;
  std::ostringstream err_;
};

Pass CreateReturnPathPass();

} // namespace ast
} // namespace bpftrace
