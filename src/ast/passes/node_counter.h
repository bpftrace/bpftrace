#pragma once

#include "ast/pass_manager.h"
#include "ast/visitors.h"
#include "bpftrace.h"
#include "config.h"
#include "log.h"

namespace bpftrace {
namespace ast {

class NodeCounter : public Visitor {
public:
  void Visit(Node &node) override
  {
    count_++;
    Visitor::Visit(node);
  }

  size_t get_count()
  {
    return count_;
  };

private:
  size_t count_ = 0;
};

inline Pass CreateCounterPass()
{
  auto fn = [](Node &n, PassContext &ctx) {
    NodeCounter c;
    c.Visit(n);
    auto node_count = c.get_count();
    auto max = ctx.b.max_ast_nodes_;
    LOG(V1) << "AST node count: " << node_count;
    if (node_count >= max) {
      LOG(ERROR) << "node count (" << node_count << ") exceeds the limit ("
                 << max << ")";
      return PassResult::Error("NodeCounter", "node count exceeded");
    }
    return PassResult::Success();
  };
  return Pass("NodeCounter", fn);
}

} // namespace ast
} // namespace bpftrace
