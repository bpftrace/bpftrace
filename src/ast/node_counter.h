#pragma once
#include "visitors.h"
#include "pass_manager.h"
#include "bpftrace.h"
#include "log.h"

namespace bpftrace {
namespace ast {

class NodeCounter : public Visitor
{
public:
  void Visit(Node &node)
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

Pass CreateCounterPass() {
  auto fn = [](Node &n, PassContext &ctx) {
    NodeCounter c;
    c.Visit(n);
    auto node_count = c.get_count();
    if (bt_verbose)
    {
      LOG(INFO) << "node count: " << ctx.max_ast_nodes;
    }
    if (node_count >= ctx.max_ast_nodes)
    {
      LOG(ERROR) << "node count (" << node_count << ") exceeds the limit ("
                 << ctx.max_ast_nodes << ")";
      return PassResult::Error("node count exceeded");
    }
    return PassResult::Success();
  };
  return AnalysePass("NodeCounter", fn);
}

} // namespace ast
} // namespace bpftrace
