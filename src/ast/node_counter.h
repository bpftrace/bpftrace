#pragma once
#include "bpftrace.h"
#include "log.h"
#include "pass_manager.h"
#include "visitors.h"

namespace bpftrace {
namespace ast {

class NodeCounter : public Visitor
{
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

Pass CreateCounterPass()
{
  auto fn = [](Node &n, PassContext &ctx) {
    NodeCounter c;
    c.Visit(n);
    auto node_count = c.get_count();
    auto max = ctx.b.ast_max_nodes_;
    if (bt_verbose)
    {
      LOG(INFO) << "node count: " << node_count;
    }
    if (node_count >= max)
    {
      LOG(ERROR) << "node count (" << node_count << ") exceeds the limit ("
                 << max << ")";
      return PassResult::Error("node count exceeded");
    }
    return PassResult::Success();
  };
  return Pass("NodeCounter", fn);
}

} // namespace ast
} // namespace bpftrace
