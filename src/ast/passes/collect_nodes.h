#pragma once

#include <functional>
#include <vector>

#include "ast/visitors.h"

namespace bpftrace::ast {

/*
 * CollectNodes
 *
 * Recurses into the provided node and builds a list of all descendants of the
 * requested type which match a predicate.
 */
template <typename NodeT>
class CollectNodes : public Visitor {
public:
  void run(
      Node &node,
      std::function<bool(const NodeT &)> pred = [](const auto &) {
        return true;
      })
  {
    pred_ = pred;
    node.accept(*this);
  }
  const std::vector<std::reference_wrapper<NodeT>> &nodes() const
  {
    return nodes_;
  }

private:
  void visit(NodeT &node) override
  {
    if (pred_(node)) {
      nodes_.push_back(node);
    }

    Visitor::visit(node);
  }

  std::vector<std::reference_wrapper<NodeT>> nodes_;
  std::function<bool(const NodeT &)> pred_;
};

} // namespace bpftrace::ast
