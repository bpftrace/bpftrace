#pragma once

#include <functional>
#include <vector>

#include "ast/visitor.h"

namespace bpftrace::ast {

// CollectNodes is a utility visitor which other passes may use directly. It
// recurses into the provided node and builds a list of all descendants of the
// requested type which match a predicate.
template <typename NodeT>
class CollectNodes : public Visitor<CollectNodes<NodeT>> {
public:
  explicit CollectNodes() : pred_([](const auto &) { return true; })
  {
  }

  const std::vector<std::reference_wrapper<NodeT>> &nodes() const
  {
    return nodes_;
  }

  using Visitor<CollectNodes<NodeT>>::visit;
  void visit(NodeT &node)
  {
    if (pred_(node)) {
      nodes_.push_back(node);
    }
    Visitor<CollectNodes<NodeT>>::visit(node);
  }

  template <typename T>
  void visit(T &node, std::function<bool(const NodeT &)> pred)
  {
    pred_ = pred;
    visit(node);
  }

private:
  std::vector<std::reference_wrapper<NodeT>> nodes_;
  std::function<bool(const NodeT &)> pred_;
};

} // namespace bpftrace::ast
