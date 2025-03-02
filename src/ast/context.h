#pragma once

#include <memory>
#include <vector>

#include "ast/diagnostic.h"

namespace bpftrace {
namespace ast {

class Node;
class Program;

template <typename T>
concept NodeType = std::derived_from<T, Node>;

// Manages the lifetime of AST nodes.
//
// Nodes allocated by an ASTContext will be kept alive for the duration of the
// owning ASTContext object.
class ASTContext {
public:
  ASTContext() : diagnostics_(std::make_unique<Diagnostics>()) {};

  // Creates and returns a pointer to an AST node.
  template <NodeType T, typename... Args>
  T *make_node(Args &&...args)
  {
    auto uniq_ptr = std::make_unique<T>(*diagnostics_.get(),
                                        std::forward<Args>(args)...);
    auto *raw_ptr = uniq_ptr.get();
    nodes_.push_back(std::move(uniq_ptr));
    return raw_ptr;
  }

  unsigned int node_count()
  {
    return nodes_.size();
  }

  // Callers should avoid mutating diagnostics through this method. It is
  // non-const to allow for tests to clear the set, but this should be avoided
  // except in the context of a test.
  Diagnostics &diagnostics() const
  {
    return *diagnostics_.get();
  }

  Program *root = nullptr;

private:
  std::vector<std::unique_ptr<Node>> nodes_;
  std::unique_ptr<Diagnostics> diagnostics_;
};

} // namespace ast
} // namespace bpftrace
