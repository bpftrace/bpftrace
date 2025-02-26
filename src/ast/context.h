#pragma once

#include <memory>
#include <vector>

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
  Program *root = nullptr;

  // Creates and returns a pointer to an AST node.
  template <NodeType T, typename... Args>
  T *make_node(Args &&...args)
  {
    auto uniq_ptr = std::make_unique<T>(std::forward<Args>(args)...);
    auto *raw_ptr = uniq_ptr.get();
    nodes_.push_back(std::move(uniq_ptr));
    return raw_ptr;
  }

  unsigned int node_count()
  {
    return nodes_.size();
  }

private:
  std::vector<std::unique_ptr<Node>> nodes_;
};

} // namespace ast
} // namespace bpftrace
