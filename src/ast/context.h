#pragma once

#include <memory>
#include <vector>

#include "ast/diagnostic.h"

namespace bpftrace {

class Driver;

namespace ast {

class Node;
class Program;

template <typename T>
concept NodeType = std::derived_from<T, Node>;

// Captures the original filename and source for a given AST.
//
// This is a heavy object, containing the full contents of the file. Only a
// single instance of this class should be created and referenced.
class ASTSource {
public:
  ASTSource(std::string &&filename, std::string &&contents)
      : filename(std::move(filename)), contents(std::move(contents)) {};
  ASTSource(const ASTSource &other) = delete;
  ASTSource &operator=(const ASTSource &other) = delete;

  const std::string filename;
  const std::string contents;
};

// Manages the lifetime of AST nodes.
//
// Nodes allocated by an ASTContext will be kept alive for the duration of the
// owning ASTContext object. The ASTContext also owns the canonical instance of
// the ASTSource, which is used by the Diagnostics to contextualize errors.
class ASTContext {
public:
  ASTContext(std::string &&filename, std::string &&contents);
  ASTContext(const std::string &filename, const std::string &contents);
  ASTContext();

  // Creates and returns a pointer to an AST node.
  template <NodeType T, typename... Args>
  T &make_node(Args &&...args)
  {
    auto ptr = std::make_unique<T>(*diagnostics_.get(),
                                   std::forward<Args>(args)...);
    auto &ref = *ptr.get();
    nodes_.emplace_back(std::move(ptr));
    return ref;
  }

  unsigned int node_count()
  {
    return nodes_.size();
  }

  const Diagnostics &diagnostics() const
  {
    return *diagnostics_.get();
  }

  // The root is the program which is set after parsing. If this is not set,
  // then parsing was not successfully.
  std::optional<std::reference_wrapper<Program>> root;

private:
  std::vector<std::unique_ptr<Node>> nodes_;
  std::shared_ptr<ASTSource> source_;
  std::unique_ptr<Diagnostics> diagnostics_;

  friend class bpftrace::Driver;
};

} // namespace ast
} // namespace bpftrace
