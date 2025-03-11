#pragma once

#include <memory>
#include <vector>

#include "ast/diagnostic.h"

namespace bpftrace {

class Driver;

namespace ast {

class Location;
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
  ASTSource(std::string &&filename, std::string &&contents);
  ASTSource(const ASTSource &other) = delete;
  ASTSource &operator=(const ASTSource &other) = delete;

  const std::string filename;
  const std::string contents;

private:
  std::vector<std::string> lines_;

  friend class Location;
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
  constexpr T *make_node(Args &&...args)
  {
    auto uniq_ptr = std::make_unique<T>(*diagnostics_.get(),
                                        wrap(std::forward<Args>(args))...);
    auto *raw_ptr = uniq_ptr.get();
    nodes_.push_back(std::move(uniq_ptr));
    return raw_ptr;
  }

  unsigned int node_count()
  {
    return nodes_.size();
  }

  const Diagnostics &diagnostics() const
  {
    return *diagnostics_.get();
  }

  Program *root = nullptr;

private:
  // wrap potentially converts external types to internal ones. At the moment,
  // this automatically converts the parser `location` to the `Location` class
  // bound to the current source file.
  template <typename T>
  auto wrap(T &&t) -> decltype(t)
  {
    return std::forward<T>(t);
  }
  Location wrap(location loc)
  {
    return { loc, source_ };
  };

  std::vector<std::unique_ptr<Node>> nodes_;
  std::unique_ptr<Diagnostics> diagnostics_;
  std::shared_ptr<ASTSource> source_;

  friend class bpftrace::Driver;
};

} // namespace ast
} // namespace bpftrace
