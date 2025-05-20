#pragma once

#include <memory>
#include <vector>

#include "ast/diagnostic.h"
#include "ast/pass_manager.h"

namespace bpftrace {

class Driver;

namespace ast {

class SourceLocation;
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
  ASTSource(std::string &&filename, std::string &&input);
  ASTSource(const ASTSource &other) = delete;
  ASTSource &operator=(const ASTSource &other) = delete;

  const std::string filename;
  const std::string contents;

private:
  std::vector<std::string> lines_;

  friend class SourceLocation;
};

// Manages the lifetime of AST nodes.
//
// Nodes allocated by an ASTContext will be kept alive for the duration of the
// owning ASTContext object. The ASTContext also owns the canonical instance of
// the ASTSource, which is used by the Diagnostics to contextualize errors.
class ASTContext : public ast::State<"ast"> {
public:
  ASTContext(std::string &&filename, std::string &&contents);
  ASTContext(const std::string &filename, const std::string &contents);
  ASTContext();

  // Creates and returns a pointer to an AST node.
  template <NodeType T, typename... Args>
  constexpr T *make_node(Args &&...args)
  {
    auto uniq_ptr = std::make_unique<T>(*this,
                                        wrap(std::forward<Args>(args))...);
    auto *raw_ptr = uniq_ptr.get();
    state_->nodes_.push_back(std::move(uniq_ptr));
    return raw_ptr;
  }

  template <NodeType T>
  constexpr T *clone_node(const T *other, const Location &loc)
  {
    if (other == nullptr) {
      return nullptr;
    }
    auto uniq_ptr = std::make_unique<T>(*this, *other, loc);
    auto *raw_ptr = uniq_ptr.get();
    state_->nodes_.push_back(std::move(uniq_ptr));
    return raw_ptr;
  }

  unsigned int node_count()
  {
    return state_->nodes_.size();
  }

  Diagnostics &diagnostics() const
  {
    return *state_->diagnostics_;
  }

  std::shared_ptr<ASTSource> source() const
  {
    return source_;
  }

  // clears all the nodes and diagnostics, but does not affect the underlying
  // `ASTSource` object. This is useful if you want to e.g. reparse the full
  // syntax tree in place.
  void clear();

  // Root points to a node in `state_.nodes_`.
  Program *root = nullptr;

private:
  // State owns the underlying nodes; they are permitted to take a reference to
  // this object since their lifetimes are bound.
  class State {
  public:
    State();
    std::vector<std::unique_ptr<Node>> nodes_;
    std::unique_ptr<Diagnostics> diagnostics_;
  };

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
    return std::make_shared<LocationChain>(SourceLocation(loc, source_));
  };

  std::unique_ptr<State> state_;
  std::shared_ptr<ASTSource> source_;

  friend class bpftrace::Driver;
  friend class Node;
};

} // namespace ast
} // namespace bpftrace
