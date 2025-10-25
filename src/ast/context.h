#pragma once

#include <map>
#include <memory>
#include <variant>
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

  // Reads the contents of the source corresponding to a specific location.
  std::string read(const SourceLocation &loc);

private:
  std::vector<std::string> lines_;

  friend class SourceLocation;
};

// MetadataIndex is an index of comments and spacing.
//
// It allows for looking up and removing comments associated with specific
// source locations. It can efficiently claim all comments up until a given
// location.
class MetadataIndex {
public:
  MetadataIndex() = default; // Allow, map will be empty.
  MetadataIndex(std::shared_ptr<ASTSource> source)
      : source_(std::move(source)) {};

  // The Variant describes either comments (strings) or vspace (size_t).
  using Variant = std::variant<std::string, size_t>;

  // Returns all metadata in this index.
  std::vector<Variant> all();

  // Finds and removes all metadata that precedes this location, returning
  // a new index. This new index can be subsequently sliced, or `all` can
  // be used to retrieve all associated metadata. Note that `all` does not
  // remove the metadata from the index, this only happens with `before`.
  MetadataIndex before(const SourceLocation::Position &pos);

private:
  struct CommentSentinel {};
  struct VspaceSentinel {
    size_t amount;
  };
  using InternalMap =
      std::map<SourceLocation,
               std::variant<CommentSentinel, VspaceSentinel>>;
  MetadataIndex(std::shared_ptr<ASTSource> source, InternalMap other)
      : source_(std::move(source)), map_(std::move(other)) {};

  std::shared_ptr<ASTSource> source_;
  InternalMap map_;
  friend class ASTContext;
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
  constexpr T *make_node(Location &&loc, Args... args)
  {
    auto uniq_ptr = std::make_unique<T>(*this,
                                        std::move(loc),
                                        std::forward<Args>(args)...);
    auto *raw_ptr = uniq_ptr.get();
    state_->nodes_.push_back(std::move(uniq_ptr));
    return raw_ptr;
  }

  template <NodeType T, typename... Args>
  T *make_node(const SourceLocation &loc, Args &&...args)
  {
    // Occasionally, the parse default-constructs SourceLocation objects,
    // which therefore do not reference the original source. We fix up this
    // case and bound a location to the current from this context.
    auto bound_loc = loc;
    if (bound_loc.source_ == nullptr) {
      bound_loc.source_ = source_;
    }
    auto loc_chain = std::make_shared<LocationChain>(std::move(bound_loc));
    return make_node<T, Args...>(std::move(loc_chain),
                                 std::forward<Args>(args)...);
  }

  template <NodeType T, typename... Args>
  T *make_node(const Location &loc, Args... args)
  {
    return make_node<T, Args...>(Location(loc), std::forward<Args>(args)...);
  }

  template <NodeType T>
  T *clone_node(const Location &loc, const T *other)
  {
    if (other == nullptr) {
      return nullptr;
    }
    auto uniq_ptr = std::make_unique<T>(*this, loc, *other);
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

  void add_comment(SourceLocation loc)
  {
    // Comments are simply stored as monostate in the map, they are
    // resolved only when the comment is used.
    state_->metadata_.emplace(std::move(loc), MetadataIndex::CommentSentinel{});
  }

  void add_vspace(SourceLocation loc, size_t elems)
  {
    // Vspace is stored as a simple unsigned value.
    state_->metadata_.emplace(std::move(loc),
                              MetadataIndex::VspaceSentinel{ .amount = elems });
  }

  // This function returns a unique a metadata object for the AST.
  //
  // This object consumed by this call is a copy, and can be used
  // to iterate over all the available metadata while printing.
  MetadataIndex metadata() const
  {
    return { source_, state_->metadata_ };
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
    MetadataIndex::InternalMap metadata_;
  };

  std::unique_ptr<State> state_;
  std::shared_ptr<ASTSource> source_;

  friend class bpftrace::Driver;
  friend class Node;
};

} // namespace ast
} // namespace bpftrace
