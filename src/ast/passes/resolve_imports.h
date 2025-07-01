#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "ast/context.h"
#include "ast/pass_manager.h"

namespace bpftrace {

class BPFtrace;

namespace ast {

class ASTContext;

// LoadedObject is a generic wrapper around some data that was either embedded,
// or has been loaded off the filesystem. We no longer depend on any files.
class LoadedObject {
public:
  LoadedObject(Node &node, const std::string_view &data)
      : node(node), data_(data) {};
  LoadedObject(Node &node, std::string &&data)
      : node(node), data_(std::move(data)) {};

  std::string_view data()
  {
    return std::visit([](const auto &v) -> std::string_view { return v; },
                      data_);
  }

  // Original node, for errors.
  Node &node;

private:
  // The reason for this extra indirection: the data is either owned,
  // or it will be a reference to something immutable in the binary.
  const std::variant<std::string_view, std::string> data_;
};

class ExternalObject {
public:
  ExternalObject(Node &node, std::filesystem::path path)
      : node(node), path(std::move(path)) {};

  // Per above, the original node.
  Node &node;

  // Objects are left on the filesystem, since these paths are passed directly
  // to the linker.
  const std::filesystem::path path;
};

// Imports holds the set of imported modules. This includes the parsed ASTs for
// any source files, the loaded module for serialized modules, any dlhandles
// for loaded dynamic plugins, and the BPF objects for any binary blobs.
class Imports : public ast::State<"imports"> {
public:
  std::map<std::string, LoadedObject> c_sources;
  std::map<std::string, LoadedObject> c_headers;
  std::map<std::string, ExternalObject> objects;
  std::map<std::string, ASTContext> scripts;

  // Record full packages/directories that have been imported separately from
  // the specific modules, in order to avoid re-importing these paths.
  std::unordered_set<std::string> packages;
};

// Ensure the existing of some internal import.
Result<> ensure_import(ASTContext &ast,
                       BPFtrace &b,
                       Imports &imports,
                       const std::string &name);

// This pass resolves imports from the AST itself. It produces an `Imports`
// object. This can later be added to via the `ensure_import` function call
// above, if needed.
Pass CreateResolveImportsPass(std::vector<std::string> &&import_paths);

} // namespace ast
} // namespace bpftrace
