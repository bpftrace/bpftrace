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

namespace bpftrace::ast {

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

class ScriptObject {
public:
  ScriptObject(Node &node, ASTContext &&ast, bool internal)
      : node(node), ast(std::move(ast)), internal(internal) {};

  // Per above, the original node.
  Node &node;

  // The parsed source context.
  ASTContext ast;

  // Indicates whether or not this came from an internal source (e.g. the
  // standard library). This may be used by subsequent passes to import/resolve
  // in different orders or at different times.
  const bool internal;
};

// Imports holds the set of imported modules. This includes the parsed ASTs for
// any source files, the loaded module for serialized modules, any dlhandles
// for loaded dynamic plugins, and the BPF objects for any binary blobs.
class Imports : public ast::State<"imports"> {
public:
  std::map<std::string, LoadedObject> c_sources;
  std::map<std::string, LoadedObject> c_headers;
  std::map<std::string, ExternalObject> objects;
  std::map<std::string, ScriptObject> scripts;

  // Public import call.
  Result<OK> import_any(Node &node,
                        const std::string &name,
                        const std::vector<std::filesystem::path> &paths = {});

private:
  Result<OK> import_any(Node &node,
                        const std::string &name,
                        const std::filesystem::path &path,
                        const std::vector<std::filesystem::path> &paths,
                        bool ignore_unknown,
                        bool allow_directories);

  Result<OK> import_any(Node &node,
                        const std::string &name,
                        const std::string_view &data,
                        const std::vector<std::filesystem::path> &paths,
                        bool ignore_unknown);

  // Record full packages/directories that have been imported separately from
  // the specific modules, in order to avoid re-importing these paths.
  std::unordered_set<std::string> packages_;
};

// This pass resolves imports from the AST itself.
Pass CreateResolveRootImportsPass(std::vector<std::string> &&import_paths = {});
Pass CreateResolveStatementImportsPass();

} // namespace bpftrace::ast
