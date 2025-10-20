#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "ast/context.h"
#include "ast/pass_manager.h"
#include "util/cache.h"

namespace bpftrace::ast {

class ScriptObject {
public:
  ScriptObject(ASTContext &&ast, bool internal)
      : ast(std::move(ast)), internal(internal) {};

  // The parsed source context.
  ASTContext ast;

  // Indicates whether or not this came from an internal source (e.g. the
  // standard library). This may be used by subsequent passes to import/resolve
  // in different orders or at different times.
  const bool internal;
};

class ImportObject {
public:
  using CacheObject = util::CacheObject;
  ImportObject(Node &node, CacheObject obj) : node(node), obj(std::move(obj)) {};
  Node &node;
  const CacheObject obj;
};

// Imports holds the set of imported modules. This includes the parsed ASTs for
// any source files, the loaded module for serialized modules, any dlhandles
// for loaded dynamic plugins, and the BPF objects for any binary blobs.
class Imports : public ast::State<"imports"> {
public:
  std::map<std::string, ImportObject> c_sources;
  std::map<std::string, ImportObject> c_headers;
  std::map<std::string, ImportObject> objects;
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
Pass CreateResolveImportsPass(std::vector<std::string> &&import_paths = {});

} // namespace bpftrace::ast
