#pragma once

#include <filesystem>
#include <map>
#include <string>
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
  LoadedObject(Node &node, const std::string &data)
      : node(node), data_(std::ref(data)) {};
  LoadedObject(Node &node, std::string &&data)
      : node(node), data_(std::move(data)) {};

  const std::string &data()
  {
    if (std::holds_alternative<std::string>(data_)) {
      return std::get<std::string>(data_);
    } else {
      return std::get<std::reference_wrapper<std::string>>(data_).get();
    }
  }

  // Original node, for errors.
  Node &node;

private:
  // The reason for this extra indirection: the data is either owned,
  // or it will be a reference to something immutable in the binary.
  std::variant<std::reference_wrapper<std::string>, std::string> data_;
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
};

Pass CreateResolveImportsPass(std::vector<std::string> &&import_paths);

} // namespace bpftrace::ast
