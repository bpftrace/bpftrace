#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "ast/context.h"
#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Imports holds the set of imported modules. This includes the parsed ASTs for
// any source files, the loaded module for serialized modules, any dlhandles
// for loaded dynamic plugins, and the BPF objects for any binary blobs.
class Imports : public ast::State<"imports"> {
public:
  std::unordered_map<std::filesystem::path, std::unique_ptr<ASTContext>> native;
  std::unordered_map<std::filesystem::path, std::string> objects;
};

Pass CreateResolveImportsPass(std::vector<std::string> &&import_paths);

} // namespace bpftrace::ast
