#pragma once

#include <string>
#include <vector>

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Imports holds the set of imported modules. This includes the parsed ASTs for
// any source files, the loaded module for serialized modules, any dlhandles
// for loaded dynamic plugins, and the BPF objects for any binary blobs.
//
// It is currently empty.
class Imports : public ast::State<"imports"> {};

Pass CreateResolveImportsPass(std::vector<std::string> &&import_paths);

} // namespace bpftrace::ast
