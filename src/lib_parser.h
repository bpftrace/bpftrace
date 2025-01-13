#pragma once

#include <filesystem>
#include <string_view>

namespace bpftrace {

class FunctionRegistry;
class StructManager;

/**
 * Extracts information from pre-compiled BPF libraries
 */
class LibParser {
public:
  bool parse(std::string_view libName,
             std::filesystem::path libPath,
             FunctionRegistry &functions,
             StructManager &structs);
};

} // namespace bpftrace
