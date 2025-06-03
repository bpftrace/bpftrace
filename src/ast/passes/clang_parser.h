#pragma once

#include "ast/pass_manager.h"
#include <map>

namespace bpftrace::ast {

// When the imported definitions are parsed with clang, relevant C definitions
// are centralized here to be consumed by later passes.
class CDefinitions : public ast::State<"C-definitions"> {
public:
  // Map of macro name to macro definition.
  std::map<std::string, std::string> macros;

  // Map of enum variant_name to (variant_value, enum_name).
  std::map<std::string, std::tuple<uint64_t, std::string>> enums;

  // Map of enum_name to map of variant_value to variant_name.
  std::map<std::string, std::map<uint64_t, std::string>> enum_defs;
};

class ClangParseError : public ErrorInfo<ClangParseError> {
public:
  static char ID;
  void log(llvm::raw_ostream &OS) const override;
};

ast::Pass CreateClangParsePass(std::vector<std::string> &&extra_flags = {});

} // namespace bpftrace::ast
