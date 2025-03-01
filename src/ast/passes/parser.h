#pragma once

#include "ast/pass_manager.h"

namespace bpftrace {
namespace ast {

// The parse pass will take the raw source in the AST, and parse it into the
// three that you expect.
Pass CreateParsePass(bool debug = false);

// The attachpoints are expanded in their own separate pass.
Pass CreateParseAttachpointPass();

// The BTF parser pass will extract necessary type information.
Pass CreateParseBTFPass();

// This will parse tracepoints specifically.
Pass CreateParseTracepointFormatParsePass();

// Macros are compiler macros that have been extracted from C. These are used
// during the paring process to expand identifiers.
class Macros : public ast::State<"macros"> {
public:
  std::map<std::string, std::string> macros;
};

// Reparse is exactly the same pass as Parse, except it requires `Macros` as
// input. Therefore, it should only be used *after* ClangParser has been run.
Pass CreateReparsePass();

} // namespace ast
} // namespace bpftrace
