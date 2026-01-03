#pragma once

#include <unordered_set>

#include "ast/visitor.h"
#include "config.h"

namespace bpftrace::ast {

struct CodegenResources {
  bool needs_elapsed_map = false;
  bool needs_join_map = false;
};

// Codegen resource analysis pass
//
// This pass collects specific information codegen later needs. All this
// could be done in codegen pass itself, but splitting out some "prerun"
// logic makes things easier to understand and maintain.
class CodegenResourceAnalyser : public Visitor<CodegenResourceAnalyser> {
public:
  CodegenResourceAnalyser(const ::bpftrace::Config &config);
  CodegenResources analyse(Program &program);

  using Visitor<CodegenResourceAnalyser>::visit;
  void visit(Builtin &builtin);
  void visit(Call &call);

private:
  const ::bpftrace::Config &config_;
  CodegenResources resources_;
};

} // namespace bpftrace::ast
