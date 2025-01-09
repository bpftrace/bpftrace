#pragma once

#include <cstdint>
#include <unordered_set>

#include "ast/visitor.h"
#include "config.h"

namespace bpftrace {
namespace ast {

struct CodegenResources {
  bool needs_elapsed_map = false;
  bool needs_join_map = false;
  std::unordered_set<StackType> stackid_maps;
};

// Codegen resource analysis pass
//
// This pass collects specific information codegen later needs. All this
// could be done in codegen pass itself, but splitting out some "prerun"
// logic makes things easier to understand and maintain.
class CodegenResourceAnalyser : public Visitor<CodegenResourceAnalyser> {
public:
  CodegenResourceAnalyser(ASTContext &ctx, const ::bpftrace::Config &config);
  CodegenResources analyse();

  using Visitor<CodegenResourceAnalyser>::visit;
  void visit(Builtin &map);
  void visit(Call &call);

private:
  const ::bpftrace::Config &config_;
  CodegenResources resources_;
};

} // namespace ast
} // namespace bpftrace
