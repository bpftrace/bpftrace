#pragma once

#include <cstdint>
#include <unordered_set>

#include "ast/visitors.h"
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
class CodegenResourceAnalyser : public Visitor {
public:
  CodegenResourceAnalyser(ASTContext &ctx, const ::bpftrace::Config &config);
  CodegenResources analyse();

private:
  void visit(Builtin &map) override;
  void visit(Call &call) override;

private:
  const ::bpftrace::Config &config_;
  CodegenResources resources_;
};

} // namespace ast
} // namespace bpftrace
