#pragma once

#include <iostream>
#include <sstream>

#include "ast/pass_manager.h"
#include "ast/visitor.h"
#include "required_resources.h"

namespace bpftrace {
namespace ast {

// Resource analysis pass on AST
//
// This pass collects information on what runtime resources a script needs.
// For example, how many maps to create, what sizes the keys and values are,
// all the async printf argument types, etc.
//
// TODO(danobi): Note that while complete resource collection in this pass is
// the goal, there are still places where the goal is not yet realized. For
// example the helper error metadata is still being collected during codegen.
class ResourceAnalyser : public Visitor<ResourceAnalyser> {
public:
  ResourceAnalyser(ASTContext &ctx,
                   BPFtrace &bpftrace,
                   std::ostream &out = std::cerr);

  std::optional<RequiredResources> analyse();

  using Visitor<ResourceAnalyser>::visit;
  void visit(Probe &probe);
  void visit(Subprog &subprog);
  void visit(Builtin &map);
  void visit(Call &call);
  void visit(Map &map);
  void visit(Tuple &tuple);
  void visit(For &f);
  void visit(Ternary &ternary);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(VarDeclStatement &decl);

private:
  // Determines whether the given function uses userspace symbol resolution.
  // This is used later for loading the symbol table into memory.
  bool uses_usym_table(const std::string &fun);

  bool exceeds_stack_limit(size_t size);

  void maybe_allocate_map_key_buffer(const Map &map);

  void update_map_info(Map &map);
  void update_variable_info(Variable &var);

  RequiredResources resources_;
  BPFtrace &bpftrace_;
  std::ostream &out_;
  std::ostringstream err_;
  // Current probe we're analysing
  Probe *probe_;

  int next_map_id_ = 0;
};

Pass CreateResourcePass();

} // namespace ast
} // namespace bpftrace
