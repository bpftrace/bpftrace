#pragma once

#include <iostream>
#include <sstream>

#include "ast/pass_manager.h"
#include "ast/visitors.h"
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
class ResourceAnalyser : public Visitor {
public:
  ResourceAnalyser(Node *root, std::ostream &out = std::cerr);

  std::optional<RequiredResources> analyse();

private:
  void visit(Probe &probe) override;
  void visit(Builtin &map) override;
  void visit(Call &call) override;
  void visit(Map &map) override;

  // seq_printf, debugf format strings are stored head to tail in a data
  // map. This method loads `RequiredResources::mapped_printf_ids` with the
  // starting indices and lengths of each format string in the data map.
  void prepare_mapped_printf_ids();

  // Determines whether the given function uses userspace symbol resolution.
  // This is used later for loading the symbol table into memory.
  bool uses_usym_table(const std::string &fun);

  RequiredResources resources_;
  Node *root_;
  std::ostream &out_;
  std::ostringstream err_;
  // Current probe we're analysing
  Probe *probe_;
};

Pass CreateResourcePass();

} // namespace ast
} // namespace bpftrace
