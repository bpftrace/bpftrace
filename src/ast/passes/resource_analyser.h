#pragma once

#include <iostream>
#include <sstream>

#include "pass_manager.h"
#include "required_resources.h"
#include "visitors.h"

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
class ResourceAnalyser : public Visitor
{
public:
  ResourceAnalyser(Node *root);

  // Note we don't return errors here b/c we assume we are run after
  // semantic analysis and AST is well formed.
  RequiredResources analyse();

private:
  void visit(Probe &probe) override;
  void visit(Builtin &map) override;
  void visit(Call &call) override;
  void visit(Map &map) override;

  // All the seq_printf format strings are stored head to tail in a data
  // map. This method loads `RequiredResources::seq_printf_ids` with the
  // starting indicies and lengths of each format string in the data map.
  void prepare_seq_printf_ids();

  RequiredResources resources_;
  Node *root_;
  // Current probe we're analysing
  Probe *probe_;
};

Pass CreateResourcePass();

} // namespace ast
} // namespace bpftrace
