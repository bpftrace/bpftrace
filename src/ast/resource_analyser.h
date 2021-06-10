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
class ResourceAnalyser : public Visitor
{
public:
  ResourceAnalyser(Node *root);

  // Note we don't return errors here b/c we assume we are run after
  // semantic analysis and AST is well formed.
  RequiredResources analyse();

private:
  RequiredResources resources_;
  Node *root_;
};

Pass CreateResourcePass();

} // namespace ast
} // namespace bpftrace
