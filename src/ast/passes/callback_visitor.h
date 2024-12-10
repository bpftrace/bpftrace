#pragma once

#include <functional>

#include "ast/visitor.h"

namespace bpftrace {
namespace ast {

using callback = std::function<void(Node *)>;

class CallbackVisitor : public Visitor<CallbackVisitor> {
public:
  explicit CallbackVisitor(callback func) : func_(func)
  {
  }
  void preVisit(Node &node)
  {
    func_(&node);
  }

private:
  callback func_;
};

} // namespace ast
} // namespace bpftrace
