#pragma once
#include "visitors.h"

namespace bpftrace {
namespace ast {

class NodeCounter : public Visitor
{
public:
  void Visit(Node &node)
  {
    count_++;
    Visitor::Visit(node);
  }

  size_t get_count()
  {
    return count_;
  };

private:
  size_t count_ = 0;
};

} // namespace ast
} // namespace bpftrace
