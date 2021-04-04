#pragma once

#include "bpftrace.h"
#include "pass_manager.h"
#include "visitors.h"

namespace bpftrace {
namespace ast {

class PositionalParamTransformer : public Mutator
{
public:
  PositionalParamTransformer() = delete;
  PositionalParamTransformer(BPFtrace *bpftrace) : bpftrace_(bpftrace){};

private:
  Node *visit(PositionalParameter &param);
  Node *visit(Call &call);
  Node *visit(Binop &binop);

  BPFtrace *bpftrace_ = nullptr;
  bool in_str_ = false;

  std::ostringstream err_;

  friend Pass CreateRemovePositionalParamPass();
};

Pass CreateRemovePositionalParamPass();

} // namespace ast
} // namespace bpftrace
