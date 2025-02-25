#pragma once

#include "ast/pass_manager.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace {
namespace ast {

class PidFilterPass : public Visitor<PidFilterPass> {
public:
  explicit PidFilterPass(ASTContext &ctx, BPFtrace &bpftrace)
      : Visitor<PidFilterPass>(ctx), bpftrace_(bpftrace)
  {
  }

  using Visitor<PidFilterPass>::visit;
  void visit(Probe &probe);

  void analyse();

private:
  BPFtrace &bpftrace_;
};

Pass CreatePidFilterPass();

} // namespace ast
} // namespace bpftrace
