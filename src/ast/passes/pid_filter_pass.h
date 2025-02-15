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
  bool probe_needs_pid_filter(AttachPoint *attach_point);
  Statement *add_pid_filter(const location &loc);
};

Pass CreatePidFilterPass();

} // namespace ast
} // namespace bpftrace
