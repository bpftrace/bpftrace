#pragma once

#include "ast/pass_manager.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

class ProbeAnalyser : public Visitor<ProbeAnalyser> {
public:
  explicit ProbeAnalyser(ASTContext &ctx, BPFtrace &bpftrace)
      : ctx_(ctx), bpftrace_(bpftrace)
  {
  }

  using Visitor<ProbeAnalyser>::visit;
  void visit(Probe &probe);

  void analyse();

private:
  const ASTContext &ctx_;
  const BPFtrace &bpftrace_;
};

Pass CreateProbePass();

} // namespace bpftrace::ast
