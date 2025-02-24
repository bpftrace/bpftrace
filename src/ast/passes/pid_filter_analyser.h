#pragma once

#include <iostream>
#include <sstream>
#include <unordered_set>

#include "ast/pass_manager.h"
#include "ast/visitor.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "collect_nodes.h"
#include "config.h"
#include "types.h"

namespace bpftrace {
namespace ast {

class PidFilterAnalyser : public Visitor<PidFilterAnalyser> {
public:
  explicit PidFilterAnalyser(ASTContext &ctx, BPFtrace &bpftrace)
      : Visitor<PidFilterAnalyser>(ctx), bpftrace_(bpftrace)
  {
  }

  using Visitor<PidFilterAnalyser>::visit;
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
