#include <unordered_set>

#include "ast/ast.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/recursion_check.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"
#include "probe_matcher.h"

namespace bpftrace::ast {

namespace {

const std::unordered_set<std::string> RECURSIVE_KERNEL_FUNCS = {
  "vmlinux:_raw_spin_lock",
  "vmlinux:_raw_spin_lock_irqsave",
  "vmlinux:_raw_spin_unlock_irqrestore",
  "vmlinux:queued_spin_lock_slowpath",
};

// Attaching to these kernel functions with fentry/fexit (kfunc/kretfunc)
// could lead to a recursive loop and kernel crash so we need additional
// generated BPF code to protect against this if one of these are being
// attached to.
bool is_recursive_func(const std::string &func_name)
{
  return RECURSIVE_KERNEL_FUNCS.contains(func_name);
}

class RecursionCheck : public Visitor<RecursionCheck> {
public:
  explicit RecursionCheck(BPFtrace &bpftrace, FunctionInfo &func_info)
      : bpftrace_(bpftrace), func_info_(func_info)
  {
  }

  using Visitor<RecursionCheck>::visit;
  void visit(Program &program);

private:
  BPFtrace &bpftrace_;
  FunctionInfo &func_info_;
};

} // namespace

// This prevents an ABBA deadlock when attaching to spin lock internal
// functions e.g. "fentry:queued_spin_lock_slowpath".
//
// Specifically, if there are two hash maps (non percpu) being accessed by
// two different CPUs by two bpf progs then we can get in a situation where,
// because there are progs attached to spin lock internals, a lock is taken for
// one map while a different lock is trying to be acquired for the other map.
// This is specific to fentry/fexit (kfunc/kretfunc) as kprobes have kernel
// protections against this type of deadlock.
//
// Note: it would be better if this was in resource analyzer but we need
// probe_matcher to get the list of functions for the attach point.
void RecursionCheck::visit(Program &program)
{
  ProbeMatcher probe_matcher(&bpftrace_,
                             func_info_.kernel_info(),
                             func_info_.user_info());
  for (auto *probe : program.probes) {
    for (auto *ap : probe->attach_points) {
      auto probe_type = probetype(ap->provider);
      if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit) {
        auto matches = probe_matcher.get_matches_for_ap(*ap);
        for (const auto &match : matches) {
          if (is_recursive_func(match)) {
            LOG(WARNING)
                << "Attaching to dangerous function: " << match
                << ". bpftrace has added mitigations to prevent a kernel "
                   "deadlock but they may result in some lost events.";
            bpftrace_.need_recursion_check_ = true;
            return;
          }
        }
      }
    }
  }
}

Pass CreateRecursionCheckPass()
{
  return Pass::create(
      "RecursionCheck",
      [](ASTContext &ast, BPFtrace &b, FunctionInfo &func_info) {
        auto recursion_check = RecursionCheck(b, func_info);
        recursion_check.visit(ast.root);
      });
};

} // namespace bpftrace::ast
