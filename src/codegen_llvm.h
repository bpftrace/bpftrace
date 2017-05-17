#pragma once

#include "ast.h"
#include "bpftrace.h"
#include "irbuilderbpf.h"
#include "map.h"

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

namespace ebpf {
namespace bpftrace {
namespace ast {

using namespace llvm;

class CodegenLLVM : public Visitor {
public:
  explicit CodegenLLVM(Node *root, BPFtrace &bpftrace) :
    root_(root),
    module_(std::make_unique<Module>("bpftrace", context_)),
    b_(context_, *module_.get(), bpftrace),
    bpftrace_(bpftrace)
    { }

  void visit(Integer &integer) override;
  void visit(Builtin &builtin) override;
  void visit(Call &call) override;
  void visit(Map &map) override;
  void visit(Binop &binop) override;
  void visit(Unop &unop) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignMapCallStatement &assignment) override;
  void visit(Predicate &pred) override;
  void visit(Probe &probe) override;
  void visit(Program &program) override;

  int compile(bool debug=false);
  AllocaInst *createAllocaBPF(llvm::Type *ty, const std::string &name="") const;

private:
  Node *root_;
  LLVMContext context_;
  std::unique_ptr<Module> module_;
  std::unique_ptr<ExecutionEngine> ee_;
  IRBuilderBPF b_;
  Value *expr_ = nullptr;
  BPFtrace &bpftrace_;

  enum bpf_func_id {
    BPF_FUNC_unspec,
    BPF_FUNC_map_lookup_elem,
    BPF_FUNC_map_update_elem,
    BPF_FUNC_map_delete_elem,
    BPF_FUNC_probe_read,
    BPF_FUNC_ktime_get_ns,
    BPF_FUNC_trace_printk,
    BPF_FUNC_get_prandom_u32,
    BPF_FUNC_get_smp_processor_id,
    BPF_FUNC_skb_store_bytes,
    BPF_FUNC_l3_csum_replace,
    BPF_FUNC_l4_csum_replace,
    BPF_FUNC_tail_call,
    BPF_FUNC_clone_redirect,
    BPF_FUNC_get_current_pid_tgid,
    BPF_FUNC_get_current_uid_gid,
    BPF_FUNC_get_current_comm,
    BPF_FUNC_get_cgroup_classid,
    BPF_FUNC_skb_vlan_push,
    BPF_FUNC_skb_vlan_pop,
    BPF_FUNC_skb_get_tunnel_key,
    BPF_FUNC_skb_set_tunnel_key,
    BPF_FUNC_perf_event_read,
    BPF_FUNC_redirect,
    BPF_FUNC_get_route_realm,
    BPF_FUNC_perf_event_output,
    BPF_FUNC_skb_load_bytes,
    BPF_FUNC_get_stackid,
  };
};

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
