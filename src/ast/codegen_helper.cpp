#include "codegen_helper.h"

#include "ast/visitor.h"
#include "log.h"

namespace bpftrace::ast {

namespace {

class IterVarCollector : public Visitor<IterVarCollector> {
public:
  using Visitor<IterVarCollector>::visit;

  void visit(While &w)
  {
    bool outer = in_iter_loop_;
    if (w.is_iter) {
      in_iter_loop_ = true;
      auto *assign = !w.block->stmts.empty()
                         ? w.block->stmts.front().as<AssignVarStatement>()
                         : nullptr;
      auto *call = assign != nullptr ? assign->expr.as<Call>() : nullptr;
      auto *addr = call != nullptr && call->is_kfunc() && !call->vargs.empty()
                       ? call->vargs.front().as<VariableAddr>()
                       : nullptr;
      if (assign == nullptr || addr == nullptr) {
        LOG(BUG) << "malformed desugared iterator loop";
      }
      skip_.insert(assign->var()->ident);
      vars_.state.insert(addr->var->ident);
    }
    Visitor<IterVarCollector>::visit(w);
    in_iter_loop_ = outer;
  }

  void visit(AssignVarStatement &assignment)
  {
    if (in_iter_loop_ && !skip_.contains(assignment.var()->ident)) {
      vars_.scratch.insert(assignment.var()->ident);
    }
    Visitor<IterVarCollector>::visit(assignment);
  }

  void visit(Unop &unop)
  {
    if (in_iter_loop_ && is_inc_dec(unop.op)) {
      if (auto *var = unop.expr.as<Variable>()) {
        vars_.scratch.insert(var->ident);
      }
    }
    Visitor<IterVarCollector>::visit(unop);
  }

  IterVars take()
  {
    return std::move(vars_);
  }

private:
  static bool is_inc_dec(Operator op)
  {
    return op == Operator::PRE_INCREMENT || op == Operator::POST_INCREMENT ||
           op == Operator::PRE_DECREMENT || op == Operator::POST_DECREMENT;
  }

  IterVars vars_;
  std::unordered_set<std::string> skip_;
  bool in_iter_loop_ = false;
};

} // namespace

template <typename T>
  requires std::same_as<T, Probe> || std::same_as<T, Subprog>
IterVars collectIterVars(T &node)
{
  IterVarCollector collector;
  collector.visit(node);
  return collector.take();
}

template IterVars collectIterVars(Probe &);
template IterVars collectIterVars(Subprog &);

bool needMapAllocation(const SizedType &src, const SizedType &dst)
{
  // For records (and records inside of tuples) the src and dst might have
  // fields out of order - for this case we need an allocation to copy
  // individual fields into so the original field ordering is preserved
  if (src.IsTupleTy() || src.IsRecordTy()) {
    if (src != dst) {
      return true;
    }
  }

  return dst.GetValueLocation() != ValueLocation::bpf_memory;
}

} // namespace bpftrace::ast
