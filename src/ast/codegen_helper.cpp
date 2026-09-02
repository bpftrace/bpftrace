#include "codegen_helper.h"

#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

class IterLoopVarCollector : public Visitor<IterLoopVarCollector> {
public:
  using Visitor<IterLoopVarCollector>::visit;

  void visit(For &f)
  {
    bool outer = in_iter_loop_;
    in_iter_loop_ = in_iter_loop_ || f.iterable.is<Call>();
    Visitor<IterLoopVarCollector>::visit(f);
    in_iter_loop_ = outer;
  }

  void visit(AssignVarStatement &assignment)
  {
    if (in_iter_loop_) {
      idents_.insert(assignment.var()->ident);
    }
    Visitor<IterLoopVarCollector>::visit(assignment);
  }

  void visit(Unop &unop)
  {
    if (in_iter_loop_ && is_inc_dec(unop.op)) {
      if (auto *var = unop.expr.as<Variable>()) {
        idents_.insert(var->ident);
      }
    }
    Visitor<IterLoopVarCollector>::visit(unop);
  }

  std::unordered_set<std::string> take()
  {
    return std::move(idents_);
  }

private:
  static bool is_inc_dec(Operator op)
  {
    return op == Operator::PRE_INCREMENT || op == Operator::POST_INCREMENT ||
           op == Operator::PRE_DECREMENT || op == Operator::POST_DECREMENT;
  }

  std::unordered_set<std::string> idents_;
  bool in_iter_loop_ = false;
};

} // namespace

template <typename T>
  requires std::same_as<T, Probe> || std::same_as<T, Subprog>
std::unordered_set<std::string> collectIterLoopVars(T &node)
{
  IterLoopVarCollector collector;
  collector.visit(node);
  return collector.take();
}

template std::unordered_set<std::string> collectIterLoopVars(Probe &);
template std::unordered_set<std::string> collectIterLoopVars(Subprog &);

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

  return !inBpfMemory(dst);
}

} // namespace bpftrace::ast
