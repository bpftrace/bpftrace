#pragma once

#include <ostream>

#include "ast/visitors.h"

namespace bpftrace {
namespace ast {

class Clone : public Visitor {
private:
  // CopyNode uses dynamic dispatch to make a copy of the given type. All
  // the internal values will point to the same external values, and will
  // need to be rewritten.
  class CopyNode : public VisitorBase {
  public:
    CopyNode(ASTContext &ctx) : ctx_(ctx)
    {
    }
    virtual void visit(Integer &integer) override
    {
      result_ = ctx_.make_node<Integer>(integer);
    }
    virtual void visit(PositionalParameter &integer) override
    {
      result_ = ctx_.make_node<PositionalParameter>(integer);
    }
    virtual void visit(String &string) override
    {
      result_ = ctx_.make_node<String>(string);
    }
    virtual void visit(Builtin &builtin) override
    {
      result_ = ctx_.make_node<Builtin>(builtin);
    }
    virtual void visit(Identifier &identifier) override
    {
      result_ = ctx_.make_node<Identifier>(identifier);
    }
    virtual void visit(StackMode &mode) override
    {
      result_ = ctx_.make_node<StackMode>(mode);
    }
    virtual void visit(Call &call) override
    {
      result_ = ctx_.make_node<Call>(call);
    }
    virtual void visit(Sizeof &szof) override
    {
      result_ = ctx_.make_node<Sizeof>(szof);
    }
    virtual void visit(Offsetof &ofof) override
    {
      result_ = ctx_.make_node<Offsetof>(ofof);
    }
    virtual void visit(Map &map) override
    {
      result_ = ctx_.make_node<Map>(map);
    }
    virtual void visit(Variable &var) override
    {
      result_ = ctx_.make_node<Variable>(var);
    }
    virtual void visit(Binop &binop) override
    {
      result_ = ctx_.make_node<Binop>(binop);
    }
    virtual void visit(Unop &unop) override
    {
      result_ = ctx_.make_node<Unop>(unop);
    }
    virtual void visit(Ternary &ternary) override
    {
      result_ = ctx_.make_node<Ternary>(ternary);
    }
    virtual void visit(FieldAccess &acc) override
    {
      result_ = ctx_.make_node<FieldAccess>(acc);
    }
    virtual void visit(ArrayAccess &arr) override
    {
      result_ = ctx_.make_node<ArrayAccess>(arr);
    }
    virtual void visit(Cast &cast) override
    {
      result_ = ctx_.make_node<Cast>(cast);
    }
    virtual void visit(Tuple &tuple) override
    {
      result_ = ctx_.make_node<Tuple>(tuple);
    }
    virtual void visit(ExprStatement &expr) override
    {
      result_ = ctx_.make_node<ExprStatement>(expr);
    }
    virtual void visit(AssignMapStatement &assignment) override
    {
      result_ = ctx_.make_node<AssignMapStatement>(assignment);
    }
    virtual void visit(AssignVarStatement &assignment) override
    {
      result_ = ctx_.make_node<AssignVarStatement>(assignment);
    }
    virtual void visit(AssignConfigVarStatement &assignment) override
    {
      result_ = ctx_.make_node<AssignConfigVarStatement>(assignment);
    }
    virtual void visit(VarDeclStatement &decl) override
    {
      result_ = ctx_.make_node<VarDeclStatement>(decl);
    }
    virtual void visit(If &if_node) override
    {
      result_ = ctx_.make_node<If>(if_node);
    }
    virtual void visit(Jump &jump) override
    {
      result_ = ctx_.make_node<Jump>(jump);
    }
    virtual void visit(Unroll &unroll) override
    {
      result_ = ctx_.make_node<Unroll>(unroll);
    }
    virtual void visit(While &while_block) override
    {
      result_ = ctx_.make_node<While>(while_block);
    }
    virtual void visit(For &for_loop) override
    {
      result_ = ctx_.make_node<For>(for_loop);
    }
    virtual void visit(Predicate &pred) override
    {
      result_ = ctx_.make_node<Predicate>(pred);
    }
    virtual void visit(AttachPoint &ap) override
    {
      result_ = ctx_.make_node<AttachPoint>(ap);
    }
    virtual void visit(Probe &probe) override
    {
      result_ = ctx_.make_node<Probe>(probe);
    }
    virtual void visit(Config &config) override
    {
      result_ = ctx_.make_node<Config>(config);
    }
    virtual void visit(Block &block) override
    {
      result_ = ctx_.make_node<Block>(block);
    }
    virtual void visit(SubprogArg &subprog_arg) override
    {
      result_ = ctx_.make_node<SubprogArg>(subprog_arg);
    }
    virtual void visit(Subprog &subprog) override
    {
      result_ = ctx_.make_node<Subprog>(subprog);
    }
    virtual void visit(Program &program) override
    {
      result_ = ctx_.make_node<Program>(program);
    }
    ASTContext &ctx_;
    Node *result_;
  };

public:
  explicit Clone(ASTContext &dst) : dst_(dst)
  {
  }

  template <typename T>
  void clone(T **t)
  {
    // Lookup the casted expression in our remapped database, and if it already
    // exists then return a reference to it.
    auto key = static_cast<Node *>(*t);
    if (key == nullptr)
      return;
    auto it = remapped_.find(key);
    if (it != remapped_.end()) {
      *t = static_cast<T *>(it->second);
      return;
    }
    // Otherwise, instantiate and copy the object, and push it to the stack. We
    // then visit the copy to recursively clone its parts.
    CopyNode copier(dst_);
    (*t)->accept(copier);
    Node *copy = copier.result_;
    remapped_[key] = copy;
    copy->accept(*this);
    *t = static_cast<T *>(copy);
    // Rewrite the expression bits.
    if constexpr (std::is_base_of_v<Expression, T>) {
      clone(&((*t)->key_for_map));
      clone(&((*t)->map));
      clone(&((*t)->var));
    }
    return;
  }
  template <typename T>
  void clone(std::vector<T *> *in)
  {
    for (auto &val : *in) {
      clone(&val);
    }
  }

  virtual void visit(Call &call) override
  {
    clone(&call.vargs);
  }
  virtual void visit(Sizeof &szof) override
  {
    clone(&szof.expr);
  }
  virtual void visit(Offsetof &ofof) override
  {
    clone(&ofof.expr);
  }
  virtual void visit(Map &map) override
  {
    clone(&map.key_expr);
  }
  virtual void visit(Binop &binop) override
  {
    clone(&binop.left);
    clone(&binop.right);
  }
  virtual void visit(Unop &unop) override
  {
    clone(&unop.expr);
  }
  virtual void visit(Ternary &ternary) override
  {
    clone(&ternary.cond);
    clone(&ternary.left);
    clone(&ternary.right);
  }
  virtual void visit(FieldAccess &acc) override
  {
    clone(&acc.expr);
  }
  virtual void visit(ArrayAccess &arr) override
  {
    clone(&arr.expr);
    clone(&arr.indexpr);
  }
  virtual void visit(Cast &cast) override
  {
    clone(&cast.expr);
  }
  virtual void visit(Tuple &tuple) override
  {
    clone(&tuple.elems);
  }
  virtual void visit(ExprStatement &expr) override
  {
    clone(&expr.expr);
  }
  virtual void visit(AssignMapStatement &assignment) override
  {
    clone(&assignment.map);
    clone(&assignment.expr);
  }
  virtual void visit(AssignVarStatement &assignment) override
  {
    clone(&assignment.var_decl_stmt);
    clone(&assignment.var);
    clone(&assignment.expr);
  }
  virtual void visit(AssignConfigVarStatement &assignment) override
  {
    clone(&assignment.expr);
  }
  virtual void visit(VarDeclStatement &decl) override
  {
    clone(&decl.var);
  }
  virtual void visit(If &if_node) override
  {
    clone(&if_node.cond);
    clone(&if_node.if_block);
    clone(&if_node.else_block);
  }
  virtual void visit(Jump &jump) override
  {
    clone(&jump.return_value);
  }
  virtual void visit(Unroll &unroll) override
  {
    clone(&unroll.expr);
    clone(&unroll.block);
  }
  virtual void visit(While &while_block) override
  {
    clone(&while_block.cond);
    clone(&while_block.block);
  }
  virtual void visit(For &for_loop) override
  {
    clone(&for_loop.decl);
    clone(&for_loop.expr);
    clone(&for_loop.stmts);
  }
  virtual void visit(Predicate &pred) override
  {
    clone(&pred.expr);
  }
  virtual void visit(Probe &probe) override
  {
    clone(&probe.attach_points);
    clone(&probe.pred);
    clone(&probe.block);
  }
  virtual void visit(Config &config) override
  {
    clone(&config.stmts);
  }
  virtual void visit(Block &block) override
  {
    clone(&block.stmts);
  }
  virtual void visit(Subprog &subprog) override
  {
    clone(&subprog.args);
    clone(&subprog.stmts);
  }
  virtual void visit(Program &program) override
  {
    clone(&program.config);
    clone(&program.functions);
    clone(&program.probes);
  }

private:
  ASTContext &dst_;
  std::unordered_map<Node *, Node *> remapped_;
};

} // namespace ast
} // namespace bpftrace
