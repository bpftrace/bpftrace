#pragma once

#include "vtable.h"
#include <string>

#include "ast.h"

namespace bpftrace {
namespace ast {

/**
   Base visitor for double dispatch based visitation
*/
class VisitorBase
{
public:
  virtual ~VisitorBase() = default;
  virtual void visit(Integer &integer) = 0;
  virtual void visit(PositionalParameter &integer) = 0;
  virtual void visit(String &string) = 0;
  virtual void visit(Builtin &builtin) = 0;
  virtual void visit(Identifier &identifier) = 0;
  virtual void visit(StackMode &mode) = 0;
  virtual void visit(Call &call) = 0;
  virtual void visit(Map &map) = 0;
  virtual void visit(Variable &var) = 0;
  virtual void visit(Binop &binop) = 0;
  virtual void visit(Unop &unop) = 0;
  virtual void visit(Ternary &ternary) = 0;
  virtual void visit(FieldAccess &acc) = 0;
  virtual void visit(ArrayAccess &arr) = 0;
  virtual void visit(Cast &cast) = 0;
  virtual void visit(Tuple &tuple) = 0;
  virtual void visit(ExprStatement &expr) = 0;
  virtual void visit(AssignMapStatement &assignment) = 0;
  virtual void visit(AssignVarStatement &assignment) = 0;
  virtual void visit(If &if_block) = 0;
  virtual void visit(Jump &jump) = 0;
  virtual void visit(Unroll &unroll) = 0;
  virtual void visit(While &while_block) = 0;
  virtual void visit(Predicate &pred) = 0;
  virtual void visit(AttachPoint &ap) = 0;
  virtual void visit(Probe &probe) = 0;
  virtual void visit(Program &program) = 0;
};

/**
   Basic tree walking visitor

   The Visit() method is called one for every node in the tree. Providing an
   easy way to run a generic method on all nodes.

   The individual visit() methods run on specific node types.
*/
class Visitor : public VisitorBase
{
public:
  explicit Visitor() = default;
  ~Visitor() = default;

  Visitor(const Visitor &) = delete;
  Visitor &operator=(const Visitor &) = delete;
  Visitor(Visitor &&) = delete;
  Visitor &operator=(Visitor &&) = delete;

  /*
    Visit a node
   */
  virtual inline void Visit(Node &n)
  {
    n.accept(*this);
  };

  /*
    Visitors for specific node types

    NB: visitor should dispatch through the Visit method and not use
    node->accept() directly
  */
  void visit(Integer &integer) override;
  void visit(PositionalParameter &param) override;
  void visit(String &string) override;
  void visit(StackMode &mode) override;
  void visit(Identifier &identifier) override;
  void visit(Builtin &builtin) override;
  void visit(Call &call) override;
  void visit(Map &map) override;
  void visit(Variable &var) override;
  void visit(Binop &binop) override;
  void visit(Unop &unop) override;
  void visit(Ternary &ternary) override;
  void visit(FieldAccess &acc) override;
  void visit(ArrayAccess &arr) override;
  void visit(Cast &cast) override;
  void visit(Tuple &tuple) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(If &if_block) override;
  void visit(Unroll &unroll) override;
  void visit(While &while_block) override;
  void visit(Jump &jump) override;
  void visit(Predicate &pred) override;
  void visit(AttachPoint &ap) override;
  void visit(Probe &probe) override;
  void visit(Program &program) override;
};

/**
   Base class for vtable based dispatching

   \tparam R return type for visitors
*/
template <typename R>
class Dispatcher
{
private:
  using tabletype = VTable<R, Node, Dispatcher>;
  using mytype = Dispatcher;

public:
  virtual ~Dispatcher() = default;

  /**
     Visit handles the dispatching on node type
   */
  virtual R Visit(Node &node)
  {
    static tabletype table = make_vtable();
    return table(node, this);
  };

#define DEFAULT_FN                                                             \
  {                                                                            \
    return default_visitor(node);                                              \
  }

  /**
      Visitors for node subtypes
   */
  virtual R visit(Integer &node) DEFAULT_FN;
  virtual R visit(PositionalParameter &node) DEFAULT_FN;
  virtual R visit(String &node) DEFAULT_FN;
  virtual R visit(Builtin &node) DEFAULT_FN;
  virtual R visit(Identifier &node) DEFAULT_FN;
  virtual R visit(StackMode &node) DEFAULT_FN;
  virtual R visit(Call &node) DEFAULT_FN;
  virtual R visit(Map &node) DEFAULT_FN;
  virtual R visit(Variable &node) DEFAULT_FN;
  virtual R visit(Binop &node) DEFAULT_FN;
  virtual R visit(Unop &node) DEFAULT_FN;
  virtual R visit(Ternary &node) DEFAULT_FN;
  virtual R visit(FieldAccess &node) DEFAULT_FN;
  virtual R visit(ArrayAccess &node) DEFAULT_FN;
  virtual R visit(Cast &node) DEFAULT_FN;
  virtual R visit(Tuple &node) DEFAULT_FN;
  virtual R visit(ExprStatement &node) DEFAULT_FN;
  virtual R visit(AssignMapStatement &node) DEFAULT_FN;
  virtual R visit(AssignVarStatement &node) DEFAULT_FN;
  virtual R visit(If &node) DEFAULT_FN;
  virtual R visit(Jump &node) DEFAULT_FN;
  virtual R visit(Unroll &node) DEFAULT_FN;
  virtual R visit(While &node) DEFAULT_FN;
  virtual R visit(Predicate &node) DEFAULT_FN;
  virtual R visit(AttachPoint &node) DEFAULT_FN;
  virtual R visit(Probe &node) DEFAULT_FN;
  virtual R visit(Program &node) DEFAULT_FN;

  virtual R default_visitor(Node &node)
  {
    throw std::runtime_error(std::string("No visitor for: ") +
                             typeid(node).name());
  }

private:
// Helper for easily defining vtable entries
#define DEFINE_DISPATCH(T)                                                     \
  {                                                                            \
    table.template set<T>(                                                     \
        [](Node &n, mytype *v) { return v->visit(static_cast<T &>(n)); });     \
  }

  static tabletype make_vtable()
  {
    tabletype table;
    DEFINE_DISPATCH(Integer);
    DEFINE_DISPATCH(PositionalParameter);
    DEFINE_DISPATCH(String);
    DEFINE_DISPATCH(StackMode);
    DEFINE_DISPATCH(Identifier);
    DEFINE_DISPATCH(Builtin);
    DEFINE_DISPATCH(Call);
    DEFINE_DISPATCH(Map);
    DEFINE_DISPATCH(Variable);
    DEFINE_DISPATCH(Binop);
    DEFINE_DISPATCH(Unop);
    DEFINE_DISPATCH(FieldAccess);
    DEFINE_DISPATCH(ArrayAccess);
    DEFINE_DISPATCH(Cast);
    DEFINE_DISPATCH(Tuple);
    DEFINE_DISPATCH(ExprStatement);
    DEFINE_DISPATCH(AssignMapStatement);
    DEFINE_DISPATCH(AssignVarStatement);
    DEFINE_DISPATCH(If);
    DEFINE_DISPATCH(Unroll);
    DEFINE_DISPATCH(Jump);
    DEFINE_DISPATCH(Predicate);
    DEFINE_DISPATCH(Ternary);
    DEFINE_DISPATCH(While);
    DEFINE_DISPATCH(AttachPoint);
    DEFINE_DISPATCH(Probe);
    DEFINE_DISPATCH(Program);

    return table;
  }
};
#undef DEFINE_DISPATCH
#undef DEFAULT_FN

/**
   Base for tree mutators

   Mutators are used to create a modified AST. While iterating the tree they
   construct a copy which will be returned at the end. This makes it possible
   to write optimizing passes.

*/

class Mutator : public Dispatcher<Node *>
{
public:
  Mutator(){};

  Node *visit(Integer &) override;
  Node *visit(PositionalParameter &) override;
  Node *visit(String &) override;
  Node *visit(Builtin &) override;
  Node *visit(Identifier &) override;
  Node *visit(StackMode &) override;
  Node *visit(Call &) override;
  Node *visit(Map &) override;
  Node *visit(Variable &) override;
  Node *visit(Binop &) override;
  Node *visit(Unop &) override;
  Node *visit(Ternary &) override;
  Node *visit(FieldAccess &) override;
  Node *visit(ArrayAccess &) override;
  Node *visit(Cast &) override;
  Node *visit(Tuple &) override;
  Node *visit(ExprStatement &) override;
  Node *visit(AssignMapStatement &) override;
  Node *visit(AssignVarStatement &) override;
  Node *visit(If &) override;
  Node *visit(Jump &) override;
  Node *visit(Unroll &) override;
  Node *visit(While &) override;
  Node *visit(Predicate &) override;
  Node *visit(AttachPoint &) override;
  Node *visit(Probe &) override;
  Node *visit(Program &) override;

protected:
  // Value is a type casting wrapper for Visit()
  template <typename T>
  T *Value(Node *n);

  /*
    visit each node in the list and return the modified list
   */
  ExpressionList *mutateExprList(ExpressionList *src);
  StatementList *mutateStmtList(StatementList *src);
};

} // namespace ast
} // namespace bpftrace
