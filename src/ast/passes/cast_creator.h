#pragma once

#include "ast/pass_manager.h"
#include "ast/visitor.h"

namespace bpftrace {
class BPFtrace;
} // namespace bpftrace

namespace bpftrace::ast {

bool try_tuple_cast(ASTContext &ctx,
                    Expression &exp,
                    const SizedType &expr_type,
                    const SizedType &target_type);

bool try_record_cast(ASTContext &ctx,
                     Expression &exp,
                     const SizedType &expr_type,
                     const SizedType &target_type);

class CastCreator : public Visitor<CastCreator> {
public:
  explicit CastCreator(ASTContext &ast, BPFtrace &bpftrace);

  using Visitor<CastCreator>::visit;
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(Binop &binop);
  void visit(BlockExpr &block);
  void visit(Cast &cast);
  void visit(IfExpr &if_expr);
  void visit(Jump &jump);
  void visit(Map &map);
  void visit(MapAccess &acc);
  void visit(Probe &probe);
  void visit(Subprog &subprog);
  void visit(Variable &var);

private:
  ASTContext &ctx_;
  BPFtrace &bpftrace_;
  Node *top_level_node_ = nullptr;

  void create_int_cast(Expression &exp, const SizedType &target_type);
};

} // namespace bpftrace::ast
