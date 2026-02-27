#pragma once

#include "ast/pass_manager.h"
#include "ast/visitor.h"

#include <optional>
#include <variant>

namespace bpftrace {
class BPFtrace;
} // namespace bpftrace

namespace bpftrace::ast {

std::optional<SizedType> try_tuple_cast(ASTContext &ctx,
                                        Expression &exp,
                                        const SizedType &expr_type,
                                        const SizedType &target_type);

std::optional<SizedType> try_record_cast(ASTContext &ctx,
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
  void visit(Call &call);
  void visit(Cast &cast);
  void visit(For &f);
  void visit(IfExpr &if_expr);
  void visit(Jump &jump);
  void visit(MapAccess &acc);
  void visit(Probe &probe);
  void visit(Subprog &subprog);

private:
  ASTContext &ctx_;
  BPFtrace &bpftrace_;
  std::variant<std::monostate, Probe *, Subprog *> top_level_node_;
};

} // namespace bpftrace::ast
