#pragma once

#include "ast/passes/types/type_resolver.h"
#include "ast/visitor.h"

#include <optional>

namespace bpftrace::ast {

class MacroRegistry;

class AstTransformer
    : public Visitor<AstTransformer, std::optional<Expression>> {
public:
  AstTransformer(ASTContext &ast,
                 const MacroRegistry &macro_registry,
                 const ResolvedTypes &resolved_types)
      : ast_(ast),
        macro_registry_(macro_registry),
        resolved_types_(resolved_types) {};

  using Visitor<AstTransformer, std::optional<Expression>>::visit;

  std::optional<Expression> visit(Expression &expr);
  std::optional<Expression> visit(Binop &binop);
  std::optional<Expression> visit(Offsetof &offof);
  std::optional<Expression> visit(Sizeof &szof);
  std::optional<Expression> visit(Typeinfo &typeinfo);
  std::optional<Expression> visit(FieldAccess &acc);

  bool had_transforms() const
  {
    return had_transforms_;
  }

private:
  ASTContext &ast_;
  const MacroRegistry &macro_registry_;
  const ResolvedTypes &resolved_types_;
  bool had_transforms_ = false;

  const SizedType &get_type(const TypeVariable &node) const
  {
    auto it = resolved_types_.find(node);
    if (it != resolved_types_.end()) {
      return it->second;
    }
    static SizedType none = CreateNone();
    return none;
  }
};

} // namespace bpftrace::ast
