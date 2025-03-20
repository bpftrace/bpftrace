#include <unordered_set>

#include "ast/passes/map_assign_funcs.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

class MapAssignTransform : public Visitor<MapAssignTransform, Expression *> {
public:
  MapAssignTransform(ASTContext &ast) : ast_(ast) {};

  using Visitor<MapAssignTransform, Expression *>::visit;
  Expression *visit(Call &call);
  Expression *visit(AssignMapStatement &map);
  Expression *pushMap(Map *map, Expression *expr);

  using Visitor<MapAssignTransform, Expression *>::replace;
  Statement *replace(Statement *orig, Expression **result);

private:
  ASTContext &ast_;
};

} // namespace

static std::unordered_set<std::string> rewrite = {
  "count", "sum", "max", "min", "avg", "stats", "hist", "lhist",
};

Expression *MapAssignTransform::visit(Call &call)
{
  visit(call.vargs);

  // This should be rewritten before getting walked.
  if (rewrite.contains(call.func)) {
    call.addError() << call.func << "() should be directly assigned to a map";
    return nullptr;
  }

  return nullptr;
}

Expression *MapAssignTransform::pushMap(Map *map, Expression *expr)
{
  if (auto *call = dynamic_cast<Call *>(expr)) {
    if (rewrite.contains(call->func)) {
      ExpressionList new_args = { map };
      ExpressionList old_args = std::move(call->vargs);
      new_args.insert(new_args.end(), old_args.begin(), old_args.end());
      call->vargs = std::move(new_args);
      visit(call->vargs);
      return call;
    }
  }
  if (auto *block = dynamic_cast<Block *>(expr)) {
    if (pushMap(map, block->expr) != nullptr) {
      return block; // Replace with this block.
    }
  }
  return nullptr;
}

Expression *MapAssignTransform::visit(AssignMapStatement &map)
{
  visit(map.map);
  return pushMap(map.map, map.expr);
}

Statement *MapAssignTransform::replace(Statement *orig, Expression **result)
{
  if (*result != nullptr) {
    // Replace the original statement with the expression, so
    // that we don't confuse ourselves with any map assignment.
    auto orig_loc = (*result)->loc;
    return ast_.make_node<ExprStatement>(*result, std::move(orig_loc));
  }
  return orig;
}

Pass CreateMapAssignTransformPass()
{
  auto fn = [](ASTContext &ast) {
    MapAssignTransform analyser(ast);
    analyser.visit(ast.root);
  };

  return Pass::create("MapAssignTransform", fn);
}

} // namespace bpftrace::ast
