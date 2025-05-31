#include <unordered_map>

#include "ast/ast.h"
#include "ast/passes/map_sugar.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

class MapDefaultKey : public Visitor<MapDefaultKey> {
public:
  explicit MapDefaultKey(ASTContext &ast) : ast_(ast) {};

  using Visitor<MapDefaultKey>::visit;
  void visit(Call &call);
  void visit(For &for_loop);
  void visit(Map &map);
  void visit(MapAccess &acc);
  void visit(AssignScalarMapStatement &assign);
  void visit(AssignMapStatement &assign);
  void visit(Expression &expr);
  void visit(Statement &stmt);

  [[nodiscard]] bool check(Map &map, bool indexed);
  void checkAccess(Map &map, bool indexed);
  void checkCall(Map &map, bool indexed, Call &call);

  MapMetadata metadata;

private:
  ASTContext &ast_;
};

class MapFunctionAliases : public Visitor<MapFunctionAliases> {
public:
  using Visitor<MapFunctionAliases>::visit;
  void visit(Call &call);
};

class MapAssignmentCall : public Visitor<MapAssignmentCall> {
public:
  explicit MapAssignmentCall(ASTContext &ast) : ast_(ast) {};

  using Visitor<MapAssignmentCall>::visit;
  void visit(Statement &stmt);

private:
  ASTContext &ast_;
};

class MapAssignmentCheck : public Visitor<MapAssignmentCheck> {
public:
  using Visitor<MapAssignmentCheck>::visit;
  void visit(Call &call);
};

} // namespace

// These are special functions which are part of the map API, and operate
// independently of any key. We allow the first argument to be a pure map, and
// therefore don't expand a default key in these cases.
//
// In the future, this could be generalized by extracting information about the
// specific function being called, and potentially respecting annotations on
// these arguments.
static std::unordered_set<std::string> RAW_MAP_ARG = {
  "print", "clear", "zero", "len", "delete", "has_key",
};

void MapDefaultKey::visit(Map &map)
{
  checkAccess(map, false);
}

void MapDefaultKey::visit(MapAccess &acc)
{
  checkAccess(*acc.map, true);
  visit(acc.key);
}

void MapDefaultKey::visit(AssignScalarMapStatement &assign)
{
  checkAccess(*assign.map, false);
  visit(assign.expr);
}

void MapDefaultKey::visit(AssignMapStatement &assign)
{
  checkAccess(*assign.map, true);
  visit(assign.key);
  visit(assign.expr);
}

void MapDefaultKey::visit(Expression &expr)
{
  Visitor<MapDefaultKey>::visit(expr);

  // Replace with an indexed map. Note that we don't visit for calls that
  // are exempt from this. This applies to all expressions in the tree,
  // including `lhist` and `hist`, which are treated in a special way
  // subsequently.
  if (auto *map = expr.as<Map>()) {
    auto *index = ast_.make_node<Integer>(0, Location(map->loc));
    expr.value = ast_.make_node<MapAccess>(map, index, Location(map->loc));
  }
}

void MapDefaultKey::visit(Statement &stmt)
{
  Visitor<MapDefaultKey>::visit(stmt);

  // Replace with a statement that has the default index, in the same way as
  // above. This will be type-checked during semantic analysis.
  if (auto *map = stmt.as<AssignScalarMapStatement>()) {
    auto *index = ast_.make_node<Integer>(0, Location(map->loc));
    stmt.value = ast_.make_node<AssignMapStatement>(
        map->map, index, map->expr, Location(map->loc));
  }
}

bool MapDefaultKey::check(Map &map, bool indexed)
{
  bool scalar = !indexed;
  auto val = metadata.scalar.find(map.ident);
  if (val == metadata.scalar.end()) {
    metadata.scalar.emplace(map.ident, scalar);
    return true;
  } else {
    return val->second == scalar;
  }
}

void MapDefaultKey::checkAccess(Map &map, bool indexed)
{
  if (!check(map, indexed)) {
    if (indexed) {
      map.addError() << map.ident
                     << " used as a map with an explicit key (non-scalar map), "
                        "previously used without an explicit key (scalar map)";
    } else {
      map.addError()
          << map.ident
          << " used as a map without an explicit key (scalar map), previously "
             "used with an explicit key (non-scalar map)";
    }
  }
}

void MapDefaultKey::checkCall(Map &map, bool indexed, Call &call)
{
  if (!check(map, indexed)) {
    if (indexed) {
      map.addError() << "call to " << call.func
                     << "() expects a map with explicit keys (non-scalar map)";
    } else {
      map.addError() << "call to " << call.func
                     << "() expects a map without explicit keys (scalar map)";
    }
  }
}

void MapDefaultKey::visit(Call &call)
{
  // Skip the first argument in these cases. This allows the argument to be
  // *either* a pure map, or a map access. Later passes will figure out what to
  // do with this, as they may have parametric behavior (as with print).
  if (RAW_MAP_ARG.contains(call.func) && !call.vargs.empty()) {
    if (auto *map = call.vargs.at(0).as<Map>()) {
      // Check our functions for consistency. These are effectively builtins
      // that require that map to have keys (conditionally for delete).
      if (call.func == "delete") {
        if (call.vargs.size() == 1) {
          // Inject the default key.
          checkCall(*map, false, call);
          auto *index = ast_.make_node<Integer>(0, Location(map->loc));
          call.vargs.emplace_back(index);
        } else if (call.vargs.size() == 2) {
          checkCall(*map, true, call);
        } else {
          // Unfortunately there's no good way to handle this after desugaring.
          // The actual `delete` function requires two arguments (fixed), but
          // we accept this weird form (and also the alias).
          call.addError() << "delete() requires 1 or 2 arguments ("
                          << call.vargs.size() << " provided)";
        }
      } else if (call.func == "has_key") {
        checkCall(*map, true, call);
      } else if (call.func == "len") {
        checkCall(*map, true, call);
      }
    } else {
      if (call.func == "delete") {
        // See above; always report this error. We don't allow the semantic
        // analyser to capture this, because it not be happy about the number
        // of arguments and we don't want to mislead users with that.
        call.vargs.at(0).node().addError() << "delete() expects a map argument";
      }
      visit(call.vargs.at(0));
    }
    for (size_t i = 1; i < call.vargs.size(); i++) {
      visit(call.vargs.at(i));
    }
  } else {
    Visitor<MapDefaultKey>::visit(call);
  }
}

void MapDefaultKey::visit(For &for_loop)
{
  if (!check(*for_loop.map, true)) {
    for_loop.map->addError() << for_loop.map->ident
                             << " has no explicit keys (scalar map), and "
                                "cannot be used for iteration";
  }
  Visitor<MapDefaultKey>::visit(for_loop.stmts);
}

void MapFunctionAliases::visit(Call &call)
{
  // We expect semantics for delete that are `delete(@, key)`. We support an
  // old `delete(@[key])` syntax but rewrite this under the hood.
  if (call.func == "delete") {
    if (call.vargs.size() == 1) {
      if (auto *access = call.vargs.at(0).as<MapAccess>()) {
        call.vargs.clear();
        call.vargs.emplace_back(access->map);
        call.vargs.emplace_back(access->key);
        call.injected_args += 1;
      }
    }
  }
}

// Similarly these are syntactic sugar over operating on a map. This list could
// also be dynamically generated based on some underlying annotation.
static std::unordered_set<std::string> ASSIGN_REWRITE = {
  "hist", "lhist", "count", "sum", "min", "max", "avg", "stats",
};

static std::optional<Expression> injectMap(Expression expr,
                                           Map *map,
                                           Expression key)
{
  if (auto *call = expr.as<Call>()) {
    if (ASSIGN_REWRITE.contains(call->func)) {
      auto args = std::move(call->vargs);
      call->vargs.emplace_back(map);
      call->vargs.emplace_back(key);
      call->injected_args += 2;
      call->vargs.insert(call->vargs.end(), args.begin(), args.end());
      return call;
    }
  } else if (auto *block_expr = expr.as<BlockExpr>()) {
    auto injected_expr = injectMap(block_expr->expr, map, key);
    if (injected_expr) {
      return block_expr;
    }
  }
  return std::nullopt;
}

void MapAssignmentCall::visit(Statement &stmt)
{
  // Any assignments that are direct calls to special functions may
  // be rewritten to simply be the function expression.
  if (auto *assign = stmt.as<AssignMapStatement>()) {
    auto expr = injectMap(assign->expr, assign->map, assign->key);
    if (expr) {
      // We injected a call, and can flatten the statement.
      stmt.value = ast_.make_node<ExprStatement>(expr.value(),
                                                 Location(assign->loc));
    }
  }
  Visitor<MapAssignmentCall>::visit(stmt);
}

void MapAssignmentCheck::visit(Call &call)
{
  if (ASSIGN_REWRITE.contains(call.func) && call.injected_args == 0) {
    call.addError() << call.func << "() must be assigned directly to a map";
  }
  Visitor<MapAssignmentCheck>::visit(call);
}

Pass CreateMapSugarPass()
{
  auto fn = [](ASTContext &ast) -> MapMetadata {
    MapFunctionAliases aliases;
    aliases.visit(ast.root);
    MapDefaultKey defaults(ast);
    defaults.visit(ast.root);
    if (!ast.diagnostics().ok()) {
      // No consistent defaults.
      return std::move(defaults.metadata);
    }
    MapAssignmentCall sugar(ast);
    sugar.visit(ast.root);
    MapAssignmentCheck check;
    check.visit(ast.root);
    return std::move(defaults.metadata);
  };

  return Pass::create("MapSugar", fn);
}

} // namespace bpftrace::ast
