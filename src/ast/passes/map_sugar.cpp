#include <unordered_map>

#include "ast/ast.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

const std::unordered_set<std::string> &getAssignRewriteFuncs()
{
  // Similarly these are syntactic sugar over operating on a map. This list
  // could also be dynamically generated based on some underlying annotation.
  static std::unordered_set<std::string> ASSIGN_REWRITE = {
    "hist", "lhist", "count", "sum", "min", "max", "avg", "stats", "tseries",
  };
  return ASSIGN_REWRITE;
}

namespace {

class MapDefaultKey : public Visitor<MapDefaultKey> {
public:
  explicit MapDefaultKey(ASTContext &ast) : ast_(ast) {};

  using Visitor<MapDefaultKey>::visit;
  void visit(Call &call);
  void visit(For &for_loop);
  void visit(Map &map);
  void visit(MapAccess &acc);
  void visit(MapAddr &map_addr);
  void visit(Typeof &typeof);
  void visit(AssignScalarMapStatement &assign);
  void visit(AssignMapStatement &assign);
  void visit(Expression &expr);
  void visit(Statement &stmt);

  [[nodiscard]] bool check(Map &map, bool indexed);
  void checkAccess(Map &map, bool indexed);
  void checkCall(Map &map, bool indexed);

  MapMetadata metadata;

private:
  ASTContext &ast_;
};

class MapFunctionAliases : public Visitor<MapFunctionAliases> {
public:
  explicit MapFunctionAliases(ASTContext &ast, MacroRegistry &macro_registry)
      : ast_(ast), macro_registry_(macro_registry) {};

  using Visitor<MapFunctionAliases>::visit;
  void visit(Expression &expr);

private:
  ASTContext &ast_;
  const MacroRegistry &macro_registry_;
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

class MapScalarCheck : public Visitor<MapScalarCheck> {
public:
  explicit MapScalarCheck(ASTContext &ast, MapMetadata &metadata)
      : ast_(ast), metadata_(metadata) {};

  using Visitor<MapScalarCheck>::visit;
  void visit(Expression &expr);

private:
  ASTContext &ast_;
  MapMetadata &metadata_;
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
  "print", "clear", "zero", "len", "is_scalar",
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

void MapDefaultKey::visit([[maybe_unused]] MapAddr &map_addr)
{
  // Don't desugar this into a map access, we want the map pointer
}

void MapDefaultKey::visit([[maybe_unused]] Typeof &typeof)
{
  if (std::holds_alternative<Expression>(typeof.record)) {
    const auto &expr = std::get<Expression>(typeof.record);
    if (auto *map = expr.as<Map>()) {
      // Don't de-sugar if it's a non-scalar map
      auto val = metadata.scalar.find(map->ident);
      if (val != metadata.scalar.end() && !val->second) {
        return;
      }
    }
  }
  Visitor<MapDefaultKey>::visit(typeof);
}

void MapDefaultKey::visit(AssignScalarMapStatement &assign)
{
  checkAccess(*assign.map, false);
  visit(assign.expr);
}

void MapDefaultKey::visit(AssignMapStatement &assign)
{
  checkAccess(*assign.map_access->map, true);
  visit(assign.map_access);
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
    auto *index = ast_.make_node<Integer>(map->loc, 0);
    expr.value = ast_.make_node<MapAccess>(map->loc, map, index);
  }
}

void MapDefaultKey::visit(Statement &stmt)
{
  Visitor<MapDefaultKey>::visit(stmt);

  // Replace with a statement that has the default index, in the same way as
  // above. This will be type-checked during semantic analysis.
  if (auto *map = stmt.as<AssignScalarMapStatement>()) {
    auto *index = ast_.make_node<Integer>(map->loc, 0, CreateInt64());
    auto *acc = ast_.make_node<MapAccess>(map->loc, map->map, index);
    stmt.value = ast_.make_node<AssignMapStatement>(map->loc, acc, map->expr);
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
      metadata.bad_scalar_access.insert(&map);
    } else {
      metadata.bad_indexed_access.insert(&map);
    }
  }
}

void MapDefaultKey::checkCall(Map &map, bool indexed)
{
  if (!check(map, indexed)) {
    if (indexed) {
      metadata.bad_scalar_call.insert(&map);
    } else {
      metadata.bad_indexed_call.insert(&map);
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
      if (call.func == "len") {
        checkCall(*map, true);
      } else if (call.func == "is_scalar") {
        if (call.vargs.size() != 1) {
          call.addError() << "is_scalar() requires 1 argument ("
                          << call.vargs.size() << " provided)";
        }
      }
    } else {
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
  if (auto *map = for_loop.iterable.as<Map>()) {
    if (!check(*map, true)) {
      metadata.bad_iterator.insert(map);
    }
  } else {
    // If the map is used for the range in any way, it needs
    // to be desugared properly.
    visit(for_loop.iterable);
  }
  visit(for_loop.block);
}

void MapFunctionAliases::visit(Expression &expr)
{
  // We expect semantics for delete that are `delete(@, key)`. We support an
  // old `delete(@[key])` syntax but rewrite this under the hood.
  // This is expanded to the `__deprecated_delete` in macro stdlib.
  Visitor<MapFunctionAliases>::visit(expr);

  if (auto *call = expr.as<Call>()) {
    if (call->func == "__deprecated_delete") {
      if (auto *access = call->vargs.at(0).as<MapAccess>()) {
        call->vargs.clear();
        call->vargs.emplace_back(access->map);
        call->vargs.emplace_back(access->key);
        call->func = "delete";
        expand_macro(ast_, expr, macro_registry_);
      }
    }
  }
}

static std::optional<Expression> injectMap(Expression expr,
                                           Map *map,
                                           Expression key)
{
  if (auto *call = expr.as<Call>()) {
    if (getAssignRewriteFuncs().contains(call->func)) {
      auto args = std::move(call->vargs);
      call->vargs.emplace_back(map);
      call->vargs.emplace_back(key);
      call->injected_args += 2;
      call->vargs.insert(call->vargs.end(), args.begin(), args.end());
      return call;
    }
  } else if (auto *block = expr.as<BlockExpr>()) {
    auto injected_expr = injectMap(block->expr, map, key);
    if (injected_expr) {
      return block;
    }
  }
  return std::nullopt;
}

void MapAssignmentCall::visit(Statement &stmt)
{
  // Any assignments that are direct calls to special functions may
  // be rewritten to simply be the function expression.
  if (auto *assign = stmt.as<AssignMapStatement>()) {
    auto expr = injectMap(assign->expr,
                          assign->map_access->map,
                          assign->map_access->key);
    if (expr) {
      // We injected a call, and can flatten the statement.
      stmt.value = ast_.make_node<ExprStatement>(assign->loc, expr.value());
    }
  }
  Visitor<MapAssignmentCall>::visit(stmt);
}

void MapAssignmentCheck::visit(Call &call)
{
  if (getAssignRewriteFuncs().contains(call.func) && call.injected_args == 0) {
    call.addError() << call.func << "() must be assigned directly to a map";
  }
  Visitor<MapAssignmentCheck>::visit(call);
}

void MapScalarCheck::visit(Expression &expr)
{
  Visitor<MapScalarCheck>::visit(expr);

  if (auto *call = expr.as<Call>()) {
    if (call->func == "is_scalar") {
      if (auto *map = call->vargs.at(0).as<Map>()) {
        auto val = metadata_.scalar.find(map->ident);
        if (val == metadata_.scalar.end()) {
          expr.node().addError() << "Unknown map: " << map->ident;
          return;
        }
        expr.value = ast_.make_node<Boolean>(call->loc, val->second);
      } else {
        expr.node().addError()
            << call->func << "() expects a map for the first argument";
      }
    }
  }
}

Pass CreateMapSugarPass()
{
  auto fn = [](ASTContext &ast, MacroRegistry &macro_registry) -> MapMetadata {
    MapFunctionAliases aliases(ast, macro_registry);
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

    MapScalarCheck scalar(ast, defaults.metadata);
    scalar.visit(ast.root);

    return std::move(defaults.metadata);
  };

  return Pass::create("MapSugar", fn);
}

} // namespace bpftrace::ast
