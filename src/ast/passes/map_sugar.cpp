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

  void check(Map &map, bool indexed);

private:
  ASTContext &ast_;
  std::unordered_map<std::string, bool> indexed_;
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
  void visit(Call &call);
  void visit(AssignMapStatement &assign);
  void visit(Statement &stmt);

private:
  ASTContext &ast_;
};

} // namespace

// These are special functions which are part of the map API, and operate
// independently of any key. We allow the first argument to be a pure map,
// and process therefore don't expand a default key in these cases.
//
// In the future, this could be generalized by extracting information about the
// specific function being called, and potentially respecting annotations on
// these arguments.
static std::unordered_set<std::string> RAW_MAP_ARG = {
  "print", "clear", "zero", "len", "delete", "has_key",
};

void MapDefaultKey::visit(Map &map)
{
  check(map, false);
}

void MapDefaultKey::visit(MapAccess &acc)
{
  check(*acc.map, true);
  visit(acc.key);
}

void MapDefaultKey::visit(AssignScalarMapStatement &assign)
{
  check(*assign.map, false);
  visit(assign.expr);
}

void MapDefaultKey::visit(AssignMapStatement &assign)
{
  check(*assign.map, true);
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

void MapDefaultKey::check(Map &map, bool indexed)
{
  auto val = indexed_.find(map.ident);
  if (val == indexed_.end()) {
    indexed_.emplace(map.ident, indexed);
  } else if (val->second != indexed) {
    if (indexed) {
      map.addError() << map.ident
                     << " used as a non-scalar map, when previously used as a "
                        "non-scalar map";
    } else {
      map.addError()
          << map.ident
          << " used as a scalar map, when previously used as a scalar map";
    }
  }
}

void MapDefaultKey::visit(Call &call)
{
  // Skip the first argument in these cases. This allows the argument to be
  // *either* a pure map, or a map access. Later passes will figure out what to
  // do with this, as they may have parametric behavior (as with print).
  if (RAW_MAP_ARG.contains(call.func) && call.vargs.size() >= 1) {
    if (auto *map = call.vargs.at(0).as<Map>()) {
      // Check our functions for consistency. These are effectively builtins
      // that require that map to have keys (conditionally for delete).
      if (call.func == "delete") {
        check(*map, call.vargs.size() > 1);
      } else if (call.func == "has_key") {
        check(*map, true);
      } else if (call.func == "len") {
        check(*map, true);
      }
    } else {
      // Process the argument.
      visit(call.vargs[0]);
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
  check(*for_loop.map, true);
}

void MapFunctionAliases::visit(Call &call)
{
  // If this is specfically `delete(@)` then we remap this to `clear`. We
  // expected semantics for delete are `delete(@, key)`. We support an old
  // `delete(@[key])` syntax but rewrite this under the hood.
  if (call.func == "delete") {
    if (call.vargs.size() == 1) {
      if (auto *map = call.vargs.at(0).as<Map>()) {
        call.vargs.clear();
        call.vargs.emplace_back(map);
      } else if (auto *access = call.vargs.at(0).as<MapAccess>()) {
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
  } else if (auto *block = expr.as<Block>()) {
    if (block->expr) {
      auto expr = injectMap(block->expr.value(), map, key);
      if (expr) {
        return block;
      }
    }
  }
  return std::nullopt;
}

void MapAssignmentCall::visit(Call &call)
{
  if (ASSIGN_REWRITE.contains(call.func)) {
    call.addError() << call.func << "() must be assigned directly to a map";
  }
  Visitor<MapAssignmentCall>::visit(call);
}

void MapAssignmentCall::visit(AssignMapStatement &assign)
{
  // Don't visit the expression directly if it's a call. These are the things
  // that are okay and we will rewrite, but evaluate everything else.
  if (auto *call = assign.expr.as<Call>()) {
    for (auto &arg : call->vargs) {
      visit(arg);
    }
  } else {
    Visitor<MapAssignmentCall>::visit(assign);
  }
}

void MapAssignmentCall::visit(Statement &stmt)
{
  Visitor<MapAssignmentCall>::visit(stmt);

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
}

Pass CreateMapSugarPass()
{
  auto fn = [](ASTContext &ast) {
    MapDefaultKey defaults(ast);
    defaults.visit(ast.root);
    if (!ast.diagnostics().ok()) {
      return; // No consistent defaults.
    }
    MapFunctionAliases aliases;
    aliases.visit(ast.root);
    MapAssignmentCall sugar(ast);
    sugar.visit(ast.root);
  };

  return Pass::create("MapSugar", fn);
}

} // namespace bpftrace::ast
