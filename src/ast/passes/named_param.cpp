
#include "ast/passes/named_param.h"

#include "ast/ast.h"
#include "ast/clone.h"
#include "ast/context.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

class NamedParamPass : public Visitor<NamedParamPass, MapAccess *> {
public:
  NamedParamPass(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<NamedParamPass, MapAccess *>::visit;
  MapAccess *visit(Expression &expr);
  MapAccess *visit(Call &call);
  MapAccess *visit(MapDeclStatement &map_decl);
  MapAccess *visit(Program &program);

  std::unordered_map<std::string, globalvars::GlobalVarValue> used_args;
  NamedParamDefaults defaults;
  std::map<std::string, MapAccess *> map_rewrites;

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
};

class MapRewriter : public Visitor<MapRewriter> {
public:
  explicit MapRewriter(ASTContext &ast,
                       std::map<std::string, MapAccess *> map_rewrites)
      : ast_(ast), map_rewrites(std::move(map_rewrites)) {};

  using Visitor<MapRewriter>::visit;
  void visit(Expression &expr);
  void visit(MapAccess &map_access);
  void visit(AssignMapStatement &map_assign);

private:
  ASTContext &ast_;
  std::map<std::string, MapAccess *> map_rewrites;
};

MapAccess *NamedParamPass::visit(Expression &expr)
{
  auto *access = Visitor<NamedParamPass, MapAccess *>::visit(expr);
  if (access) {
    expr.value = access;
  }
  return nullptr;
}

MapAccess *NamedParamPass::visit(Call &call)
{
  Visitor<NamedParamPass, MapAccess *>::visit(call);

  if (call.func != "getopt") {
    return nullptr;
  }

  auto *arg_name = call.vargs.at(0).as<String>();
  if (!arg_name) {
    call.vargs.at(0).node().addError()
        << "First argument to 'getopt' must be a string literal.";
    return nullptr;
  }

  if (call.vargs.size() == 2) {
    if (!call.vargs.at(1).as<Integer>() &&
        !call.vargs.at(1).as<NegativeInteger>() &&
        !call.vargs.at(1).as<String>() && !call.vargs.at(1).as<Boolean>()) {
      call.vargs.at(1).node().addError()
          << "Second argument to 'getopt' must be a string literal, integer "
             "literal, or a boolean literal.";
      return nullptr;
    }
  }

  globalvars::GlobalVarValue np_default;

  auto *map_node = ast_.make_node<Map>(call.loc, arg_name->value);
  map_node->key_type = CreateInt64();

  if (call.vargs.size() == 1) {
    // boolean
    map_node->value_type = CreateBool();
    np_default = false;
  } else if (auto *default_value = call.vargs.at(1).as<Boolean>()) {
    // boolean
    map_node->value_type = CreateBool();
    np_default = default_value->value;
  } else if (auto *default_value = call.vargs.at(1).as<String>()) {
    // string
    map_node->value_type = CreateString(bpftrace_.config_->max_strlen);
    np_default = default_value->value;
  } else if (auto *default_value = call.vargs.at(1).as<Integer>()) {
    // unsigned integer
    map_node->value_type = CreateUInt64();
    np_default = default_value->value;
  } else if (auto *default_value = call.vargs.at(1).as<NegativeInteger>()) {
    // signed integer
    map_node->value_type = CreateInt64();
    np_default = default_value->value;
  }

  if (used_args.contains(arg_name->value) &&
      used_args.at(arg_name->value) != np_default) {
    std::string pre_value;
    if (std::holds_alternative<std::string>(used_args.at(arg_name->value))) {
      pre_value = std::get<std::string>(used_args.at(arg_name->value));
    } else if (std::holds_alternative<int64_t>(used_args.at(arg_name->value))) {
      pre_value = std::to_string(
          std::get<int64_t>(used_args.at(arg_name->value)));
    } else if (std::holds_alternative<uint64_t>(
                   used_args.at(arg_name->value))) {
      pre_value = std::to_string(
          std::get<uint64_t>(used_args.at(arg_name->value)));
    } else {
      pre_value = std::get<bool>(used_args.at(arg_name->value)) ? "true"
                                                                : "false";
    }
    call.addError() << "Command line option '" << arg_name->value
                    << "' needs to have the same default value in all places "
                       "it is used. Previous default value: "
                    << pre_value;
    return nullptr;
  }

  auto *index = ast_.make_node<Integer>(map_node->loc, 0);
  auto *access = ast_.make_node<MapAccess>(map_node->loc, map_node, index);

  used_args[arg_name->value] = np_default;
  defaults.defaults[arg_name->value] = std::move(np_default);
  return access;
}

MapAccess *NamedParamPass::visit(MapDeclStatement &map_decl)
{
  auto *access = visit(map_decl.call);
  if (access) {
    // Record the renaming for below.
    map_rewrites[map_decl.ident] = access;
  }
  return nullptr;
}

MapAccess *NamedParamPass::visit(Program &program)
{
  Visitor<NamedParamPass, MapAccess *>::visit(program);

  // Remove all explicit declarations for getopt maps.
  std::erase_if(program.map_decls, [](auto *map_decl) {
    return map_decl->call->func == "getopt";
  });
  return nullptr;
}

void MapRewriter::visit(Expression &expr)
{
  Visitor<MapRewriter>::visit(expr);

  // The naked map expression can come up in e.g. print(...) statements,
  // and still needs to be rewritten to be the scalar value. It is basically
  // always flattened, unlike other maps which are only mostly flattened.
  if (auto *map = expr.as<Map>()) {
    auto it = map_rewrites.find(map->ident);
    if (it != map_rewrites.end()) {
      expr.value = clone(ast_, map->loc, it->second);
    }
  }
}

void MapRewriter::visit(MapAccess &map_access)
{
  // We validate that this has been desugared in a way that we
  // expect for a scalar map access, and then we simply replace
  // the map name with the generated name for the getopt variable.
  auto it = map_rewrites.find(map_access.map->ident);
  if (it != map_rewrites.end()) {
    if (map_access.key != it->second->key) {
      map_access.addError() << "getopt map access must be scalar";
    } else {
      // The key is already the same, we can just update the
      // map entry to be the map entry of the getopt map.
      map_access.map = clone(ast_, map_access.map->loc, it->second->map);
    }
  }

  Visitor<MapRewriter>::visit(map_access);
}

void MapRewriter::visit(AssignMapStatement &map_assign)
{
  // Option maps must not be written to; they are fixed.
  auto it = map_rewrites.find(map_assign.map_access->map->ident);
  if (it != map_rewrites.end()) {
    map_assign.addError() << "getopt map is immutable";
  }

  Visitor<MapRewriter>::visit(map_assign);
}

Pass CreateNamedParamsPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) -> Result<NamedParamDefaults> {
    NamedParamPass np_pass(ast, b);
    np_pass.visit(ast.root);
    MapRewriter map_rewriter(ast, std::move(np_pass.map_rewrites));
    map_rewriter.visit(ast.root);
    return std::move(np_pass.defaults);
  };

  return Pass::create("NamedParam", fn);
}

} // namespace bpftrace::ast
