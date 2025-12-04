#include "ast/passes/named_param.h"
#include "ast/ast.h"
#include "ast/context.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

class NamedParamPass : public Visitor<NamedParamPass> {
public:
  NamedParamPass(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<NamedParamPass>::visit;
  void visit(Expression &expr);

  std::unordered_map<std::string, globalvars::GlobalVarValue> used_args;
  NamedParamDefaults defaults;

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
};

void NamedParamPass::visit(Expression &expr)
{
  auto *call = expr.as<Call>();
  if (!call || call->func != "getopt") {
    Visitor<NamedParamPass>::visit(expr);
    return;
  }

  auto *arg_name = call->vargs.at(0).as<String>();
  if (!arg_name) {
    call->vargs.at(0).node().addError()
        << "First argument to 'getopt' must be a string literal.";
    return;
  }

  if (call->vargs.size() == 2) {
    if (!call->vargs.at(1).as<Integer>() &&
        !call->vargs.at(1).as<NegativeInteger>() &&
        !call->vargs.at(1).as<String>() && !call->vargs.at(1).as<Boolean>()) {
      call->vargs.at(1).node().addError()
          << "Second argument to 'getopt' must be a string literal, integer "
             "literal, or a boolean literal.";
      return;
    }
  }

  globalvars::GlobalVarValue np_default;

  auto *map_node = ast_.make_node<Map>(arg_name->value, Location(call->loc));
  map_node->key_type = CreateInt64();

  if (call->vargs.size() == 1) {
    // boolean
    map_node->value_type = CreateBool();
    np_default = false;
  } else if (auto *default_value = call->vargs.at(1).as<Boolean>()) {
    // boolean
    map_node->value_type = CreateBool();
    np_default = default_value->value;
  } else if (auto *default_value = call->vargs.at(1).as<String>()) {
    // string
    map_node->value_type = CreateString(bpftrace_.config_->max_strlen);
    np_default = default_value->value;
  } else if (auto *default_value = call->vargs.at(1).as<Integer>()) {
    // unsigned integer
    map_node->value_type = CreateUInt64();
    np_default = default_value->value;
  } else if (auto *default_value = call->vargs.at(1).as<NegativeInteger>()) {
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
    call->addError() << "Command line option '" << arg_name->value
                     << "' needs to have the same default value in all places "
                        "it is used. Previous default value: "
                     << pre_value;
    return;
  }

  auto *index = ast_.make_node<Integer>(0, Location(map_node->loc));
  expr.value = ast_.make_node<MapAccess>(map_node,
                                         index,
                                         Location(map_node->loc));

  used_args[arg_name->value] = np_default;
  defaults.defaults[arg_name->value] = std::move(np_default);
}

Pass CreateNamedParamsPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) -> Result<NamedParamDefaults> {
    NamedParamPass np_pass(ast, b);
    np_pass.visit(ast.root);

    return std::move(np_pass.defaults);
  };

  return Pass::create("NamedParam", fn);
}

} // namespace bpftrace::ast
