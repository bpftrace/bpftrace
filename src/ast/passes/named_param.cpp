#include <algorithm>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/named_param.h"
#include "ast/visitor.h"
#include "clang_parser.h"
#include "driver.h"
#include "util/strings.h"

namespace bpftrace::ast {

class NamedParamPass : public Visitor<NamedParamPass> {
public:
  NamedParamPass(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<NamedParamPass>::visit;
  void visit(Expression &expr);

  std::unordered_map<std::string, std::string> used_args;
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

  bool is_arg_error = false;
  if (call->vargs.size() == 2) {
    if (!call->vargs.at(1).as<Integer>() &&
        !call->vargs.at(1).as<NegativeInteger>() &&
        !call->vargs.at(1).as<String>() &&
        !call->vargs.at(1).as<Identifier>()) {
      is_arg_error = true;
    } else if (auto *ident = call->vargs.at(1).as<Identifier>()) {
      if (!util::is_str_bool_truthy(ident->ident) &&
          !util::is_str_bool_falsy(ident->ident)) {
        is_arg_error = true;
      }
    }
    if (is_arg_error) {
      call->vargs.at(1).node().addError()
          << "Second argument to 'getopt' must be a string literal, integer "
             "literal, or a boolean-ish identifier (e.g. true, false, yes, "
             "no).";
      return;
    }
  }

  NamedParamDefault np_default;

  auto map_node = ast_.make_node<Map>(arg_name->value,
                                      true,
                                      Location(call->loc));
  map_node->key_type = CreateInt64();

  std::string expected_default_val;
  if (call->vargs.size() == 1) {
    // boolean
    map_node->value_type = CreateInt64();
    expected_default_val = "false";
    np_default.is_bool = true;
  } else if (auto *default_value = call->vargs.at(1).as<String>()) {
    // string
    map_node->value_type = CreateString(bpftrace_.config_->max_strlen);
    expected_default_val = default_value->value;
  } else if (auto *default_value = call->vargs.at(1).as<Integer>()) {
    // integer
    map_node->value_type = CreateInt64();
    expected_default_val = std::to_string(default_value->value);
  } else if (auto *default_value = call->vargs.at(1).as<NegativeInteger>()) {
    // integer
    map_node->value_type = CreateInt64();
    expected_default_val = std::to_string(default_value->value);
  } else if (auto *default_value = call->vargs.at(1).as<Identifier>()) {
    // boolean
    map_node->value_type = CreateInt64();
    expected_default_val = default_value->ident;
    np_default.is_bool = true;
  }

  if (used_args.contains(arg_name->value) &&
      used_args.at(arg_name->value) != expected_default_val) {
    call->addError() << "Command line option '" << arg_name->value
                     << "' needs to have the same default value in all places "
                        "it is used. Previous default value: "
                     << used_args.at(arg_name->value);
    return;
  }

  np_default.type = map_node->value_type.GetTy();
  np_default.value = expected_default_val;

  auto *index = ast_.make_node<Integer>(0, Location(map_node->loc));
  expr.value = ast_.make_node<MapAccess>(map_node,
                                         index,
                                         Location(map_node->loc));

  used_args[arg_name->value] = expected_default_val;
  defaults.defaults[arg_name->value] = std::move(np_default);
}

Pass CreateNamedParamPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) -> Result<NamedParamDefaults> {
    NamedParamPass np_pass(ast, b);
    np_pass.visit(ast.root);

    return std::move(np_pass.defaults);
  };

  return Pass::create("NamedParam", fn);
}

} // namespace bpftrace::ast
