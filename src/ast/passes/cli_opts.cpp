#include <algorithm>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/cli_opts.h"
#include "ast/visitor.h"
#include "clang_parser.h"
#include "driver.h"
#include "util/strings.h"

namespace bpftrace::ast {

class CLIOptsPass : public Visitor<CLIOptsPass> {
public:
  CLIOptsPass(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<CLIOptsPass>::visit;
  void visit(Expression &expr);

  std::unordered_map<std::string, std::string> used_args;

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
};

void CLIOptsPass::visit(Expression &expr)
{
  auto *call = expr.as<Call>();
  if (!call || call->func != "getopt") {
    Visitor<CLIOptsPass>::visit(expr);
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

  std::string expected_default_val;
  if (call->vargs.size() == 1) {
    // boolean
    expr.value = ast_.make_node<NamedParameter>(
        arg_name->value, CreateInt64(), "0", true, Location(call->loc));
    expected_default_val = "false";
  } else if (auto *default_value = call->vargs.at(1).as<String>()) {
    // string
    expr.value = ast_.make_node<NamedParameter>(
        arg_name->value,
        CreateString(bpftrace_.config_->max_strlen),
        default_value->value,
        false,
        Location(call->loc));
    expected_default_val = default_value->value;
  } else if (auto *default_value = call->vargs.at(1).as<Integer>()) {
    // integer
    expected_default_val = std::to_string(default_value->value);
    expr.value = ast_.make_node<NamedParameter>(arg_name->value,
                                                CreateInt64(),
                                                expected_default_val,
                                                false,
                                                Location(call->loc));
  } else if (auto *default_value = call->vargs.at(1).as<NegativeInteger>()) {
    // integer
    expected_default_val = std::to_string(default_value->value);
    expr.value = ast_.make_node<NamedParameter>(arg_name->value,
                                                CreateInt64(),
                                                expected_default_val,
                                                false,
                                                Location(call->loc));
  } else if (auto *default_value = call->vargs.at(1).as<Identifier>()) {
    // boolean
    expected_default_val = default_value->ident;
    expr.value = ast_.make_node<NamedParameter>(arg_name->value,
                                                CreateInt64(),
                                                expected_default_val,
                                                true,
                                                Location(call->loc));
  }

  if (used_args.contains(arg_name->value) &&
      used_args.at(arg_name->value) != expected_default_val) {
    call->addError() << "Command line option '" << arg_name->value
                     << "' needs to have the same default value in all places "
                        "it is used. Previous default value: "
                     << used_args.at(arg_name->value);
    return;
  }

  used_args[arg_name->value] = expected_default_val;
}

Pass CreateCLIOptsPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) {
    CLIOptsPass expander(ast, b);
    expander.visit(ast.root);
  };

  return Pass::create("CLIOpts", fn);
}

} // namespace bpftrace::ast
