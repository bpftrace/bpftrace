#include <algorithm>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/cli_opts.h"
#include "ast/visitor.h"
#include "clang_parser.h"
#include "driver.h"
#include "util/strings.h"

namespace bpftrace::ast {

char CliOptsError::ID;
void CliOptsError::log(llvm::raw_ostream &OS) const
{
  OS << err_ << "\n";
}

class CLIOptsPass : public Visitor<CLIOptsPass> {
public:
  CLIOptsPass(ASTContext &ast,
              const std::unordered_map<std::string, std::string> &named_args)
      : ast_(ast), named_args_(named_args) {};

  using Visitor<CLIOptsPass>::visit;
  void visit(Expression &expr);

  std::unordered_set<std::string> used_args_;

private:
  ASTContext &ast_;
  const std::unordered_map<std::string, std::string> named_args_;
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

  used_args_.insert(arg_name->value);

  if (call->vargs.size() == 2) {
    if (!call->vargs.at(1).as<Integer>() &&
        !call->vargs.at(1).as<NegativeInteger>() &&
        !call->vargs.at(1).as<String>()) {
      call->vargs.at(1).node().addError()
          << "Second argument to 'getopt' must be a string or integer literal.";
      return;
    }
  }

  // Use the default value passed to opt
  if (!named_args_.contains(arg_name->value)) {
    if (call->vargs.size() == 1) {
      expr.value = ast_.make_node<Integer>(0, Location(call->loc));
    } else if (auto *default_value = call->vargs.at(1).as<String>()) {
      expr.value = clone(ast_, default_value, call->loc);
    } else if (auto *default_value = call->vargs.at(1).as<Integer>()) {
      expr.value = clone(ast_, default_value, call->loc);
    } else if (auto *default_value = call->vargs.at(1).as<NegativeInteger>()) {
      expr.value = clone(ast_, default_value, call->loc);
    }
    return;
  }

  if (call->vargs.size() == 1) {
    if (util::is_str_bool_truthy(named_args_.at(arg_name->value))) {
      expr.value = ast_.make_node<Integer>(1, Location(call->loc));
    } else if (util::is_str_bool_falsy(named_args_.at(arg_name->value))) {
      expr.value = ast_.make_node<Integer>(0, Location(call->loc));
    } else {
      call->addError() << "Command line option '" << arg_name->value
                       << "' is expecting a boolean (e.g. 1, 'true'). Got: "
                       << arg_name->value;
    }
    return;
  }

  if (call->vargs.at(1).as<String>()) {
    expr.value = ast_.make_node<String>(named_args_.at(arg_name->value),
                                        Location(call->loc));
    return;
  }

  // Check if the opt is expecting a bool flag
  auto *default_value = call->vargs.at(1).as<Integer>();
  if (default_value &&
      (default_value->value == 0 || default_value->value == 1)) {
    if (util::is_str_bool_truthy(named_args_.at(arg_name->value))) {
      expr.value = ast_.make_node<Integer>(1, Location(call->loc));
      return;
    } else if (util::is_str_bool_falsy(named_args_.at(arg_name->value))) {
      expr.value = ast_.make_node<Integer>(0, Location(call->loc));
      return;
    }
  }

  try {
    auto val = std::stoll(named_args_.at(arg_name->value));
    if (val < 0) {
      expr.value = ast_.make_node<NegativeInteger>(val, Location(call->loc));
    } else {
      expr.value = ast_.make_node<Integer>(val, Location(call->loc));
    }
  } catch (const std::invalid_argument &) {
    call->addError() << "Command line option '" << arg_name->value
                     << "' is expecting an integer. Got: "
                     << named_args_.at(arg_name->value);
  } catch (const std::out_of_range &) {
    call->addError() << "Value for command line option '" << arg_name->value
                     << "' is out of range. Got: "
                     << named_args_.at(arg_name->value);
  }
}

Pass CreateCLIOptsPass(
    const std::unordered_map<std::string, std::string> &named_args)
{
  auto fn = [&named_args](ASTContext &ast) -> Result<OK> {
    CLIOptsPass expander(ast, named_args);
    expander.visit(ast.root);

    std::string unused_args_str;
    // Check if there are any unused args
    for (const auto &arg : named_args) {
      if (!expander.used_args_.contains(arg.first)) {
        unused_args_str += arg.first + ", ";
      }
    }

    if (!unused_args_str.empty()) {
      // Remove the last comma and space
      unused_args_str.pop_back();
      unused_args_str.pop_back();
      return make_error<CliOptsError>("Unexpected command line options: " +
                                      unused_args_str);
    }

    return OK();
  };

  return Pass::create("CLIOpts", fn);
}

} // namespace bpftrace::ast
