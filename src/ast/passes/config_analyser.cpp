#include "config_analyser.h"

#include <cstring>
#include <string>

#include "ast/ast.h"
#include "config.h"
#include "log.h"
#include "types.h"

namespace bpftrace {
namespace ast {

template <class... Ts>
struct overloaded : Ts... {
  using Ts::operator()...;
};
// explicit deduction guide (not needed as of C++20)
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

void ConfigAnalyser::log_type_error(SizedType &type,
                                    Type expected_type,
                                    AssignConfigVarStatement &assignment)
{
  LOG(ERROR, assignment.loc, err_)
      << "Invalid type for " << assignment.config_var
      << ". Type: " << type.GetTy() << ". Expected Type: " << expected_type;
}

void ConfigAnalyser::set_uint64_config(AssignConfigVarStatement &assignment,
                                       ConfigKeyInt key)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsIntegerTy()) {
    log_type_error(assignTy, Type::integer, assignment);
    return;
  }

  config_setter_.set(key, dynamic_cast<Integer *>(assignment.expr)->n);
}

void ConfigAnalyser::set_bool_config(AssignConfigVarStatement &assignment,
                                     ConfigKeyBool key)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsIntegerTy()) {
    log_type_error(assignTy, Type::integer, assignment);
    return;
  }

  auto val = dynamic_cast<Integer *>(assignment.expr)->n;
  if (val == 0) {
    config_setter_.set(key, false);
  } else if (val == 1) {
    config_setter_.set(key, true);
  } else {
    LOG(ERROR) << "Invalid value for " << assignment.config_var
               << ". Needs to be 0 or 1. Value: " << val;
  }
}

void ConfigAnalyser::set_string_config(AssignConfigVarStatement &assignment,
                                       ConfigKeyString key)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsStringTy()) {
    log_type_error(assignTy, Type::string, assignment);
    return;
  }

  config_setter_.set(key, dynamic_cast<String *>(assignment.expr)->str);
}

void ConfigAnalyser::set_stack_mode_config(AssignConfigVarStatement &assignment)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsStackModeTy()) {
    log_type_error(assignTy, Type::stack_mode, assignment);
    return;
  }

  config_setter_.set(assignTy.stack_type.mode);
}

void ConfigAnalyser::set_user_symbol_cache_type_config(
    AssignConfigVarStatement &assignment)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsStringTy()) {
    log_type_error(assignTy, Type::string, assignment);
    return;
  }

  auto val = dynamic_cast<String *>(assignment.expr)->str;
  if (!config_setter_.set_user_symbol_cache_type(val))
    LOG(ERROR, assignment.expr->loc, err_);
}

void ConfigAnalyser::set_missing_probes_config(
    AssignConfigVarStatement &assignment)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsStringTy()) {
    log_type_error(assignTy, Type::string, assignment);
    return;
  }

  auto val = dynamic_cast<String *>(assignment.expr)->str;
  if (!config_setter_.set_missing_probes_config(val))
    LOG(ERROR, assignment.expr->loc, err_);
}

void ConfigAnalyser::visit(Integer &integer)
{
  integer.type = CreateInt64();
}

void ConfigAnalyser::visit(String &string)
{
  string.type = CreateString(string.str.size() + 1);
}

void ConfigAnalyser::visit(StackMode &mode)
{
  auto stack_mode = bpftrace::Config::get_stack_mode(mode.mode);
  if (stack_mode.has_value()) {
    mode.type = CreateStackMode();
    mode.type.stack_type.mode = stack_mode.value();
  } else {
    mode.type = CreateNone();
    LOG(ERROR, mode.loc, err_) << "Unknown stack mode: '" + mode.mode + "'";
  }
}

void ConfigAnalyser::visit(AssignConfigVarStatement &assignment)
{
  Visitor::visit(assignment);
  std::string &raw_ident = assignment.config_var;

  std::string err_msg;
  const auto maybeConfigKey = bpftrace_.config_.get_config_key(raw_ident,
                                                               err_msg);

  if (!maybeConfigKey.has_value()) {
    LOG(ERROR, assignment.loc, err_) << err_msg;
    return;
  }

  if (!assignment.expr->is_literal) {
    LOG(ERROR, assignment.loc, err_)
        << "Assignemnt for " << assignment.config_var << " must be literal.";
    return;
  }

  auto configKey = maybeConfigKey.value();

  std::visit(
      overloaded{
          [&, this](ConfigKeyBool key) { set_bool_config(assignment, key); },
          [&, this](ConfigKeyInt key) { set_uint64_config(assignment, key); },
          [&, this](ConfigKeyString key) {
            set_string_config(assignment, key);
          },
          [&, this](ConfigKeyStackMode) { set_stack_mode_config(assignment); },
          [&, this](ConfigKeyUserSymbolCacheType) {
            set_user_symbol_cache_type_config(assignment);
          },
          [&, this](ConfigKeyMissingProbes) {
            set_missing_probes_config(assignment);
          } },
      configKey);
}

bool ConfigAnalyser::analyse()
{
  Visit(*root_);
  std::string errors = err_.str();
  if (!errors.empty()) {
    out_ << errors;
    return false;
  }
  return true;
}

Pass CreateConfigPass()
{
  auto fn = [](Node &n, PassContext &ctx) {
    auto configs = ConfigAnalyser(&n, ctx.b);
    if (!configs.analyse())
      return PassResult::Error("Config");
    return PassResult::Success();
  };

  return Pass("ConfigAnalyser", fn);
};

} // namespace ast
} // namespace bpftrace
