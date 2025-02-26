#include "config_analyser.h"

#include <cstring>
#include <string>
#include <unordered_set>

#include "ast/ast.h"
#include "ast/visitor.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "config.h"
#include "log.h"
#include "types.h"

namespace bpftrace::ast {

namespace {

class ConfigAnalyser : public Visitor<ConfigAnalyser> {
public:
  explicit ConfigAnalyser(BPFtrace &bpftrace)
      : bpftrace_(bpftrace),
        config_setter_(ConfigSetter(*bpftrace.config_, ConfigSource::script))
  {
  }

  using Visitor<ConfigAnalyser>::visit;
  void visit(Integer &integer);
  void visit(String &string);
  void visit(StackMode &mode);
  void visit(AssignConfigVarStatement &assignment);

private:
  BPFtrace &bpftrace_;
  ConfigSetter config_setter_;

  void set_config(AssignConfigVarStatement &assignment, ConfigKeyInt key);
  void set_config(AssignConfigVarStatement &assignment, ConfigKeyBool key);
  void set_config(AssignConfigVarStatement &assignment, ConfigKeyString key);
  void set_config(AssignConfigVarStatement &assignment,
                  ConfigKeyUserSymbolCacheType key);
  void set_config(AssignConfigVarStatement &assignment,
                  ConfigKeySymbolSource key);
  void set_config(AssignConfigVarStatement &assignment, ConfigKeyStackMode key);
  void set_config(AssignConfigVarStatement &assignment,
                  ConfigKeyMissingProbes key);

  void log_type_error(SizedType &type,
                      Type expected_type,
                      AssignConfigVarStatement &assignment);
};

} // namespace

void ConfigAnalyser::log_type_error(SizedType &type,
                                    Type expected_type,
                                    AssignConfigVarStatement &assignment)
{
  assignment.addError() << "Invalid type for " << assignment.config_var
                        << ". Type: " << type.GetTy()
                        << ". Expected Type: " << expected_type;
}

void ConfigAnalyser::set_config(AssignConfigVarStatement &assignment,
                                ConfigKeyInt key)
{
  auto &assignTy = assignment.expr->type();
  if (!assignTy.IsIntegerTy()) {
    log_type_error(assignTy, Type::integer, assignment);
    return;
  }

  config_setter_.set(key, assignment.expr->as<Integer>()->n);
}

void ConfigAnalyser::set_config(AssignConfigVarStatement &assignment,
                                ConfigKeyBool key)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsIntegerTy()) {
    log_type_error(assignTy, Type::integer, assignment);
    return;
  }

  auto val = assignment.expr->as<Integer>()->n;
  if (val == 0) {
    config_setter_.set(key, false);
  } else if (val == 1) {
    config_setter_.set(key, true);
  } else {
    assignment.addError() << "Invalid value for " << assignment.config_var
                          << ". Needs to be 0 or 1. Value: " << val;
  }
}

void ConfigAnalyser::set_config(AssignConfigVarStatement &assignment,
                                [[maybe_unused]] ConfigKeyString key)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsStringTy()) {
    log_type_error(assignTy, Type::string, assignment);
    return;
  }

  config_setter_.set(key, assignment.expr->as<String>()->str);
}

void ConfigAnalyser::set_config(AssignConfigVarStatement &assignment,
                                [[maybe_unused]] ConfigKeyStackMode)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsStackModeTy()) {
    log_type_error(assignTy, Type::stack_mode, assignment);
    return;
  }

  config_setter_.set(assignTy.stack_type.mode);
}

void ConfigAnalyser::set_config(
    AssignConfigVarStatement &assignment,
    [[maybe_unused]] ConfigKeyUserSymbolCacheType key)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsStringTy()) {
    log_type_error(assignTy, Type::string, assignment);
    return;
  }

  auto val = assignment.expr->as<String>()->str;
  if (!config_setter_.set_user_symbol_cache_type(val))
    assignment.expr->addError();
}

void ConfigAnalyser::set_config(AssignConfigVarStatement &assignment,
                                [[maybe_unused]] ConfigKeySymbolSource key)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsStringTy()) {
    log_type_error(assignTy, Type::string, assignment);
    return;
  }

  auto val = assignment.expr->as<String>()->str;
  if (!config_setter_.set_symbol_source_config(val))
    assignment.expr->addError();
}

void ConfigAnalyser::set_config(AssignConfigVarStatement &assignment,
                                [[maybe_unused]] ConfigKeyMissingProbes key)
{
  auto &assignTy = assignment.expr->type;
  if (!assignTy.IsStringTy()) {
    log_type_error(assignTy, Type::string, assignment);
    return;
  }

  auto val = assignment.expr->as<String>()->str;
  if (!config_setter_.set_missing_probes_config(val))
    assignment.expr->addError();
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
    mode.addError() << "Unknown stack mode: '" + mode.mode + "'";
  }
}

void ConfigAnalyser::visit(AssignConfigVarStatement &assignment)
{
  Visitor<ConfigAnalyser>::visit(assignment);
  std::string &raw_ident = assignment.config_var;

  std::string err_msg;
  const auto maybeConfigKey = bpftrace_.config_->get_config_key(raw_ident,
                                                                err_msg);

  if (!maybeConfigKey.has_value()) {
    assignment.addError() << err_msg;
    return;
  }

  if (!assignment.expr->is_literal) {
    assignment.addError() << "Assignment for " << assignment.config_var
                          << " must be literal.";
    return;
  }

  auto configKey = maybeConfigKey.value();

  std::visit([&](auto key) { set_config(assignment, key); }, configKey);
}

Pass CreateConfigPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) {
    auto configs = ConfigAnalyser(b);
    configs.visit(ast.root);
  };

  return Pass::create("ConfigAnalyser", fn);
};

} // namespace bpftrace::ast
