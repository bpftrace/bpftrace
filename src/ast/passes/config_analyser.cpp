#include <cstring>
#include <string>

#include "ast/ast.h"
#include "ast/passes/config_analyser.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "config.h"

namespace bpftrace::ast {

namespace {

class ConfigAnalyser : public Visitor<ConfigAnalyser> {
public:
  explicit ConfigAnalyser(BPFtrace &bpftrace) : bpftrace_(bpftrace) {};

  using Visitor<ConfigAnalyser>::visit;
  void visit(AssignConfigVarStatement &assignment);

private:
  BPFtrace &bpftrace_;
};

} // namespace

void ConfigAnalyser::visit(AssignConfigVarStatement &assignment)
{
  // If this is deprecated, just emit a warning and move on. This is done here
  // because they are no longer understood by the actual config type.
  if (DEPRECATED_CONFIGS.contains(assignment.var)) {
    assignment.addWarning()
        << assignment.var << " is deprecated and has no effect";
    return;
  }

  std::string var(assignment.var);
  while (true) {
    // Set the variable.
    auto ok = std::visit(
        [&](const auto &v) { return bpftrace_.config_->set(var, v); },
        assignment.value);

    // Attempt to handle a rename error, and find the new name. This is done
    // here rather than the config so that we can emit a suitable error.
    if (!ok) {
      ok = handleErrors(std::move(ok),
                        [&](const RenameError &e) { var = e.new_name(); });
      if (!ok) {
        assignment.addError() << ok.takeError();
        return;
      }
      continue;
    }
    break; // All set.
  }
  if (var != assignment.var) {
    assignment.addWarning()
        << assignment.var << " has been renamed, please use " << var;
  }
}

Pass CreateConfigPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) -> Result<OK> {
    auto configs = ConfigAnalyser(b);
    configs.visit(ast.root);

    // Reload any environment changes.
    auto ok = b.config_->load_environment();
    if (!ok) {
      return ok.takeError();
    }

    return OK();
  };

  return Pass::create("ConfigAnalyser", fn);
};

} // namespace bpftrace::ast
