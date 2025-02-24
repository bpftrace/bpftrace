#include "macro_expansion.h"

#include "log.h"

#include <cstdint>

namespace bpftrace::ast {

MacroSpecializer::MacroSpecializer(ASTContext &ctx, std::ostream &out)
    : Visitor<MacroSpecializer>(ctx), out_(out)
{
}

void MacroSpecializer::visit(Variable &var)
{
  if (auto it = vars_.find(var.ident); it != vars_.end()) {
    var.ident = it->second;
  } else {
    LOG(ERROR, var.loc, err_) << "Unhygienic access to variable";
  }
}

void MacroSpecializer::visit(Map &map)
{
  if (auto it = maps_.find(map.ident); it != maps_.end()) {
    map.ident = it->second;
  } else {
    LOG(ERROR, map.loc, err_) << "Unhygienic access to map";
  }
}

Expression *MacroSpecializer::specialize(Macro &macro, const Call &call)
{
  maps_.clear();
  vars_.clear();

  if (macro.args.size() != call.vargs.size()) {
    LOG(ERROR, call.loc, err_)
        << "Call to macro has wrong number arguments: " << macro.args.size()
        << "!=" << call.vargs.size();
  }

  for (size_t i = 0; i < call.vargs.size(); i++) {
    Expression *marg = macro.args[i];
    Expression *carg = call.vargs[i];

    if (auto *cvar = dynamic_cast<Variable *>(carg)) {
      if (auto *mvar = dynamic_cast<Variable *>(marg)) {
        vars_[mvar->ident] = cvar->ident;
      } else {
        LOG(ERROR, call.loc, err_)
            << "Mismatched arg=" << i << " to macro call";
      }
    } else if (auto *cmap = dynamic_cast<Map *>(carg)) {
      if (auto *mmap = dynamic_cast<Map *>(marg)) {
        maps_[mmap->ident] = cmap->ident;
      } else {
        LOG(ERROR, call.loc, err_)
            << "Mismatched arg=" << i << " to macro call";
      }
    } else {
      LOG(BUG) << "Parser let in a non-var and non-map macro argument";
    }
  }

  // TODO: clone the macro body
  visit(macro.expr);

  std::string errors = err_.str();
  if (!errors.empty()) {
    out_ << errors;
    return nullptr;
  } else {
    return macro.expr;
  }
}

MacroExpansion::MacroExpansion(ASTContext &ctx, std::ostream &out)
    : Visitor<MacroExpansion>(ctx), out_(out)
{
}

int MacroExpansion::run()
{
  for (Macro *macro : ctx_.root->macros) {
    macros_[macro->name] = macro;
  }

  visit(ctx_.root);

  std::string errors = err_.str();
  if (!errors.empty()) {
    out_ << errors;
    return 1;
  }

  return 0;
}

Expression *MacroExpansion::replace(Call *call, [[maybe_unused]] void *)
{
  if (auto it = macros_.find(call->func); it != macros_.end()) {
    if (called_.contains(call->func)) {
      LOG(ERROR, call->loc, err_)
          << "The PoC can only handle a single call of: " << call->func;
      return nullptr;
    } else {
      called_.insert(call->func);
    }

    Macro *macro = it->second;
    MacroSpecializer specializer(ctx_, out_);
    Expression *expr = specializer.specialize(*macro, *call);
    if (expr) {
      return expr;
    } else {
      LOG(ERROR, call->loc, err_)
          << "Failed to specialize macro: " << call->func;
      return call;
    }
  }

  return call;
}

Pass CreateMacroExpansionPass()
{
  auto fn = [](PassContext &ctx) {
    MacroExpansion expander(ctx.ast_ctx);
    if (expander.run())
      return PassResult::Error("");

    return PassResult::Success();
  };

  return Pass("MacroExpansion", fn);
}

} // namespace bpftrace::ast
