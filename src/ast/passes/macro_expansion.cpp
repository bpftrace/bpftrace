#include "macro_expansion.h"

#include "log.h"

namespace bpftrace::ast {

MacroExpansion::MacroExpansion(ASTContext &ctx)
    : Visitor<MacroExpansion>(ctx)
{
}

void MacroExpansion::run()
{
  for (Macro *macro : ctx_.root->macros) {
    macros_[macro->name] = macro;
  }

  visit(ctx_.root);
}

Expression *MacroExpansion::replace(Call *call, [[maybe_unused]] void *)
{
  if (auto it = macros_.find(call->func); it != macros_.end()) {
    LOG(DEBUG) << "Expanding call to: '" << call->func << "'";
    Macro *macro = it->second;

    // XXX: this does not rewrite macro args yet
    return macro->expr;
  }

  return call;
}

Pass CreateMacroExpansionPass()
{
  auto fn = [](PassContext &ctx) {
    MacroExpansion expander(ctx.ast_ctx);
    expander.run();

    return PassResult::Success();
  };

  return Pass("MacroExpansion", fn);
}

} // namespace bpftrace::ast
