#include "ast/passes/probe_prune.h"
#include "ast/ast.h"
#include "bpftrace.h"

namespace bpftrace::ast {

Pass CreateProbePrunePass()
{
  static std::string missing_msg = " has no valid attach points.";
  return Pass::create("ProbePrune", [](ASTContext &ast, BPFtrace &b) {
    auto missing_config = b.config_->missing_probes;
    for (Probe *probe : ast.root->probes) {
      if (probe->attach_points.empty()) {
        if (missing_config == ConfigMissingProbes::error) {
          probe->addError() << "Probe" << missing_msg
                            << " If this is expected, set the 'missing_probes' "
                               "config variable to 'warn'.";
        } else if (missing_config == ConfigMissingProbes::warn) {
          probe->addWarning()
              << "Probe " << missing_msg
              << " It is being removed which may cause issues with "
                 "program behavior.";
        }
      }
    };
    if (missing_config != ConfigMissingProbes::error) {
      ast.root->clear_empty_probes();
    }
  });
};

} // namespace bpftrace::ast
