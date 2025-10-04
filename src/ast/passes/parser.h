#pragma once

#include "ast/pass_manager.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/builtins.h"
#include "ast/passes/c_macro_expansion.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/config_analyser.h"
#include "ast/passes/control_flow_analyser.h"
#include "ast/passes/deprecated.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/import_scripts.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/pid_filter_pass.h"
#include "ast/passes/probe_expansion.h"
#include "ast/passes/recursion_check.h"
#include "ast/passes/resolve_imports.h"
#include "ast/passes/unstable_feature.h"
#include "ast/passes/usdt_arguments.h"
#include "btf.h"
#include "driver.h"
#include "tracepoint_format_parser.h"

namespace bpftrace::ast {

// AllParsePasses returns a vector of passes representing all parser passes, in
// the expected order. This should be used unless there's a reason not to.
inline std::vector<Pass> AllParsePasses(
    std::vector<std::string> &&extra_flags = {},
    std::vector<std::string> &&import_paths = {},
    bool debug = false)
{
  std::vector<Pass> passes;
  passes.emplace_back(CreateParsePass(debug));
  passes.emplace_back(CreateConfigPass());
  passes.emplace_back(CreateResolveImportsPass(std::move(import_paths)));

  // N.B. We expand the AST with all externally imported scripts, then check
  // against unstable features, *then* import all internal scripts. This means
  // that internal scripts are except from the unstable feature warning.
  passes.emplace_back(CreateImportExternalScriptsPass());
  passes.emplace_back(CreateUnstableFeaturePass());
  passes.emplace_back(CreateDeprecatedPass());

  // Attachpoints are parsed and checked, but not yet expanded.
  passes.emplace_back(CreateParseAttachpointsPass());
  passes.emplace_back(CreateCheckAttachpointsPass());

  // Any transformations that rely on conditional internal imports should be
  // placed here, and should be careful not to rely on control flow analysis.
  passes.emplace_back(CreateUSDTImportPass());
  passes.emplace_back(CreateImportInternalScriptsPass());

  // After this point, all imports have been resolved, and everthing is present
  // but unexpanded. We now perform control flow analysis to ensure that all
  // macros are well-formed, and transformations that assume control flow can be
  // placed *after* this point.
  passes.emplace_back(CreateControlFlowPass());
  passes.emplace_back(CreatePidFilterPass());
  passes.emplace_back(CreateRecursionCheckPass());

  // All macros are expanded.
  passes.emplace_back(CreateMacroExpansionPass());

  // Past this point, the AST should not generally grow and will have builtins
  // replaced, simplifications applied, types filled in, etc.
  passes.emplace_back(CreateParseBTFPass());
  passes.emplace_back(CreateProbeExpansionPass());
  passes.emplace_back(CreateParseTracepointFormatPass());
  passes.emplace_back(CreateBuiltinsPass());
  passes.emplace_back(CreateFieldAnalyserPass());
  passes.emplace_back(CreateClangParsePass(std::move(extra_flags)));
  passes.emplace_back(CreateCMacroExpansionPass());
  passes.emplace_back(CreateMapSugarPass());
  passes.emplace_back(CreateNamedParamsPass());
  return passes;
}

} // namespace bpftrace::ast
