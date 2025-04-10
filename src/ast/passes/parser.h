#pragma once

#include "ast/attachpoint_parser.h"
#include "ast/pass_manager.h"
#include "ast/passes/deprecated.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/map_sugar.h"
#include "btf.h"
#include "clang_parser.h"
#include "driver.h"
#include "tracepoint_format_parser.h"

namespace bpftrace::ast {

// AllParsePasses returns a vector of passes representing all parser passes, in
// the expected order. This should be used unless there's a reason not to.
inline std::vector<Pass> AllParsePasses(
    std::vector<std::string> &&extra_flags = {})
{
  std::vector<Pass> passes;
  passes.emplace_back(CreateParsePass());
  passes.emplace_back(CreateDeprecatedPass());
  passes.emplace_back(CreateParseAttachpointsPass());
  passes.emplace_back(CreateParseBTFPass());
  passes.emplace_back(CreateParseTracepointFormatPass());
  passes.emplace_back(CreateFieldAnalyserPass());
  passes.emplace_back(CreateClangPass(std::move(extra_flags)));
  // The source and syntax is reparsed because it uses the `macros_` which are
  // set during the clang parse to expand identifiers within the lexer.
  passes.emplace_back(CreateParsePass());
  passes.emplace_back(CreateParseAttachpointsPass());
  passes.emplace_back(CreateMapSugarPass());
  return passes;
}

} // namespace bpftrace::ast
