#pragma once

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "ast/location.h"
#include "ast/pass_manager.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/resolve_imports.h"
#include "bpftrace.h"

namespace bpftrace::ast {

class BitcodeModules : public State<"bitcode"> {
public:
  struct Result {
    std::unique_ptr<llvm::Module> module;
    std::string object;
    Location loc;
    std::string name;
  };
  std::vector<Result> modules;
  std::set<std::string_view> built_imports;
};

class ClangBuildError : public ErrorInfo<ClangBuildError> {
public:
  static char ID;
  void log(llvm::raw_ostream &OS) const override;
  ClangBuildError(std::string msg) : msg_(std::move(msg)) {};

private:
  std::string msg_;
};

void build_imports(BPFtrace &bpftrace, CompileContext &ctx, ast::Imports &imports, BitcodeModules& bm);
ast::Pass CreateClangBuildPass();

} // namespace bpftrace::ast
