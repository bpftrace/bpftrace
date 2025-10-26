#pragma once

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "ast/location.h"
#include "ast/pass_manager.h"

namespace bpftrace::ast {

class BitcodeModules : public State<"bitcode"> {
public:
  struct Result {
    std::unique_ptr<llvm::Module> module;
    std::string object;
    Location loc;
  };
  std::vector<Result> modules;
};

class ClangBuildError : public ErrorInfo<ClangBuildError> {
public:
  static char ID;
  void log(llvm::raw_ostream &OS) const override;
  ClangBuildError(std::string msg) : msg_(std::move(msg)) {};

private:
  std::string msg_;
};

ast::Pass CreateClangBuildPass();

} // namespace bpftrace::ast
