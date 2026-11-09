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

  // An object with the libbpf prototypes of all BPF helpers, as members of
  // `HELPERS_STRUCT`. It is only built if there are `helper::` calls, is only
  // used for its BTF, and is never linked.
  std::string helpers_object;
  static constexpr std::string_view HELPERS_STRUCT = "__bpftrace_helpers";
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
