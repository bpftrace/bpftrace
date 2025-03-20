#pragma once

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "ast/pass_manager.h"
#include "usdt.h"

namespace bpftrace::ast {

class CompileContext : public ast::State<"compile-context"> {
public:
  CompileContext() : context(std::make_unique<llvm::LLVMContext>()) {};
  std::unique_ptr<llvm::LLVMContext> context;
};

// LLVMInit will create the required LLVM context which can be subsequently
// shared by other passes. This should always be added, unless an external
// `LLVMContext` is injected into the pass ahead of time.
Pass CreateLLVMInitPass();

class CompiledModule : public ast::State<"compiled-module"> {
public:
  CompiledModule(std::unique_ptr<llvm::Module> module)
      : module(std::move(module)) {};
  std::unique_ptr<llvm::Module> module;
};

// Compiles the primary AST, and emits `CompiledModule`.
Pass CreateCompilePass(std::optional<std::reference_wrapper<USDTHelper>>
                           &&usdt_helper = std::nullopt);

// Dumps `CompiledModule` to the given stream.
Pass CreateDumpIRPass(std::ostream &out);

// Validates `CompiledModule`, and attaches an error diagnostic to the program
// itself if verification fails.
Pass CreateVerifyPass();

// In-place optimizes the `CompiledModule` emitted by the compile pass.
Pass CreateOptimizePass();

class BpfObject : public ast::State<"bpf-object"> {
public:
  BpfObject(std::span<char> data) : data(data.begin(), data.end()) {};
  std::vector<char> data;
};

// Produces the ELF data for the BPF bytecode as a `BpfObject`. This is
// required by the Link pass below.
Pass CreateObjectPass();

// Dumps `BpfObject` as disassembled bytecode.
Pass CreateDumpASMPass(std::ostream &out);

// Produces the final output `BpfBytecode` object from `BpfObject`.
Pass CreateLinkPass();

// AllCompilePasses returns a vector of passes representing all compile passes,
// in the expected order.
inline std::vector<Pass> AllCompilePasses(
    std::optional<std::reference_wrapper<USDTHelper>> &&usdt_helper =
        std::nullopt)
{
  std::vector<Pass> passes;
  passes.emplace_back(CreateLLVMInitPass());
  passes.emplace_back(CreateCompilePass(std::move(usdt_helper)));
  passes.emplace_back(CreateVerifyPass());
  passes.emplace_back(CreateOptimizePass());
  passes.emplace_back(CreateObjectPass());
  passes.emplace_back(CreateLinkPass());
  return passes;
}

} // namespace bpftrace::ast
