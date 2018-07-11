#pragma once

#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JITSymbol.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/LambdaResolver.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/Target/TargetMachine.h"

namespace bpftrace {

using namespace llvm;
using namespace llvm::orc;

class MemoryManager : public SectionMemoryManager
{
public:
  explicit MemoryManager(std::map<std::string, std::tuple<uint8_t *, uintptr_t>> &sections)
    : sections_(sections) { }
  uint8_t *allocateCodeSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, StringRef SectionName) override
  {
    uint8_t *addr = SectionMemoryManager::allocateCodeSection(Size, Alignment, SectionID, SectionName);
    sections_[SectionName.str()] = std::make_tuple(addr, Size);
    return addr;
  }

  uint8_t *allocateDataSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, StringRef SectionName, bool isReadOnly) override
  {
    uint8_t *addr = SectionMemoryManager::allocateDataSection(Size, Alignment, SectionID, SectionName, isReadOnly);
    sections_[SectionName.str()] = std::make_tuple(addr, Size);
    return addr;
  }

private:
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> &sections_;
};

class BpfOrc
{
private:
  std::unique_ptr<TargetMachine> TM;
  RTDyldObjectLinkingLayer ObjectLayer;
  IRCompileLayer<decltype(ObjectLayer), SimpleCompiler> CompileLayer;

public:
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> sections_;

  using ModuleHandle = decltype(CompileLayer)::ModuleHandleT;

  BpfOrc(TargetMachine *TM_)
    : TM(TM_),
      ObjectLayer([this]() { return std::make_shared<MemoryManager>(sections_); }),
      CompileLayer(ObjectLayer, SimpleCompiler(*TM))
  {
  }

  void compileModule(std::unique_ptr<Module> M)
  {
    auto mod = addModule(move(M));
    CompileLayer.emitAndFinalize(mod);
  }

  ModuleHandle addModule(std::unique_ptr<Module> M) {
    // We don't actually care about resolving symbols from other modules
    auto Resolver = createLambdaResolver(
        [](const std::string &Name) { return JITSymbol(nullptr); },
        [](const std::string &Name) { return JITSymbol(nullptr); });

    return cantFail(CompileLayer.addModule(std::move(M), std::move(Resolver)));
  }
};

} // namespace bpftrace
