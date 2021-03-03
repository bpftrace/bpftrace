#pragma once

#include "llvm/Config/llvm-config.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JITSymbol.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/LambdaResolver.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include <llvm/Support/TargetRegistry.h>
#include "llvm/Target/TargetMachine.h"

namespace bpftrace {

using namespace llvm;
using namespace llvm::orc;

using SectionMap = std::map<std::string, std::tuple<uint8_t *, uintptr_t>>;
class MemoryManager : public SectionMemoryManager
{
public:
  explicit MemoryManager(SectionMap &sections) : sections_(sections)
  {
  }
  uint8_t *allocateCodeSection(uintptr_t Size,
                               unsigned Alignment,
                               unsigned SectionID,
                               StringRef SectionName) override;
  uint8_t *allocateDataSection(uintptr_t Size,
                               unsigned Alignment,
                               unsigned SectionID,
                               StringRef SectionName,
                               bool isReadOnly) override;
private:
  SectionMap &sections_;
};

class BpfOrc
{
private:
  ExecutionSession ES;
  std::unique_ptr<TargetMachine> TM;
  DataLayout DL;
  std::shared_ptr<SymbolResolver> Resolver;
  LLVMContext CTX;

#if LLVM_VERSION_MAJOR >= 8
  LegacyRTDyldObjectLinkingLayer ObjectLayer;
  LegacyIRCompileLayer<decltype(ObjectLayer), SimpleCompiler> CompileLayer;
#else
  RTDyldObjectLinkingLayer ObjectLayer;
  IRCompileLayer<decltype(ObjectLayer), SimpleCompiler> CompileLayer;
#endif

  SectionMap sections_;
public:
  BpfOrc(TargetMachine *TM);
  void compile(std::unique_ptr<Module> M);
  const DataLayout &getDataLayout() const;
  LLVMContext &getContext();
  TargetMachine & getTargetMachine();
  static std::unique_ptr<BpfOrc> Create();
  std::optional<std::tuple<uint8_t *, uintptr_t>> getSection(const std::string & name) const;
};

} // namespace bpftrace
