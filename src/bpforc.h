#pragma once

#include <llvm/ADT/StringRef.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/JITSymbol.h>
#include <llvm/ExecutionEngine/Orc/CompileOnDemandLayer.h>
#include <llvm/ExecutionEngine/Orc/CompileUtils.h>
#include <llvm/ExecutionEngine/Orc/ExecutionUtils.h>
#include <llvm/ExecutionEngine/Orc/IRCompileLayer.h>
#if LLVM_VERSION_MAJOR == 6
#include <llvm/ExecutionEngine/Orc/LambdaResolver.h>
#endif
#include <llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Target/TargetMachine.h>

#ifdef LLVM_ORC_V2
#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h>
#endif

#include <optional>

namespace bpftrace {

const std::string LLVMTargetTriple = "bpf-pc-linux";

using namespace llvm;
using namespace llvm::orc;

/*
Custom memory manager to keep track of the address and size of code sections
created. Each section being a Probe.
*/
// name -> {addr, size}
using SectionMap =
    std::unordered_map<std::string, std::tuple<uint8_t *, uintptr_t>>;
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

  ~MemoryManager()
  {
    deregisterEHFrames();
  };

private:
  SectionMap &sections_;
};

class BpfOrc
{
private:
  SectionMap sections_;
  std::unique_ptr<TargetMachine> TM;
  DataLayout DL;
#if LLVM_VERSION_MAJOR >= 7
  ExecutionSession ES;
#endif
#if LLVM_VERSION_MAJOR >= 7 && LLVM_VERSION_MAJOR < 12
  std::shared_ptr<SymbolResolver> Resolver;
#endif

#ifdef LLVM_ORC_V2
  RTDyldObjectLinkingLayer ObjectLayer;
  IRCompileLayer CompileLayer;
  MangleAndInterner Mangle;
  ThreadSafeContext CTX;
  JITDylib &MainJD;
#else // LLVM_ORC_V1
#if LLVM_VERSION_MAJOR >= 8
  LLVMContext CTX;
  LegacyRTDyldObjectLinkingLayer ObjectLayer;
  LegacyIRCompileLayer<decltype(ObjectLayer), SimpleCompiler> CompileLayer;
#else
  LLVMContext CTX;
  RTDyldObjectLinkingLayer ObjectLayer;
  IRCompileLayer<decltype(ObjectLayer), SimpleCompiler> CompileLayer;
#endif

#endif

public:
  BpfOrc(TargetMachine *TM, DataLayout DL);
  void compile(std::unique_ptr<Module> M);

  /* Helper for creating a orc object, responsible for creating internal objects
   */
  static std::unique_ptr<BpfOrc> Create();

  /* get the {addr, size} of a code section */
  std::optional<std::tuple<uint8_t *, uintptr_t>> getSection(
      const std::string &name);

  LLVMContext &getContext();
  const DataLayout &getDataLayout() const
  {
    return DL;
  }

  TargetMachine &getTargetMachine()
  {
    return *TM;
  }

  /* Dump the JIT state, only works for ORCv2 */
  void dump([[maybe_unused]] raw_ostream &os)
  {
#ifdef LLVM_ORC_V2
    MainJD.dump(os);
#endif
  }

#ifdef LLVM_ORC_V2
  Expected<JITEvaluatedSymbol> lookup(StringRef Name)
  {
    return ES.lookup({ &MainJD }, Mangle(Name.str()));
  }
#endif
};

} // namespace bpftrace
