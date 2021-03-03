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
                               StringRef SectionName) override
  {
    uint8_t *addr = SectionMemoryManager::allocateCodeSection(
        Size, Alignment, SectionID, SectionName);
    sections_[SectionName.str()] = std::make_tuple(addr, Size);
    return addr;
  }

  uint8_t *allocateDataSection(uintptr_t Size,
                               unsigned Alignment,
                               unsigned SectionID,
                               StringRef SectionName,
                               bool isReadOnly) override
  {
    uint8_t *addr = SectionMemoryManager::allocateDataSection(
        Size, Alignment, SectionID, SectionName, isReadOnly);
    sections_[SectionName.str()] = std::make_tuple(addr, Size);
    return addr;
  }

private:
  SectionMap &sections_;
};

#if LLVM_VERSION_MAJOR >= 7
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

public:
  SectionMap sections_;

  BpfOrc(TargetMachine *TM)
      : TM(TM),
        DL(this->TM->createDataLayout()),
        Resolver(createLegacyLookupResolver(
            ES,
#if LLVM_VERSION_MAJOR >= 11
            [](llvm::StringRef Name __attribute__((unused))) -> JITSymbol {
              return nullptr;
            },
#else
            [](const std::string &Name __attribute__((unused))) -> JITSymbol {
              return nullptr;
            },
#endif
            [](Error Err) { cantFail(std::move(Err), "lookup failed"); })),
#if LLVM_VERSION_MAJOR > 8
        ObjectLayer(AcknowledgeORCv1Deprecation,
                    ES,
                    [this](VModuleKey) {
                      return LegacyRTDyldObjectLinkingLayer::Resources{
                        std::make_shared<MemoryManager>(sections_), Resolver
                      };
                    }),
        CompileLayer(AcknowledgeORCv1Deprecation,
                     ObjectLayer,
                     SimpleCompiler(*this->TM))
  {
  }
#elif LLVM_VERSION_MAJOR == 8
        ObjectLayer(ES,
                    [this](VModuleKey) {
                      return LegacyRTDyldObjectLinkingLayer::Resources{
                        std::make_shared<MemoryManager>(sections_), Resolver
                      };
                    }),
        CompileLayer(ObjectLayer, SimpleCompiler(*this->TM))
  {
  }
#else
        ObjectLayer(ES,
                    [this](VModuleKey) {
                      return RTDyldObjectLinkingLayer::Resources{
                        std::make_shared<MemoryManager>(sections_), Resolver
                      };
                    }),
        CompileLayer(ObjectLayer, SimpleCompiler(*this->TM))
  {
  }
#endif

  void compileModule(std::unique_ptr<Module> M)
  {
    auto K = ES.allocateVModule();
    cantFail(CompileLayer.addModule(K, std::move(M)));
    cantFail(CompileLayer.emitAndFinalize(K));
  }

  const DataLayout &getDataLayout() const
  {
    return DL;
  }

  LLVMContext &getContext()
  {
    return CTX;
  }

  TargetMachine & getTargetMachine()
  {
    return *TM;
  }

  static std::unique_ptr<BpfOrc> Create()
  {
    std::string targetTriple = "bpf-pc-linux";

    LLVMInitializeBPFTargetInfo();
    LLVMInitializeBPFTarget();
    LLVMInitializeBPFTargetMC();
    LLVMInitializeBPFAsmPrinter();

    std::string error;
    const Target *target = TargetRegistry::lookupTarget(targetTriple, error);
    if (!target)
      throw std::runtime_error("Could not create LLVM target " + error);

    TargetOptions opt;
    auto RM = Reloc::Model();
    auto TM = target->createTargetMachine(targetTriple, "generic", "", opt, RM);

    return std::make_unique<BpfOrc>(TM);
  }
};
#else
#error Unsupported LLVM version
#endif

} // namespace bpftrace
