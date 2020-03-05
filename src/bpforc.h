#pragma once

#include "llvm/Config/llvm-config.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JITSymbol.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/LambdaResolver.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
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

#if LLVM_VERSION_MAJOR >= 5 && LLVM_VERSION_MAJOR < 7
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
    cantFail(CompileLayer.emitAndFinalize(mod));
  }

  ModuleHandle addModule(std::unique_ptr<Module> M)
  {
    // We don't actually care about resolving symbols from other modules
    auto Resolver = createLambdaResolver(
        [](const std::string &) { return JITSymbol(nullptr); },
        [](const std::string &) { return JITSymbol(nullptr); });

    return cantFail(CompileLayer.addModule(std::move(M), std::move(Resolver)));
  }
};
#elif LLVM_VERSION_MAJOR >= 7
class BpfOrc
{
private:
  ExecutionSession ES;
  std::unique_ptr<TargetMachine> TM;
  std::shared_ptr<SymbolResolver> Resolver;
#if LLVM_VERSION_MAJOR >= 8
  LegacyRTDyldObjectLinkingLayer ObjectLayer;
  LegacyIRCompileLayer<decltype(ObjectLayer), SimpleCompiler> CompileLayer;
#else
  RTDyldObjectLinkingLayer ObjectLayer;
  IRCompileLayer<decltype(ObjectLayer), SimpleCompiler> CompileLayer;
#endif

public:
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> sections_;

  BpfOrc(TargetMachine *TM_)
      : TM(TM_),
        Resolver(createLegacyLookupResolver(
            ES,
            [](const std::string &Name __attribute__((unused))) -> JITSymbol {
              return nullptr;
            },
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
                     SimpleCompiler(*TM))
  {
  }
#elif LLVM_VERSION_MAJOR == 8
        ObjectLayer(ES,
                    [this](VModuleKey) {
                      return LegacyRTDyldObjectLinkingLayer::Resources{
                        std::make_shared<MemoryManager>(sections_), Resolver
                      };
                    }),
        CompileLayer(ObjectLayer, SimpleCompiler(*TM))
  {
  }
#else
        ObjectLayer(ES,
                    [this](VModuleKey) {
                      return RTDyldObjectLinkingLayer::Resources{
                        std::make_shared<MemoryManager>(sections_), Resolver
                      };
                    }),
        CompileLayer(ObjectLayer, SimpleCompiler(*TM))
  {
  }
#endif

  void compileModule(std::unique_ptr<Module> M)
  {
    auto K = addModule(move(M));
    cantFail(CompileLayer.emitAndFinalize(K));
  }

  VModuleKey addModule(std::unique_ptr<Module> M)
  {
    auto K = ES.allocateVModule();
    cantFail(CompileLayer.addModule(K, std::move(M)));
    return K;
  }
};
#else
#error Unsupported LLVM version
#endif

} // namespace bpftrace
