#include "bpforc.h"

namespace bpftrace {

using namespace llvm;
using namespace llvm::orc;

uint8_t *MemoryManager::allocateCodeSection(uintptr_t Size,
                                            unsigned Alignment,
                                            unsigned SectionID,
                                            StringRef SectionName)
{
  uint8_t *addr = SectionMemoryManager::allocateCodeSection(
      Size, Alignment, SectionID, SectionName);
  sections_[SectionName.str()] = std::make_tuple(addr, Size);
  return addr;
}

uint8_t *MemoryManager::allocateDataSection(uintptr_t Size,
                                            unsigned Alignment,
                                            unsigned SectionID,
                                            StringRef SectionName,
                                            bool isReadOnly)
{
  uint8_t *addr = SectionMemoryManager::allocateDataSection(
      Size, Alignment, SectionID, SectionName, isReadOnly);
  sections_[SectionName.str()] = std::make_tuple(addr, Size);
  return addr;
}

BpfOrc::BpfOrc(TargetMachine *TM)
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

void BpfOrc::compile(std::unique_ptr<Module> M)
{
  auto K = ES.allocateVModule();
  cantFail(CompileLayer.addModule(K, std::move(M)));
  cantFail(CompileLayer.emitAndFinalize(K));
}

const DataLayout &BpfOrc::getDataLayout() const
{
  return DL;
}

LLVMContext &BpfOrc::getContext()
{
  return CTX;
}

TargetMachine &BpfOrc::getTargetMachine()
{
  return *TM;
}

std::unique_ptr<BpfOrc> BpfOrc::Create()
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

std::optional<std::tuple<uint8_t *, uintptr_t>> BpfOrc::getSection(
    const std::string &name) const
{
  auto sec = sections_.find(name);
  if (sec == sections_.end())
    return {};
  return sec->second;
}

} // namespace bpftrace
