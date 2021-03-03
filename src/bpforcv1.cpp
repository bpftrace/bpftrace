// Included by bpforc.cpp

BpfOrc::BpfOrc(TargetMachine *TM, DataLayout DL)
    : TM(TM),
      DL(std::move(DL)),
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

LLVMContext &BpfOrc::getContext()
{
  return CTX;
}

std::unique_ptr<BpfOrc> BpfOrc::Create()
{
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFAsmPrinter();

  std::string error;
  const Target *target = TargetRegistry::lookupTarget(LLVMTargetTriple, error);
  if (!target)
    throw std::runtime_error("Could not create LLVM target " + error);

  TargetOptions opt;
  auto RM = Reloc::Model();
  auto TM = target->createTargetMachine(
      LLVMTargetTriple, "generic", "", opt, RM);

  return std::make_unique<BpfOrc>(TM, TM->createDataLayout());
}
