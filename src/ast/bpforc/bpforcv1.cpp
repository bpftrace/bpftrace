// Included by bpforc.cpp

BpfOrc::BpfOrc(TargetMachine *TM, DataLayout DL)
    : TM(TM),
      DL(std::move(DL)),
#if LLVM_VERSION_MAJOR >= 7
      Resolver(createLegacyLookupResolver(
          ES,
          [](const std::string &Name __attribute__((unused))) -> JITSymbol {
            return nullptr;
          },
          [](Error Err) { cantFail(std::move(Err), "lookup failed"); })),
#endif
#if LLVM_VERSION_MAJOR >= 9
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
#elif LLVM_VERSION_MAJOR == 7
      ObjectLayer(ES,
                  [this](VModuleKey) {
                    return RTDyldObjectLinkingLayer::Resources{
                      std::make_shared<MemoryManager>(sections_), Resolver
                    };
                  }),
      CompileLayer(ObjectLayer, SimpleCompiler(*this->TM))
{
}
#elif LLVM_VERSION_MAJOR <= 6
      ObjectLayer(
          [this]() { return std::make_shared<MemoryManager>(sections_); }),
      CompileLayer(ObjectLayer, SimpleCompiler(*TM))
{
}
#endif

#if LLVM_VERSION_MAJOR >= 7
void BpfOrc::compile(std::unique_ptr<Module> M)
{
  auto K = ES.allocateVModule();
  cantFail(CompileLayer.addModule(K, std::move(M)));
  cantFail(CompileLayer.emitAndFinalize(K));
}
#else

void BpfOrc::compile(std::unique_ptr<Module> M)
{
  auto Resolver = createLambdaResolver(
      [](const std::string &) { return JITSymbol(nullptr); },
      [](const std::string &) { return JITSymbol(nullptr); });

  auto mod = cantFail(
      CompileLayer.addModule(std::move(M), std::move(Resolver)));
  cantFail(CompileLayer.emitAndFinalize(mod));
}
#endif

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
