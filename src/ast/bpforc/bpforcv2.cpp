// Included by bpforc.cpp

BpfOrc::BpfOrc(TargetMachine *TM,
               DataLayout DL,
               std::unique_ptr<ExecutionSession> ES)
    : TM(std::move(TM)),
      DL(std::move(DL)),
      ES(std::move(ES)),
      ObjectLayer(*(this->ES),
                  [this]() {
                    return std::make_unique<MemoryManager>(sections_);
                  }),
      CompileLayer(*this->ES,
                   ObjectLayer,
                   std::make_unique<SimpleCompiler>(*this->TM)),
      Mangle(*this->ES, this->DL),
      CTX(std::make_unique<LLVMContext>()),
      MainJD(cantFail(this->ES->createJITDylib("<main>")))
{
}
LLVMContext &BpfOrc::getContext()
{
  return *CTX.getContext();
}

std::unique_ptr<BpfOrc> BpfOrc::Create()
{
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFAsmPrinter();

  auto JTMB = cantFail(
      Expected<JITTargetMachineBuilder>(Triple(LLVMTargetTriple)));

  // return unique_ptrs
  auto DL = cantFail(JTMB.getDefaultDataLayoutForTarget());
  auto TM = cantFail(JTMB.createTargetMachine());
#if LLVM_VERSION_MAJOR >= 13
  auto EPC = SelfExecutorProcessControl::Create();
  auto ES = std::make_unique<ExecutionSession>(std::move(*EPC));
#else
  auto ES = std::make_unique<ExecutionSession>();
#endif
  return std::make_unique<BpfOrc>(TM.release(), std::move(DL), std::move(ES));
}

void BpfOrc::compile(std::unique_ptr<Module> M)
{
  cantFail(CompileLayer.add(MainJD, ThreadSafeModule(std::move(M), CTX)));
}
