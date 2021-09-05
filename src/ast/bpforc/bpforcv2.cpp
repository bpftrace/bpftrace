// Included by bpforc.cpp

BpfOrc::BpfOrc(TargetMachine *TM,
               DataLayout DL,
               std::unique_ptr<ExecutionSession> ES)
    : TM(std::move(TM)),
      DL(std::move(DL)),
      ES(std::move(ES)),
      ObjectLayer(*this->ES,
                  []() { return std::make_unique<SectionMemoryManager>(); }),
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
  auto EPC = SelfExecutorProcessControl::Create();
  auto ES = std::make_unique<ExecutionSession>(std::move(*EPC));
  return std::make_unique<BpfOrc>(TM.release(), std::move(DL), std::move(ES));
}

void BpfOrc::compile(std::unique_ptr<Module> M)
{
  cantFail(CompileLayer.add(MainJD, ThreadSafeModule(std::move(M), CTX)));
}
