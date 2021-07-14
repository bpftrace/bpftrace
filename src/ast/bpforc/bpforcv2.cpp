// Included by bpforc.cpp

BpfOrc::BpfOrc(TargetMachine *TM, DataLayout DL)
    : TM(std::move(TM)),
      DL(std::move(DL)),
      ObjectLayer(ES,
                  [this]() {
                    return std::make_unique<MemoryManager>(sections_);
                  }),
      CompileLayer(ES,
                   ObjectLayer,
                   std::make_unique<SimpleCompiler>(*this->TM)),
      Mangle(ES, this->DL),
      CTX(std::make_unique<LLVMContext>()),
      MainJD(cantFail(ES.createJITDylib("<main>")))
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

  return std::make_unique<BpfOrc>(TM.release(), std::move(DL));
}

void BpfOrc::compile(std::unique_ptr<Module> M)
{
  cantFail(CompileLayer.add(MainJD, ThreadSafeModule(std::move(M), CTX)));
}
