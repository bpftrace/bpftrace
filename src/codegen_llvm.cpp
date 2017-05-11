#include "codegen_llvm.h"
#include "ast.h"
#include "parser.tab.hh"

#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

namespace ebpf {
namespace bpftrace {
namespace ast {

void CodegenLLVM::visit(Integer &integer)
{
  expr_ = ConstantInt::get(module_->getContext(), APInt(64, integer.n)); // TODO fix bit width
}

void CodegenLLVM::visit(Builtin &builtin)
{
  expr_ = b_.getInt64(0);
}

void CodegenLLVM::visit(Call &call)
{
  expr_ = b_.getInt64(0);
}

void CodegenLLVM::visit(Map &map)
{
  int mapfd;
  if (bpftrace_.maps_.find(map.ident) == bpftrace_.maps_.end()) {
    bpftrace_.maps_[map.ident] = std::make_unique<ebpf::bpftrace::Map>(map.ident);
  }
  mapfd = bpftrace_.maps_[map.ident]->mapfd_;

  Function *pseudo_func = module_->getFunction("llvm.bpf.pseudo");
  Value *map_ptr = b_.CreateCall(pseudo_func,
        {b_.getInt64(BPF_PSEUDO_MAP_FD), b_.getInt64(mapfd)});
  AllocaInst *key = createAllocaBPF(b_.getInt64Ty());
  b_.CreateStore(b_.getInt64(0), key); // TODO variable key

  // void *map_lookup_elem(&map, &key)
  FunctionType *lookup_func_type = FunctionType::get(
      b_.getInt8PtrTy(),
      {b_.getInt8PtrTy(), b_.getInt8PtrTy()},
      false);
  PointerType *lookup_func_ptr_type = PointerType::get(lookup_func_type, 0);
  Constant *lookup_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      b_.getInt64(BPF_MAP_LOOKUP_ELEM),
      lookup_func_ptr_type);
  CallInst *call = b_.CreateCall(lookup_func, {map_ptr, key});

  // Check if result == 0
  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_->getContext(), "lookup_success", parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_->getContext(), "lookup_failure", parent);
  BasicBlock *lookup_merge_block = BasicBlock::Create(module_->getContext(), "lookup_merge", parent);

  Value *value = createAllocaBPF(b_.getInt64Ty());
  Value *condition = b_.CreateICmpNE(
      b_.CreateIntCast(call, b_.getInt8PtrTy(), true),
      ConstantExpr::getCast(Instruction::IntToPtr, b_.getInt64(0), b_.getInt8PtrTy()),
      "map_lookup_cond");
  b_.CreateCondBr(condition, lookup_success_block, lookup_failure_block);
  b_.SetInsertPoint(lookup_success_block);
  Value *loaded_value = b_.CreateLoad(b_.getInt64Ty(), call);
  b_.CreateStore(loaded_value, value);
  b_.CreateBr(lookup_merge_block);
  b_.SetInsertPoint(lookup_failure_block);
  b_.CreateStore(b_.getInt64(0), value);
  b_.CreateBr(lookup_merge_block);
  b_.SetInsertPoint(lookup_merge_block);
  expr_ = b_.CreateLoad(value);
}

void CodegenLLVM::visit(Binop &binop)
{
  Value *lhs, *rhs;
  binop.left->accept(*this);
  lhs = expr_;
  binop.right->accept(*this);
  rhs = expr_;

  switch (binop.op) {
    case ebpf::bpftrace::Parser::token::EQ:    expr_ = b_.CreateICmpEQ (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::NE:    expr_ = b_.CreateICmpNE (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::LE:    expr_ = b_.CreateICmpSLE(lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::GE:    expr_ = b_.CreateICmpSGE(lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::LT:    expr_ = b_.CreateICmpSLT(lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::GT:    expr_ = b_.CreateICmpSGT(lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::LAND:  break;//expr_ = b_.CreateAnd(lhs, rhs); break; TODO
    case ebpf::bpftrace::Parser::token::LOR:   break;//expr_ = b_.CreateOR(lhs, rhs); break; TODO
    case ebpf::bpftrace::Parser::token::PLUS:  expr_ = b_.CreateAdd    (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::MINUS: expr_ = b_.CreateSub    (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::MUL:   expr_ = b_.CreateMul    (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::DIV:   expr_ = b_.CreateSDiv   (lhs, rhs); break; // TODO signed/unsigned
    case ebpf::bpftrace::Parser::token::MOD:   expr_ = b_.CreateURem   (lhs, rhs); break; // TODO signed/unsigned
    case ebpf::bpftrace::Parser::token::BAND:  expr_ = b_.CreateAnd    (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::BOR:   expr_ = b_.CreateOr     (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::BXOR:  expr_ = b_.CreateXor    (lhs, rhs); break;
    default: abort();
  }
}

void CodegenLLVM::visit(Unop &unop)
{
  unop.expr->accept(*this);

  switch (unop.op) {
    case ebpf::bpftrace::Parser::token::LNOT: expr_ = b_.CreateNot(expr_); break;
    case ebpf::bpftrace::Parser::token::BNOT: expr_ = b_.CreateNeg(expr_); break;
    default: abort();
  }
}

void CodegenLLVM::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void CodegenLLVM::visit(AssignMapStatement &assignment)
{
  Map &map = *assignment.map;
  int mapfd;
  if (bpftrace_.maps_.find(map.ident) == bpftrace_.maps_.end()) {
    bpftrace_.maps_[map.ident] = std::make_unique<ebpf::bpftrace::Map>(map.ident);
  }
  mapfd = bpftrace_.maps_[map.ident]->mapfd_;

  Function *pseudo_func = module_->getFunction("llvm.bpf.pseudo");
  Value *map_ptr = b_.CreateCall(pseudo_func,
        {b_.getInt64(BPF_PSEUDO_MAP_FD), b_.getInt64(mapfd)});
  AllocaInst *key = createAllocaBPF(b_.getInt64Ty());
  AllocaInst *val = createAllocaBPF(b_.getInt64Ty());
  Value *flags = b_.getInt64(0);

  b_.CreateStore(b_.getInt64(0), key); // TODO variable key
  assignment.expr->accept(*this);
  b_.CreateStore(expr_, val);

  // int map_update_elem(&map, &key, &value, flags)
  FunctionType *update_func_type = FunctionType::get(
      b_.getInt64Ty(),
      {b_.getInt8PtrTy(), b_.getInt8PtrTy(), b_.getInt8PtrTy(), b_.getInt64Ty()},
      false);
  PointerType *update_func_ptr_type = PointerType::get(update_func_type, 0);
  Constant *update_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      b_.getInt64(BPF_MAP_UPDATE_ELEM),
      update_func_ptr_type);
  CallInst *call = b_.CreateCall(update_func, {map_ptr, key, val, flags});
}

void CodegenLLVM::visit(AssignMapCallStatement &assignment)
{
}

void CodegenLLVM::visit(Predicate &pred)
{
  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *pred_false_block = BasicBlock::Create(
      module_->getContext(),
      "pred_false",
      parent);
  BasicBlock *pred_true_block = BasicBlock::Create(
      module_->getContext(),
      "pred_true",
      parent);

  pred.expr->accept(*this);

  expr_ = b_.CreateICmpEQ(
      b_.CreateIntCast(expr_, b_.getInt64Ty(), true),
      b_.getInt64(0),
      "predcond");

  b_.CreateCondBr(expr_, pred_false_block, pred_true_block);
  b_.SetInsertPoint(pred_false_block);
  b_.CreateRet(ConstantInt::get(module_->getContext(), APInt(64, 0)));

  b_.SetInsertPoint(pred_true_block);
}

void CodegenLLVM::visit(Probe &probe)
{
  FunctionType *func_type = FunctionType::get(b_.getInt64Ty(), false);
  Function *func = Function::Create(func_type, Function::ExternalLinkage, probe.name, module_.get());
  func->setSection(probe.name);
  BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", func);
  b_.SetInsertPoint(entry);

  if (probe.pred) {
    probe.pred->accept(*this);
  }
  for (Statement *stmt : *probe.stmts) {
    stmt->accept(*this);
  }

  b_.CreateRet(ConstantInt::get(module_->getContext(), APInt(64, 0)));
}

void CodegenLLVM::visit(Program &program)
{
  for (Probe *probe : *program.probes) {
    probe->accept(*this);
  }
}

class BPFtraceMemoryManager : public SectionMemoryManager
{
public:
  explicit BPFtraceMemoryManager(std::map<std::string, std::tuple<uint8_t *, uintptr_t>> &sections)
    : sections_(sections) { }
  uint8_t *allocateCodeSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, StringRef SectionName) override
  {
    uint8_t *addr = SectionMemoryManager::allocateCodeSection(Size, Alignment, SectionID, SectionName);
    sections_[SectionName.str()] = {addr, Size};
    return addr;
  }

  uint8_t *allocateDataSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, StringRef SectionName, bool isReadOnly) override
  {
    uint8_t *addr = SectionMemoryManager::allocateDataSection(Size, Alignment, SectionID, SectionName, isReadOnly);
    sections_[SectionName.str()] = {addr, Size};
    return addr;
  }

private:
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> &sections_;
};

int CodegenLLVM::compile(bool debug)
{
  // Declare external LLVM function
  FunctionType *pseudo_func_type = FunctionType::get(
      b_.getInt64Ty(),
      {b_.getInt64Ty(), b_.getInt64Ty()},
      false);
  Function::Create(
      pseudo_func_type,
      GlobalValue::ExternalLinkage,
      "llvm.bpf.pseudo",
      module_.get());

  root_->accept(*this);

  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFAsmPrinter();

  std::string targetTriple = "bpf-pc-linux";
  module_->setTargetTriple(targetTriple);

  std::string error;
  const Target *target = TargetRegistry::lookupTarget(targetTriple, error);
  if (!target) {
    std::cerr << "Could not create LLVM target" << std::endl;
    std::cerr << error << std::endl;
    abort();
  }

  TargetOptions opt;
  auto RM = Reloc::Model();
  TargetMachine *targetMachine = target->createTargetMachine(targetTriple, "generic", "", opt, RM);
  module_->setDataLayout(targetMachine->createDataLayout());

  legacy::PassManager PM;
  PassManagerBuilder PMB;
  PMB.OptLevel = 3;
  PMB.populateModulePassManager(PM);
  PM.run(*module_.get());

  if (debug)
    module_->dump();

  EngineBuilder builder(move(module_));
  builder.setMCJITMemoryManager(std::make_unique<BPFtraceMemoryManager>(bpftrace_.sections_));
  ee_ = std::unique_ptr<ExecutionEngine>(builder.create());
  ee_->finalizeObject();

  return 0;
}

AllocaInst *CodegenLLVM::createAllocaBPF(llvm::Type *ty, const std::string &name) const
{
  Function *parent = b_.GetInsertBlock()->getParent();
  Instruction *first_instr = &parent->getEntryBlock().front();
  return new AllocaInst(ty, "", first_instr);
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
