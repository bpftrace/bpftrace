#include "codegen_llvm.h"
#include "ast.h"
#include "parser.tab.hh"
#include "arch/arch.h"

#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

namespace bpftrace {
namespace ast {

void CodegenLLVM::visit(Integer &integer)
{
  expr_ = b_.getInt64(integer.n);
}

void CodegenLLVM::visit(Builtin &builtin)
{
  if (builtin.ident == "nsecs")
  {
    expr_ = b_.CreateGetNs();
  }
  else if (builtin.ident == "stack")
  {
    expr_ = b_.CreateGetStackId(ctx_);
  }
  else if (builtin.ident == "pid" || builtin.ident == "tid")
  {
    Value *pidtgid = b_.CreateGetPidTgid();
    if (builtin.ident == "pid")
    {
      expr_ = b_.CreateLShr(pidtgid, 32);
    }
    else if (builtin.ident == "tid")
    {
      expr_ = b_.CreateAnd(pidtgid, 0xffffffff);
    }
  }
  else if (builtin.ident == "uid" || builtin.ident == "gid")
  {
    Value *uidgid = b_.CreateGetUidGid();
    if (builtin.ident == "uid")
    {
      expr_ = b_.CreateAnd(uidgid, 0xffffffff);
    }
    else if (builtin.ident == "gid")
    {
      expr_ = b_.CreateLShr(uidgid, 32);
    }
  }
  else if (!builtin.ident.compare(0, 3, "arg") && builtin.ident.size() == 4 &&
      builtin.ident.at(3) >= '0' && builtin.ident.at(3) <= '9')
  {
    int arg_num = atoi(builtin.ident.substr(3).c_str());

    AllocaInst *dst = b_.CreateAllocaBPF();
    int offset = arch::arg_offset(arg_num) * sizeof(uintptr_t);
    Value *src = b_.CreateGEP(ctx_, b_.getInt64(offset));
    b_.CreateProbeRead(dst, b_.getInt64(8), src);
    expr_ = b_.CreateLoad(dst);
  }
  else if (builtin.ident == "retval")
  {
    AllocaInst *dst = b_.CreateAllocaBPF();
    int offset = arch::ret_offset() * sizeof(uintptr_t);
    Value *src = b_.CreateGEP(ctx_, b_.getInt64(offset));
    b_.CreateProbeRead(dst, b_.getInt64(8), src);
    expr_ = b_.CreateLoad(dst);
  }
  else
  {
    abort();
  }
}

void CodegenLLVM::visit(Call &call)
{
  abort();
}

void CodegenLLVM::visit(Map &map)
{
  AllocaInst *key = getMapKey(map);
  expr_ = b_.CreateMapLookupElem(map, key);
}

void CodegenLLVM::visit(Binop &binop)
{
  Value *lhs, *rhs;
  binop.left->accept(*this);
  lhs = expr_;
  binop.right->accept(*this);
  rhs = expr_;

  switch (binop.op) {
    case bpftrace::Parser::token::EQ:    expr_ = b_.CreateICmpEQ (lhs, rhs); break;
    case bpftrace::Parser::token::NE:    expr_ = b_.CreateICmpNE (lhs, rhs); break;
    case bpftrace::Parser::token::LE:    expr_ = b_.CreateICmpSLE(lhs, rhs); break;
    case bpftrace::Parser::token::GE:    expr_ = b_.CreateICmpSGE(lhs, rhs); break;
    case bpftrace::Parser::token::LT:    expr_ = b_.CreateICmpSLT(lhs, rhs); break;
    case bpftrace::Parser::token::GT:    expr_ = b_.CreateICmpSGT(lhs, rhs); break;
    case bpftrace::Parser::token::LAND:  abort();// TODO
    case bpftrace::Parser::token::LOR:   abort();// TODO
    case bpftrace::Parser::token::PLUS:  expr_ = b_.CreateAdd    (lhs, rhs); break;
    case bpftrace::Parser::token::MINUS: expr_ = b_.CreateSub    (lhs, rhs); break;
    case bpftrace::Parser::token::MUL:   expr_ = b_.CreateMul    (lhs, rhs); break;
    case bpftrace::Parser::token::DIV:   expr_ = b_.CreateSDiv   (lhs, rhs); break; // TODO signed/unsigned
    case bpftrace::Parser::token::MOD:   expr_ = b_.CreateURem   (lhs, rhs); break; // TODO signed/unsigned
    case bpftrace::Parser::token::BAND:  expr_ = b_.CreateAnd    (lhs, rhs); break;
    case bpftrace::Parser::token::BOR:   expr_ = b_.CreateOr     (lhs, rhs); break;
    case bpftrace::Parser::token::BXOR:  expr_ = b_.CreateXor    (lhs, rhs); break;
    default: abort();
  }
}

void CodegenLLVM::visit(Unop &unop)
{
  unop.expr->accept(*this);

  switch (unop.op) {
    case bpftrace::Parser::token::LNOT: expr_ = b_.CreateNot(expr_); break;
    case bpftrace::Parser::token::BNOT: expr_ = b_.CreateNeg(expr_); break;
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

  AllocaInst *val = b_.CreateAllocaBPF();
  assignment.expr->accept(*this);
  b_.CreateStore(expr_, val);

  AllocaInst *key = getMapKey(map);

  b_.CreateMapUpdateElem(map, key, val);
}

void CodegenLLVM::visit(AssignMapCallStatement &assignment)
{
  Map &map = *assignment.map;
  Call &call = *assignment.call;

  if (call.func == "count")
  {
    AllocaInst *key = getMapKey(map);
    Value *oldval = b_.CreateMapLookupElem(map, key);
    AllocaInst *newval = b_.CreateAllocaBPF();
    b_.CreateStore(b_.CreateAdd(oldval, b_.getInt64(1)), newval);
    b_.CreateMapUpdateElem(map, key, newval);
  }
  else if (call.func == "quantize")
  {
    call.vargs->front()->accept(*this);
    Function *log2_func = module_->getFunction("log2");
    Value *log2 = b_.CreateCall(log2_func, expr_);
    AllocaInst *key = getQuantizeMapKey(map, log2);

    Value *oldval = b_.CreateMapLookupElem(map, key);
    AllocaInst *newval = b_.CreateAllocaBPF();
    b_.CreateStore(b_.CreateAdd(oldval, b_.getInt64(1)), newval);
    b_.CreateMapUpdateElem(map, key, newval);
  }
  else if (call.func == "delete")
  {
    AllocaInst *key = getMapKey(map);
    b_.CreateMapDeleteElem(map, key);
  }
  else
  {
    abort();
  }
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
  FunctionType *func_type = FunctionType::get(
      b_.getInt64Ty(),
      {b_.getInt8PtrTy()}, // struct pt_regs *ctx
      false);
  Function *func = Function::Create(func_type, Function::ExternalLinkage, probe.name, module_.get());
  func->setSection(probe.name);
  BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", func);
  b_.SetInsertPoint(entry);

  ctx_ = &func->getArgumentList().front();

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

AllocaInst *CodegenLLVM::getMapKey(Map &map)
{
  AllocaInst *key;
  if (map.vargs) {
    key = b_.CreateAllocaBPF(map.vargs->size());
    int i = 0;
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
      Value *offset = b_.CreateGEP(key, b_.getInt64(i++));
      b_.CreateStore(expr_, offset);
    }
  }
  else
  {
    key = b_.CreateAllocaBPF();
    b_.CreateStore(b_.getInt64(0), key);
  }
  return key;
}

AllocaInst *CodegenLLVM::getQuantizeMapKey(Map &map, Value *log2)
{
  AllocaInst *key;
  if (map.vargs) {
    key = b_.CreateAllocaBPF(map.vargs->size() + 1);
    int i = 0;
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
      Value *offset = b_.CreateGEP(key, b_.getInt64(i++));
      b_.CreateStore(expr_, offset);
    }
    Value *offset = b_.CreateGEP(key, b_.getInt64(i));
    b_.CreateStore(log2, offset);
  }
  else
  {
    key = b_.CreateAllocaBPF();
    b_.CreateStore(log2, key);
  }
  return key;
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

void CodegenLLVM::createLog2Function()
{
  // log2(int n)
  // {
  //   int result = 0;
  //   int shift;
  //   for (int i = 4; i >= 0; i--)
  //   {
  //     shift = (v >= (1<<(1<<i))) << i;
  //     n >> = shift;
  //     result += shift;
  //   }
  //   return result;
  // }

  FunctionType *log2_func_type = FunctionType::get(b_.getInt64Ty(), {b_.getInt64Ty()}, false);
  Function *log2_func = Function::Create(log2_func_type, Function::InternalLinkage, "log2", module_.get());
  log2_func->setSection("helpers");
  BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", log2_func);
  b_.SetInsertPoint(entry);

  Value *arg = &log2_func->getArgumentList().front();

  Value *n_alloc = b_.CreateAllocaBPF();
  b_.CreateStore(arg, n_alloc);

  Value *result = b_.CreateAllocaBPF();
  b_.CreateStore(b_.getInt64(0), result);

  for (int i = 4; i >= 0; i--)
  {
    Value *n = b_.CreateLoad(n_alloc);
    Value *shift = b_.CreateShl(b_.CreateIntCast(b_.CreateICmpSGE(b_.CreateIntCast(n, b_.getInt64Ty(), false), b_.getInt64(1 << (1<<i))), b_.getInt64Ty(), false), i);
    b_.CreateStore(b_.CreateLShr(n, shift), n_alloc);
    b_.CreateStore(b_.CreateAdd(b_.CreateLoad(result), shift), result);
  }
  b_.CreateRet(b_.CreateLoad(result));
}

int CodegenLLVM::compile(bool debug)
{
  createLog2Function();
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
  PM.add(createFunctionInliningPass());
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

} // namespace ast
} // namespace bpftrace
