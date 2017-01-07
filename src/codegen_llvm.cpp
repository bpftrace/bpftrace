#include "codegen_llvm.h"
#include "ast.h"
#include "parser.tab.hh"

#include <llvm/Support/TargetRegistry.h>

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
  if (maps_.find(map.ident) == maps_.end()) {
    maps_[map.ident] = std::make_unique<ebpf::bpftrace::Map>();
  }
  mapfd = maps_[map.ident]->mapfd_;
  expr_ = b_.getInt64(mapfd);

//   CALL(BPF_FUNC_map_lookup_elem)
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
    case ebpf::bpftrace::Parser::token::LAND:  break;//expr_ = b_.CreateAnd(lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::LOR:   break;//expr_ = b_.CreateOR(lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::PLUS:  expr_ = b_.CreateAdd    (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::MINUS: expr_ = b_.CreateSub    (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::MUL:   expr_ = b_.CreateMul    (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::DIV:   expr_ = b_.CreateSDiv   (lhs, rhs); break; // TODO signed/unsigned
    case ebpf::bpftrace::Parser::token::MOD:   expr_ = b_.CreateURem   (lhs, rhs); break; // TODO signed/unsigned
    case ebpf::bpftrace::Parser::token::BAND:  expr_ = b_.CreateAnd    (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::BOR:   expr_ = b_.CreateOr     (lhs, rhs); break;
    case ebpf::bpftrace::Parser::token::BXOR:  expr_ = b_.CreateXor    (lhs, rhs); break;
    default: break;
  }
}

void CodegenLLVM::visit(Unop &unop)
{
  unop.expr->accept(*this);

  switch (unop.op) {
    case ebpf::bpftrace::Parser::token::LNOT: expr_ = b_.CreateNot(expr_); break;
    case ebpf::bpftrace::Parser::token::BNOT: expr_ = b_.CreateNeg(expr_); break;
    default: break;
  }
}

void CodegenLLVM::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void CodegenLLVM::visit(AssignMapStatement &assignment)
{
  Value *map, *val;
  assignment.map->accept(*this);
  map = expr_;
  assignment.expr->accept(*this);
  val = expr_;

//   CALL(BPF_FUNC_map_update_elem)
}

void CodegenLLVM::visit(AssignMapCallStatement &assignment)
{
}

void CodegenLLVM::visit(Predicate &pred)
{
  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *pred_false_block = BasicBlock::Create(module_->getContext(), "pred_false", parent);
  BasicBlock *pred_true_block = BasicBlock::Create(module_->getContext(), "pred_true", parent);

  pred.expr->accept(*this);
  expr_ = b_.CreateICmpEQ(expr_, b_.getInt1(0), "predcond");

  b_.CreateCondBr(expr_, pred_false_block, pred_true_block);
  b_.SetInsertPoint(pred_false_block);
  b_.CreateRet(ConstantInt::get(module_->getContext(), APInt(64, 0)));

  b_.SetInsertPoint(pred_true_block);
}

void CodegenLLVM::visit(Probe &probe)
{
  FunctionType *func_type = FunctionType::get(b_.getInt64Ty(), false);
  Function *func = Function::Create(func_type, Function::ExternalLinkage, probe.name, module_.get());
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

int CodegenLLVM::compile()
{
  root_->accept(*this);
  module_->dump();

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
    abort();
  }

  TargetOptions opt;
  auto RM = Optional<Reloc::Model>();
  TargetMachine *targetMachine = target->createTargetMachine(targetTriple, "generic", "", opt, RM);
  module_->setDataLayout(targetMachine->createDataLayout());

  // TODO: Run some optimisation passes here

  EngineBuilder builder(move(module_));
  ee_ = std::unique_ptr<ExecutionEngine>(builder.create());
  ee_->finalizeObject();

  return 0;
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
