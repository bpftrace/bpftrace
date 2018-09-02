#include "bpforc.h"
#include "codegen_llvm.h"
#include "ast.h"
#include "parser.tab.hh"
#include "arch/arch.h"
#include "types.h"

#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm-c/Transforms/IPO.h>

namespace bpftrace {
namespace ast {

void CodegenLLVM::visit(Integer &integer)
{
  expr_ = b_.getInt64(integer.n);
}

void CodegenLLVM::visit(String &string)
{
  string.str.resize(string.type.size-1);
  Constant *const_str = ConstantDataArray::getString(module_->getContext(), string.str, true);
  AllocaInst *buf = b_.CreateAllocaBPF(string.type, "str");
  b_.CreateStore(b_.CreateGEP(const_str, b_.getInt64(0)), buf);
  expr_ = buf;
}

void CodegenLLVM::visit(Builtin &builtin)
{
  if (builtin.ident == "nsecs")
  {
    expr_ = b_.CreateGetNs();
  }
  else if (builtin.ident == "stack" || builtin.ident == "ustack")
  {
    // pack uint64_t with: (uint32_t)stack_id, (uint32_t)pid
    Value *pidhigh = b_.CreateShl(b_.CreateGetPidTgid(), 32);
    Value *stackid = b_.CreateGetStackId(ctx_, builtin.ident == "ustack");
    expr_ = b_.CreateOr(stackid, pidhigh);
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
  else if (builtin.ident == "cpu")
  {
    expr_ = b_.CreateGetCpuId();
  }
  else if (builtin.ident == "curtask")
  {
    expr_ = b_.CreateGetCurrentTask();
  }
  else if (builtin.ident == "rand")
  {
    expr_ = b_.CreateGetRandom();
  }
  else if (builtin.ident == "comm")
  {
    AllocaInst *buf = b_.CreateAllocaBPF(builtin.type, "comm");
    // initializing memory needed for older kernels:
    b_.CreateMemSet(buf, b_.getInt8(0), builtin.type.size, 1);
    b_.CreateGetCurrentComm(buf, builtin.type.size);
    expr_ = buf;
  }
  else if (!builtin.ident.compare(0, 3, "arg") && builtin.ident.size() == 4 &&
      builtin.ident.at(3) >= '0' && builtin.ident.at(3) <= '9' ||
      builtin.ident == "retval" ||
      builtin.ident == "func")
  {
    int offset;
    if (builtin.ident == "retval")
      offset = arch::ret_offset();
    else if (builtin.ident == "func")
      offset = arch::pc_offset();
    else // argX
    {
      int arg_num = atoi(builtin.ident.substr(3).c_str());
      offset = arch::arg_offset(arg_num);
    }

    AllocaInst *dst = b_.CreateAllocaBPF(builtin.type, builtin.ident);
    Value *src = b_.CreateGEP(ctx_, b_.getInt64(offset * sizeof(uintptr_t)));
    b_.CreateProbeRead(dst, builtin.type.size, src);
    expr_ = b_.CreateLoad(dst);
    b_.CreateLifetimeEnd(dst);
  }
  else if (builtin.ident == "name")
  {
    static int name_id = 0;
    bpftrace_.name_ids_.push_back(probefull_);
    builtin.name_id = name_id;
    name_id++;
    expr_ = b_.getInt64(builtin.name_id);
  }
  else
  {
    abort();
  }
}

void CodegenLLVM::visit(Call &call)
{
  if (call.func == "count")
  {
    Map &map = *call.map;
    AllocaInst *key = getMapKey(map);
    Value *oldval = b_.CreateMapLookupElem(map, key);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");
    b_.CreateStore(b_.CreateAdd(oldval, b_.getInt64(1)), newval);
    b_.CreateMapUpdateElem(map, key, newval);

    // oldval can only be an integer so won't be in memory and doesn't need lifetime end
    b_.CreateLifetimeEnd(key);
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "sum")
  {
    Map &map = *call.map;
    AllocaInst *key = getMapKey(map);
    Value *oldval = b_.CreateMapLookupElem(map, key);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");

    call.vargs->front()->accept(*this);
    b_.CreateStore(b_.CreateAdd(expr_, oldval), newval);
    b_.CreateMapUpdateElem(map, key, newval);

    // oldval can only be an integer so won't be in memory and doesn't need lifetime end
    b_.CreateLifetimeEnd(key);
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "min")
  {
    Map &map = *call.map;
    AllocaInst *key = getMapKey(map);
    Value *oldval = b_.CreateMapLookupElem(map, key);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");

    // Store the max of (0xffffffff - val), so that our SGE comparison with uninitialized
    // elements will always store on the first occurrance. Revent this later when printing.
    Function *parent = b_.GetInsertBlock()->getParent();
    call.vargs->front()->accept(*this);
    Value *inverted = b_.CreateSub(b_.getInt64(0xffffffff), expr_);
    BasicBlock *lt = BasicBlock::Create(module_->getContext(), "min.lt", parent);
    BasicBlock *ge = BasicBlock::Create(module_->getContext(), "min.ge", parent);
    b_.CreateCondBr(b_.CreateICmpSGE(inverted, oldval), ge, lt);

    b_.SetInsertPoint(ge);
    b_.CreateStore(inverted, newval);
    b_.CreateMapUpdateElem(map, key, newval);
    b_.CreateBr(lt);

    b_.SetInsertPoint(lt);
    b_.CreateLifetimeEnd(key);
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "max")
  {
    Map &map = *call.map;
    AllocaInst *key = getMapKey(map);
    Value *oldval = b_.CreateMapLookupElem(map, key);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");

    Function *parent = b_.GetInsertBlock()->getParent();
    call.vargs->front()->accept(*this);
    BasicBlock *lt = BasicBlock::Create(module_->getContext(), "min.lt", parent);
    BasicBlock *ge = BasicBlock::Create(module_->getContext(), "min.ge", parent);
    b_.CreateCondBr(b_.CreateICmpSGE(expr_, oldval), ge, lt);

    b_.SetInsertPoint(ge);
    b_.CreateStore(expr_, newval);
    b_.CreateMapUpdateElem(map, key, newval);
    b_.CreateBr(lt);

    b_.SetInsertPoint(lt);
    b_.CreateLifetimeEnd(key);
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "avg" || call.func == "stats")
  {
    // avg stores the count and total in a hist map using indexes 0 and 1
    // respectively, and the calculation is made when printing.
    Map &map = *call.map;

    AllocaInst *count_key = getHistMapKey(map, b_.getInt64(0));
    Value *count_old = b_.CreateMapLookupElem(map, count_key);
    AllocaInst *count_new = b_.CreateAllocaBPF(map.type, map.ident + "_num");
    b_.CreateStore(b_.CreateAdd(count_old, b_.getInt64(1)), count_new);
    b_.CreateMapUpdateElem(map, count_key, count_new);
    b_.CreateLifetimeEnd(count_key);
    b_.CreateLifetimeEnd(count_new);

    AllocaInst *total_key = getHistMapKey(map, b_.getInt64(1));
    Value *total_old = b_.CreateMapLookupElem(map, total_key);
    AllocaInst *total_new = b_.CreateAllocaBPF(map.type, map.ident + "_val");
    call.vargs->front()->accept(*this);
    b_.CreateStore(b_.CreateAdd(expr_, total_old), total_new);
    b_.CreateMapUpdateElem(map, total_key, total_new);
    b_.CreateLifetimeEnd(total_key);
    b_.CreateLifetimeEnd(total_new);

    expr_ = nullptr;
  }
  else if (call.func == "hist")
  {
    Map &map = *call.map;
    call.vargs->front()->accept(*this);
    Function *log2_func = module_->getFunction("log2");
    Value *log2 = b_.CreateCall(log2_func, expr_, "log2");
    AllocaInst *key = getHistMapKey(map, log2);

    Value *oldval = b_.CreateMapLookupElem(map, key);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");
    b_.CreateStore(b_.CreateAdd(oldval, b_.getInt64(1)), newval);
    b_.CreateMapUpdateElem(map, key, newval);

    // oldval can only be an integer so won't be in memory and doesn't need lifetime end
    b_.CreateLifetimeEnd(key);
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "lhist")
  {
    Map &map = *call.map;
    call.vargs->front()->accept(*this);
    Function *linear_func = module_->getFunction("linear");

    // prepare arguments
    Integer &value_arg = static_cast<Integer&>(*call.vargs->at(0));
    Integer &min_arg = static_cast<Integer&>(*call.vargs->at(1));
    Integer &max_arg = static_cast<Integer&>(*call.vargs->at(2));
    Integer &step_arg = static_cast<Integer&>(*call.vargs->at(3));
    Value *value, *min, *max, *step;
    value_arg.accept(*this);
    value = expr_;
    min_arg.accept(*this);
    min = expr_;
    max_arg.accept(*this);
    max = expr_;
    step_arg.accept(*this);
    step = expr_;

    Value *linear = b_.CreateCall(linear_func, {value, min, max, step} , "linear");

    AllocaInst *key = getHistMapKey(map, linear);

    Value *oldval = b_.CreateMapLookupElem(map, key);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");
    b_.CreateStore(b_.CreateAdd(oldval, b_.getInt64(1)), newval);
    b_.CreateMapUpdateElem(map, key, newval);

    // oldval can only be an integer so won't be in memory and doesn't need lifetime end
    b_.CreateLifetimeEnd(key);
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "delete")
  {
    auto &arg = *call.vargs->at(0);
    auto &map = static_cast<Map&>(arg);
    AllocaInst *key = getMapKey(map);
    b_.CreateMapDeleteElem(map, key);
    b_.CreateLifetimeEnd(key);
    expr_ = nullptr;
  }
  else if (call.func == "str")
  {
    AllocaInst *buf = b_.CreateAllocaBPF(call.type, "str");
    b_.CreateMemSet(buf, b_.getInt8(0), call.type.size, 1);
    call.vargs->front()->accept(*this);
    b_.CreateProbeReadStr(buf, call.type.size, expr_);
    expr_ = buf;
  }
  else if (call.func == "join")
  {
    call.vargs->front()->accept(*this);
    AllocaInst *first = b_.CreateAllocaBPF(SizedType(Type::integer, 8), call.func + "_first");
    AllocaInst *second = b_.CreateAllocaBPF(b_.getInt64Ty(), call.func+"_second");
    Value *perfdata = b_.CreateGetJoinMap(ctx_);
    Function *parent = b_.GetInsertBlock()->getParent();
    BasicBlock *zero = BasicBlock::Create(module_->getContext(), "joinzero", parent);
    BasicBlock *notzero = BasicBlock::Create(module_->getContext(), "joinnotzero", parent);
    b_.CreateCondBr(b_.CreateICmpNE(perfdata, ConstantExpr::getCast(Instruction::IntToPtr, b_.getInt64(0), b_.getInt8PtrTy()), "joinzerocond"), notzero, zero);

    // arg0
    b_.SetInsertPoint(notzero);
    b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::join)), perfdata);
    AllocaInst *arr = b_.CreateAllocaBPF(b_.getInt64Ty(), call.func+"_r0");
    b_.CreateProbeRead(arr, 8, expr_);
    b_.CreateProbeReadStr(b_.CreateAdd(perfdata, b_.getInt64(8)), bpftrace_.join_argsize_, b_.CreateLoad(arr));

    for (int i = 1; i < bpftrace_.join_argnum_; i++) {
      // argi
      b_.CreateStore(b_.CreateAdd(expr_, b_.getInt64(8 * i)), first);
      b_.CreateProbeRead(second, 8, b_.CreateLoad(first));
      b_.CreateProbeReadStr(b_.CreateAdd(perfdata, b_.getInt64(8 + i * bpftrace_.join_argsize_)), bpftrace_.join_argsize_, b_.CreateLoad(second));
    }

    // emit
    b_.CreatePerfEventOutput(ctx_, perfdata, 8 + bpftrace_.join_argnum_ * bpftrace_.join_argsize_);

    b_.CreateBr(zero);

    // done
    b_.SetInsertPoint(zero);
    expr_ = nullptr;
  }
  else if (call.func == "sym")
  {
    // We want expr_ to just pass through from the child node - don't set it here
    call.vargs->front()->accept(*this);
  }
  else if (call.func == "usym")
  {
    // store uint64_t[2] with: [0]: (uint64_t)addr, [1]: (uint64_t)pid
    AllocaInst *buf = b_.CreateAllocaBPF(call.type, "usym");
    b_.CreateMemSet(buf, b_.getInt8(0), call.type.size, 1);
    Value *pid = b_.CreateLShr(b_.CreateGetPidTgid(), 32);
    Value *addr_offset = b_.CreateGEP(buf, b_.getInt64(0));
    Value *pid_offset = b_.CreateGEP(buf, {b_.getInt64(0), b_.getInt64(8)});
    call.vargs->front()->accept(*this);
    b_.CreateStore(expr_, addr_offset);
    b_.CreateStore(pid, pid_offset);
    expr_ = buf;
  }
  else if (call.func == "reg")
  {
    auto &reg_name = static_cast<String&>(*call.vargs->at(0)).str;
    int offset = arch::offset(reg_name);
    if (offset == -1)
      abort();

    AllocaInst *dst = b_.CreateAllocaBPF(call.type, call.func+"_"+reg_name);
    Value *src = b_.CreateGEP(ctx_, b_.getInt64(offset * sizeof(uintptr_t)));
    b_.CreateProbeRead(dst, 8, src);
    expr_ = b_.CreateLoad(dst);
    b_.CreateLifetimeEnd(dst);
  }
  else if (call.func == "printf")
  {
    /*
     * perf event output has: uint64_t printf_id, vargs
     * The printf_id maps to bpftrace_.printf_args_, and is a way to define the
     * types and offsets of each of the arguments, and share that between BPF and
     * user-space for printing.
     */
    ArrayType *string_type = ArrayType::get(b_.getInt8Ty(), STRING_SIZE);
    StructType *printf_struct = StructType::create(module_->getContext(), "printf_t");
    std::vector<llvm::Type *> elements = { b_.getInt64Ty() }; // printf ID
    String &fmt = static_cast<String&>(*call.vargs->at(0));

    static int printf_id = 0;
    auto args = std::get<1>(bpftrace_.printf_args_.at(printf_id));
    for (SizedType t : args)
    {
      llvm::Type *ty = b_.GetType(t);
      elements.push_back(ty);
    }
    printf_struct->setBody(elements);
    int struct_size = layout_.getTypeAllocSize(printf_struct);

    AllocaInst *printf_args = b_.CreateAllocaBPF(printf_struct, "printf_args");

    b_.CreateStore(b_.getInt64(printf_id), printf_args);
    for (int i=1; i<call.vargs->size(); i++)
    {
      Expression &arg = *call.vargs->at(i);
      arg.accept(*this);
      Value *offset = b_.CreateGEP(printf_args, {b_.getInt32(0), b_.getInt32(i)});
      if (arg.type.type == Type::string || arg.type.type == Type::usym)
        b_.CreateMemCpy(offset, expr_, arg.type.size, 1);
      else
        b_.CreateStore(expr_, offset);
    }

    printf_id++;
    b_.CreatePerfEventOutput(ctx_, printf_args, struct_size);
    b_.CreateLifetimeEnd(printf_args);
    expr_ = nullptr;
  }
  else if (call.func == "exit")
  {
    /*
     * perf event output has: uint64_t asyncaction_id
     * The asyncaction_id informs user-space that this is not a printf(), but is a
     * special asynchronous action. The ID maps to exit().
     */
    ArrayType *perfdata_type = ArrayType::get(b_.getInt8Ty(), sizeof(uint64_t));
    AllocaInst *perfdata = b_.CreateAllocaBPF(perfdata_type, "perfdata");
    b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::exit)), perfdata);
    b_.CreatePerfEventOutput(ctx_, perfdata, sizeof(uint64_t));
    b_.CreateLifetimeEnd(perfdata);
    expr_ = nullptr;
  }
  else if (call.func == "print")
  {
    /*
     * perf event output has: uint64_t asyncaction_id, uint64_t top, uint64_t div, string map_ident
     * The asyncaction_id informs user-space that this is not a printf(), but is a
     * special asynchronous action. The ID maps to print(). The top argument is either
     * a value for truncation, or 0 for everything. The div argument divides the output values
     * by this (eg: for use in nanosecond -> millisecond conversions).
     * TODO: consider stashing top & div in a printf_args_ like struct, so we don't need to pass
     * them here via the perfdata output (which is a little more wasteful than need be: I'm using
     * uint64_t's to avoid "misaligned stack access off" errors when juggling uint32_t's).
     */
    auto &arg = *call.vargs->at(0);
    auto &map = static_cast<Map&>(arg);
    Constant *const_str = ConstantDataArray::getString(module_->getContext(), map.ident, true);
    AllocaInst *str_buf = b_.CreateAllocaBPF(ArrayType::get(b_.getInt8Ty(), map.ident.length()), "str");
    b_.CreateStore(b_.CreateGEP(const_str, b_.getInt64(0)), str_buf);
    ArrayType *perfdata_type = ArrayType::get(b_.getInt8Ty(), sizeof(uint64_t) + 2 * sizeof(uint64_t) + map.ident.length());
    AllocaInst *perfdata = b_.CreateAllocaBPF(perfdata_type, "perfdata");

    // store asyncactionid:
    b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::print)), perfdata);

    // store top:
    if (call.vargs->size() > 1)
    {
      Integer &top_arg = static_cast<Integer&>(*call.vargs->at(1));
      Value *top;
      top_arg.accept(*this);
      top = expr_;
      b_.CreateStore(top, b_.CreateGEP(perfdata, {b_.getInt32(0), b_.getInt32(sizeof(uint64_t))}));
    }
    else
      b_.CreateStore(b_.getInt64(0), b_.CreateGEP(perfdata, {b_.getInt64(0), b_.getInt64(sizeof(uint64_t))}));

    // store top:
    if (call.vargs->size() > 2)
    {
      Integer &div_arg = static_cast<Integer&>(*call.vargs->at(2));
      Value *div;
      div_arg.accept(*this);
      div = expr_;
      b_.CreateStore(div, b_.CreateGEP(perfdata, {b_.getInt64(0), b_.getInt64(sizeof(uint64_t) + sizeof(uint64_t))}));
    }
    else
      b_.CreateStore(b_.getInt64(0), b_.CreateGEP(perfdata, {b_.getInt64(0), b_.getInt64(sizeof(uint64_t) + sizeof(uint64_t))}));

    // store map ident:
    b_.CreateMemCpy(b_.CreateGEP(perfdata, {b_.getInt64(0), b_.getInt64(sizeof(uint64_t) + 2 * sizeof(uint64_t))}), str_buf, map.ident.length(), 1);
    b_.CreatePerfEventOutput(ctx_, perfdata, sizeof(uint64_t) + 2 * sizeof(uint64_t) + map.ident.length());
    b_.CreateLifetimeEnd(perfdata);
    expr_ = nullptr;
  }
  else if (call.func == "clear" || call.func == "zero")
  {
    auto &arg = *call.vargs->at(0);
    auto &map = static_cast<Map&>(arg);
    Constant *const_str = ConstantDataArray::getString(module_->getContext(), map.ident, true);
    AllocaInst *str_buf = b_.CreateAllocaBPF(ArrayType::get(b_.getInt8Ty(), map.ident.length()), "str");
    b_.CreateStore(b_.CreateGEP(const_str, b_.getInt64(0)), str_buf);
    ArrayType *perfdata_type = ArrayType::get(b_.getInt8Ty(), sizeof(uint64_t) + map.ident.length());
    AllocaInst *perfdata = b_.CreateAllocaBPF(perfdata_type, "perfdata");
    if (call.func == "clear")
      b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::clear)), perfdata);
    else
      b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::zero)), perfdata);
    b_.CreateMemCpy(b_.CreateGEP(perfdata, {b_.getInt64(0), b_.getInt64(sizeof(uint64_t))}), str_buf, map.ident.length(), 1);
    b_.CreatePerfEventOutput(ctx_, perfdata, sizeof(uint64_t) + map.ident.length());
    b_.CreateLifetimeEnd(perfdata);
    expr_ = nullptr;
  }
  else if (call.func == "time")
  {
    ArrayType *perfdata_type = ArrayType::get(b_.getInt8Ty(), sizeof(uint64_t) * 2);
    AllocaInst *perfdata = b_.CreateAllocaBPF(perfdata_type, "perfdata");
    b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::time)), perfdata);
    static int time_id = 0;
    b_.CreateStore(b_.getInt64(time_id), b_.CreateGEP(perfdata, {b_.getInt64(0), b_.getInt64(sizeof(uint64_t))}));

    time_id++;
    b_.CreatePerfEventOutput(ctx_, perfdata, sizeof(uint64_t) * 2);
    b_.CreateLifetimeEnd(perfdata);
    expr_ = nullptr;
  }

  else
  {
    std::cerr << "Error: missing codegen for function \"" << call.func << "\"" << std::endl;
    abort();
  }
}

void CodegenLLVM::visit(Map &map)
{
  AllocaInst *key = getMapKey(map);
  expr_ = b_.CreateMapLookupElem(map, key);
  b_.CreateLifetimeEnd(key);
}

void CodegenLLVM::visit(Variable &var)
{
  expr_ = variables_[var.ident];
}

void CodegenLLVM::visit(Binop &binop)
{
  // Handle && and || separately so short circuiting works
  if (binop.op == bpftrace::Parser::token::LAND)
  {
    expr_ = createLogicalAnd(binop);
    return;
  }
  else if (binop.op == bpftrace::Parser::token::LOR)
  {
    expr_ = createLogicalOr(binop);
    return;
  }

  Value *lhs, *rhs;
  binop.left->accept(*this);
  lhs = expr_;
  binop.right->accept(*this);
  rhs = expr_;

  Type &type = binop.left->type.type;
  if (type == Type::string)
  {
    Function *strcmp_func = module_->getFunction("strcmp");
    switch (binop.op) {
      case bpftrace::Parser::token::EQ:
        expr_ = b_.CreateCall(strcmp_func, {lhs, rhs}, "strcmp");
        break;
      case bpftrace::Parser::token::NE:
        expr_ = b_.CreateNot(b_.CreateCall(strcmp_func, {lhs, rhs}, "strcmp"));
        break;
      default:
        abort();
    }
    if (!binop.left->is_variable)
      b_.CreateLifetimeEnd(lhs);
    if (!binop.right->is_variable)
      b_.CreateLifetimeEnd(rhs);
  }
  else
  {
    switch (binop.op) {
      case bpftrace::Parser::token::EQ:    expr_ = b_.CreateICmpEQ (lhs, rhs); break;
      case bpftrace::Parser::token::NE:    expr_ = b_.CreateICmpNE (lhs, rhs); break;
      case bpftrace::Parser::token::LE:    expr_ = b_.CreateICmpSLE(lhs, rhs); break;
      case bpftrace::Parser::token::GE:    expr_ = b_.CreateICmpSGE(lhs, rhs); break;
      case bpftrace::Parser::token::LT:    expr_ = b_.CreateICmpSLT(lhs, rhs); break;
      case bpftrace::Parser::token::GT:    expr_ = b_.CreateICmpSGT(lhs, rhs); break;
      case bpftrace::Parser::token::PLUS:  expr_ = b_.CreateAdd    (lhs, rhs); break;
      case bpftrace::Parser::token::MINUS: expr_ = b_.CreateSub    (lhs, rhs); break;
      case bpftrace::Parser::token::MUL:   expr_ = b_.CreateMul    (lhs, rhs); break;
      case bpftrace::Parser::token::DIV:   expr_ = b_.CreateUDiv   (lhs, rhs); break;
      case bpftrace::Parser::token::MOD:   expr_ = b_.CreateURem   (lhs, rhs); break;
      case bpftrace::Parser::token::BAND:  expr_ = b_.CreateAnd    (lhs, rhs); break;
      case bpftrace::Parser::token::BOR:   expr_ = b_.CreateOr     (lhs, rhs); break;
      case bpftrace::Parser::token::BXOR:  expr_ = b_.CreateXor    (lhs, rhs); break;
      case bpftrace::Parser::token::LAND:  abort(); // Handled earlier
      case bpftrace::Parser::token::LOR:   abort(); // Handled earlier
      default: abort();
    }
  }
  expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), false);
}

void CodegenLLVM::visit(Unop &unop)
{
  assert(unop.expr->type.type == Type::integer);
  unop.expr->accept(*this);

  switch (unop.op) {
    case bpftrace::Parser::token::LNOT: expr_ = b_.CreateNot(expr_); break;
    case bpftrace::Parser::token::BNOT: expr_ = b_.CreateNeg(expr_); break;
    case bpftrace::Parser::token::MUL:
    {
      AllocaInst *dst = b_.CreateAllocaBPF(unop.expr->type, "deref");
      b_.CreateProbeRead(dst, unop.expr->type.size, expr_);
      expr_ = b_.CreateLoad(dst);
      b_.CreateLifetimeEnd(dst);
      break;
    }
    default: abort();
  }
}

void CodegenLLVM::visit(Ternary &ternary)
{
  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *left_block = BasicBlock::Create(module_->getContext(), "left", parent);
  BasicBlock *right_block = BasicBlock::Create(module_->getContext(), "right", parent);
  BasicBlock *done = BasicBlock::Create(module_->getContext(), "done", parent);

  // ordering of all the following statements is important
  Value *result = b_.CreateAllocaBPF(ternary.type, "result");
  AllocaInst *buf = b_.CreateAllocaBPF(ternary.type, "buf");
  Value *cond;
  ternary.cond->accept(*this);
  cond = expr_;
  b_.CreateCondBr(b_.CreateICmpNE(cond, b_.getInt64(0), "true_cond"),
                  left_block, right_block);

  if (ternary.type.type == Type::integer) {
    // fetch selected integer via CreateStore
    b_.SetInsertPoint(left_block);
    ternary.left->accept(*this);
    b_.CreateStore(expr_, result);
    b_.CreateBr(done);

    b_.SetInsertPoint(right_block);
    ternary.right->accept(*this);
    b_.CreateStore(expr_, result);
    b_.CreateBr(done);

    b_.SetInsertPoint(done);
    expr_ = b_.CreateLoad(result);
  } else {
    // copy selected string via CreateMemCpy
    b_.SetInsertPoint(left_block);
    ternary.left->accept(*this);
    b_.CreateMemCpy(buf, expr_, ternary.type.size, 1);
    b_.CreateBr(done);

    b_.SetInsertPoint(right_block);
    ternary.right->accept(*this);
    b_.CreateMemCpy(buf, expr_, ternary.type.size, 1);
    b_.CreateBr(done);

    b_.SetInsertPoint(done);
    expr_ = buf;
  }
}

void CodegenLLVM::visit(FieldAccess &acc)
{
  // TODO
}

void CodegenLLVM::visit(Cast &cast)
{
  // TODO
}

void CodegenLLVM::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void CodegenLLVM::visit(AssignMapStatement &assignment)
{
  Map &map = *assignment.map;

  assignment.expr->accept(*this);

  if (!expr_) // Some functions do the assignments themselves
    return;

  Value *val, *expr;
  expr = expr_;
  AllocaInst *key = getMapKey(map);
  if (assignment.expr->type.type == Type::string)
  {
    val = expr;
  }
  else
  {
    val = b_.CreateAllocaBPF(map.type, map.ident + "_val");
    b_.CreateStore(expr, val);
  }
  b_.CreateMapUpdateElem(map, key, val);
  b_.CreateLifetimeEnd(key);
  if (!assignment.expr->is_variable)
    b_.CreateLifetimeEnd(val);
}

void CodegenLLVM::visit(AssignVarStatement &assignment)
{
  Variable &var = *assignment.var;

  assignment.expr->accept(*this);
  variables_[var.ident] = expr_;
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

  expr_ = b_.CreateICmpEQ(expr_, b_.getInt64(0), "predcond");

  b_.CreateCondBr(expr_, pred_false_block, pred_true_block);
  b_.SetInsertPoint(pred_false_block);
  b_.CreateRet(ConstantInt::get(module_->getContext(), APInt(64, 0)));

  b_.SetInsertPoint(pred_true_block);
}

void CodegenLLVM::visit(AttachPoint &)
{
  // Empty
}

void CodegenLLVM::visit(Probe &probe)
{
  FunctionType *func_type = FunctionType::get(
      b_.getInt64Ty(),
      {b_.getInt8PtrTy()}, // struct pt_regs *ctx
      false);

  /*
   * Most of the time, we can take a probe like kprobe:do_f* and build a
   * single BPF program for that, called "s_kprobe:do_f*", and attach it to
   * each wildcard match. An exception is the "name" builtin, where we need
   * to build different BPF programs for each wildcard match that cantains an
   * ID for the match. Those programs will be called "s_kprobe:do_fcntl" etc.
   */
  if (probe.need_expansion == false) {
    // build a single BPF program pre-wildcards
    Function *func = Function::Create(func_type, Function::ExternalLinkage, probe.name(), module_.get());
    func->setSection("s_" + probe.name());
    BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", func);
    b_.SetInsertPoint(entry);

    ctx_ = func->arg_begin();

    if (probe.pred) {
      probe.pred->accept(*this);
    }
    for (Statement *stmt : *probe.stmts) {
      stmt->accept(*this);
    }

    b_.CreateRet(ConstantInt::get(module_->getContext(), APInt(64, 0)));

  } else {
    // build a separate BPF programs for each wildcard match
    for (auto &attach_point : *probe.attach_points) {
      std::string file_name;
      switch (probetype(attach_point->provider))
      {
        case ProbeType::kprobe:
        case ProbeType::kretprobe:
          file_name = "/sys/kernel/debug/tracing/available_filter_functions";
          break;
        case ProbeType::tracepoint:
          file_name = "/sys/kernel/debug/tracing/available_events";
          break;
        default:
          std::cerr << "Wildcard matches aren't available on probe type '"
                    << attach_point->provider << "'" << std::endl;
          return;
      }
      auto matches = bpftrace_.find_wildcard_matches(attach_point->target, attach_point->func, file_name);
      for (auto &match : matches) {
        probefull_ = attach_point->name(match);
        Function *func = Function::Create(func_type, Function::ExternalLinkage, attach_point->name(match), module_.get());
        func->setSection("s_" + attach_point->name(match));
        BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", func);
        b_.SetInsertPoint(entry);

        // check: do the following 8 lines need to be in the wildcard loop?
        ctx_ = func->arg_begin();
        if (probe.pred) {
          probe.pred->accept(*this);
        }
        for (Statement *stmt : *probe.stmts) {
          stmt->accept(*this);
        }
        b_.CreateRet(ConstantInt::get(module_->getContext(), APInt(64, 0)));
      }
    }
  }
}

void CodegenLLVM::visit(Include &include)
{
}

void CodegenLLVM::visit(Program &program)
{
  for (Include *include : *program.includes)
    include->accept(*this);
  for (Probe *probe : *program.probes)
    probe->accept(*this);
}

AllocaInst *CodegenLLVM::getMapKey(Map &map)
{
  AllocaInst *key;
  if (map.vargs) {
    size_t size = 0;
    for (Expression *expr : *map.vargs)
    {
      size += expr->type.size;
    }
    key = b_.CreateAllocaMapKey(size, map.ident + "_key");

    int offset = 0;
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
      Value *offset_val = b_.CreateGEP(key, {b_.getInt64(0), b_.getInt64(offset)});
      if (expr->type.type == Type::string || expr->type.type == Type::usym)
        b_.CreateMemCpy(offset_val, expr_, expr->type.size, 1);
      else
        b_.CreateStore(expr_, offset_val);
      offset += expr->type.size;
    }
  }
  else
  {
    key = b_.CreateAllocaBPF(SizedType(Type::integer, 8), map.ident + "_key");
    b_.CreateStore(b_.getInt64(0), key);
  }
  return key;
}

AllocaInst *CodegenLLVM::getHistMapKey(Map &map, Value *log2)
{
  AllocaInst *key;
  if (map.vargs) {
    size_t size = 8; // Extra space for the bucket value
    for (Expression *expr : *map.vargs)
    {
      size += expr->type.size;
    }
    key = b_.CreateAllocaMapKey(size, map.ident + "_key");

    int offset = 0;
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
      Value *offset_val = b_.CreateGEP(key, {b_.getInt64(0), b_.getInt64(offset)});
      if (expr->type.type == Type::string || expr->type.type == Type::usym)
        b_.CreateMemCpy(offset_val, expr_, expr->type.size, 1);
      else
        b_.CreateStore(expr_, offset_val);
      offset += expr->type.size;
    }
    Value *offset_val = b_.CreateGEP(key, {b_.getInt64(0), b_.getInt64(offset)});
    b_.CreateStore(log2, offset_val);
  }
  else
  {
    key = b_.CreateAllocaBPF(SizedType(Type::integer, 8), map.ident + "_key");
    b_.CreateStore(log2, key);
  }
  return key;
}

Value *CodegenLLVM::createLogicalAnd(Binop &binop)
{
  assert(binop.left->type.type == Type::integer);
  assert(binop.right->type.type == Type::integer);

  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *lhs_true_block = BasicBlock::Create(module_->getContext(), "&&_lhs_true", parent);
  BasicBlock *true_block = BasicBlock::Create(module_->getContext(), "&&_true", parent);
  BasicBlock *false_block = BasicBlock::Create(module_->getContext(), "&&_false", parent);
  BasicBlock *merge_block = BasicBlock::Create(module_->getContext(), "&&_merge", parent);

  Value *result = b_.CreateAllocaBPF(b_.getInt64Ty(), "&&_result");
  Value *lhs;
  binop.left->accept(*this);
  lhs = expr_;
  b_.CreateCondBr(b_.CreateICmpNE(lhs, b_.getInt64(0), "lhs_true_cond"),
                  lhs_true_block,
                  false_block);

  b_.SetInsertPoint(lhs_true_block);
  Value *rhs;
  binop.right->accept(*this);
  rhs = expr_;
  b_.CreateCondBr(b_.CreateICmpNE(rhs, b_.getInt64(0), "rhs_true_cond"),
                  true_block,
                  false_block);

  b_.SetInsertPoint(true_block);
  b_.CreateStore(b_.getInt64(1), result);
  b_.CreateBr(merge_block);

  b_.SetInsertPoint(false_block);
  b_.CreateStore(b_.getInt64(0), result);
  b_.CreateBr(merge_block);

  b_.SetInsertPoint(merge_block);
  return b_.CreateLoad(result);
}

Value *CodegenLLVM::createLogicalOr(Binop &binop)
{
  assert(binop.left->type.type == Type::integer);
  assert(binop.right->type.type == Type::integer);

  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *lhs_false_block = BasicBlock::Create(module_->getContext(), "||_lhs_false", parent);
  BasicBlock *false_block = BasicBlock::Create(module_->getContext(), "||_false", parent);
  BasicBlock *true_block = BasicBlock::Create(module_->getContext(), "||_true", parent);
  BasicBlock *merge_block = BasicBlock::Create(module_->getContext(), "||_merge", parent);

  Value *result = b_.CreateAllocaBPF(b_.getInt64Ty(), "||_result");
  Value *lhs;
  binop.left->accept(*this);
  lhs = expr_;
  b_.CreateCondBr(b_.CreateICmpNE(lhs, b_.getInt64(0), "lhs_true_cond"),
                  true_block,
                  lhs_false_block);

  b_.SetInsertPoint(lhs_false_block);
  Value *rhs;
  binop.right->accept(*this);
  rhs = expr_;
  b_.CreateCondBr(b_.CreateICmpNE(rhs, b_.getInt64(0), "rhs_true_cond"),
                  true_block,
                  false_block);

  b_.SetInsertPoint(false_block);
  b_.CreateStore(b_.getInt64(0), result);
  b_.CreateBr(merge_block);

  b_.SetInsertPoint(true_block);
  b_.CreateStore(b_.getInt64(1), result);
  b_.CreateBr(merge_block);

  b_.SetInsertPoint(merge_block);
  return b_.CreateLoad(result);
}

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
  log2_func->addFnAttr(Attribute::AlwaysInline);
  log2_func->setSection("helpers");
  BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", log2_func);
  b_.SetInsertPoint(entry);

  Value *arg = log2_func->arg_begin();

  Value *n_alloc = b_.CreateAllocaBPF(SizedType(Type::integer, 8));
  b_.CreateStore(arg, n_alloc);

  Value *result = b_.CreateAllocaBPF(SizedType(Type::integer, 8));
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

void CodegenLLVM::createLinearFunction()
{
  // lhist() returns a bucket index for the given value. The first and last
  //   bucket indexes are special: they are 0 for the less-than-range
  //   bucket, and index max_bucket+2 for the greater-than-range bucket.
  //   Indexes 1 to max_bucket+1 span the buckets in the range.
  //
  // int lhist(int value, int min, int max, int step)
  // {
  // 	int result;
  //
  // 	if (value < min)
  // 		return 0;
  // 	if (value > max)
  // 		return 1 + (max - min) / step;
  // 	result = 1 + (value - min) / step;
  //
  // 	return result;
  // }

  // inlined function initialization
  FunctionType *linear_func_type = FunctionType::get(b_.getInt64Ty(), {b_.getInt64Ty(), b_.getInt64Ty(), b_.getInt64Ty(), b_.getInt64Ty()}, false);
  Function *linear_func = Function::Create(linear_func_type, Function::InternalLinkage, "linear", module_.get());
  linear_func->addFnAttr(Attribute::AlwaysInline);
  linear_func->setSection("helpers");
  BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", linear_func);
  b_.SetInsertPoint(entry);

  // pull in arguments
  Value *value_alloc = b_.CreateAllocaBPF(SizedType(Type::integer, 8));
  Value *min_alloc = b_.CreateAllocaBPF(SizedType(Type::integer, 8));
  Value *max_alloc = b_.CreateAllocaBPF(SizedType(Type::integer, 8));
  Value *step_alloc = b_.CreateAllocaBPF(SizedType(Type::integer, 8));
  Value *result_alloc = b_.CreateAllocaBPF(SizedType(Type::integer, 8));
  Value *value = linear_func->arg_begin()+0;
  Value *min = linear_func->arg_begin()+1;
  Value *max = linear_func->arg_begin()+2;
  Value *step = linear_func->arg_begin()+3;
  b_.CreateStore(value, value_alloc);
  b_.CreateStore(min, min_alloc);
  b_.CreateStore(max, max_alloc);
  b_.CreateStore(step, step_alloc);

  // algorithm
  Value *cmp = b_.CreateICmpSLT(b_.CreateLoad(value_alloc), b_.CreateLoad(min_alloc));
  BasicBlock *lt_min = BasicBlock::Create(module_->getContext(), "lhist.lt_min", linear_func);
  BasicBlock *ge_min = BasicBlock::Create(module_->getContext(), "lhist.ge_min", linear_func);
  b_.CreateCondBr(cmp, lt_min, ge_min);

  b_.SetInsertPoint(lt_min);
  b_.CreateRet(b_.getInt64(0));

  b_.SetInsertPoint(ge_min);
  Value *cmp1 = b_.CreateICmpSGT(b_.CreateLoad(value_alloc), b_.CreateLoad(max_alloc));
  BasicBlock *le_max = BasicBlock::Create(module_->getContext(), "lhist.le_max", linear_func);
  BasicBlock *gt_max = BasicBlock::Create(module_->getContext(), "lhist.gt_max", linear_func);
  b_.CreateCondBr(cmp1, gt_max, le_max);

  b_.SetInsertPoint(gt_max);
  Value *div = b_.CreateSDiv(b_.CreateSub(b_.CreateLoad(max_alloc), b_.CreateLoad(min_alloc)), b_.CreateLoad(step_alloc));
  b_.CreateStore(b_.CreateAdd(div, b_.getInt64(1)), result_alloc);
  b_.CreateRet(b_.CreateLoad(result_alloc));

  b_.SetInsertPoint(le_max);
  Value *div3 = b_.CreateSDiv(b_.CreateSub(b_.CreateLoad(value_alloc), b_.CreateLoad(min_alloc)), b_.CreateLoad(step_alloc));
  b_.CreateStore(b_.CreateAdd(div3, b_.getInt64(1)), result_alloc);
  b_.CreateRet(b_.CreateLoad(result_alloc));
}

void CodegenLLVM::createStrcmpFunction()
{
  // Returns 1 if strings match, 0 otherwise
  // i1 strcmp(const char *s1, const char *s2)
  // {
  //   for (int i=0; i<STRING_SIZE; i++)
  //   {
  //     if (s1[i] != s2[i]) return 0;
  //   }
  //   return 1;
  // }

  FunctionType *strcmp_func_type = FunctionType::get(b_.getInt1Ty(), {b_.getInt8PtrTy(), b_.getInt8PtrTy()}, false);
  Function *strcmp_func = Function::Create(strcmp_func_type, Function::InternalLinkage, "strcmp", module_.get());
  strcmp_func->addFnAttr(Attribute::AlwaysInline);
  strcmp_func->setSection("helpers");
  BasicBlock *entry = BasicBlock::Create(module_->getContext(), "strcmp.entry", strcmp_func);
  BasicBlock *not_equal_block = BasicBlock::Create(module_->getContext(), "strcmp.not_equal", strcmp_func);
  b_.SetInsertPoint(entry);

  Value *s1 = strcmp_func->arg_begin();
  Value *s2 = strcmp_func->arg_begin()+1;

  for (int i=0; i<STRING_SIZE; i++)
  {
    Value *s1_char = b_.CreateGEP(s1, {b_.getInt64(i)});
    Value *s2_char = b_.CreateGEP(s2, {b_.getInt64(i)});

    BasicBlock *continue_block = BasicBlock::Create(module_->getContext(), "strcmp.continue", strcmp_func);

    Value *cmp = b_.CreateICmpNE(b_.CreateLoad(s1_char), b_.CreateLoad(s2_char));
    b_.CreateCondBr(cmp, not_equal_block, continue_block);

    b_.SetInsertPoint(continue_block);
  }
  b_.CreateRet(b_.getInt1(1));

  b_.SetInsertPoint(not_equal_block);
  b_.CreateRet(b_.getInt1(0));
}

std::unique_ptr<BpfOrc> CodegenLLVM::compile(bool debug, std::ostream &out)
{
  createLog2Function();
  createLinearFunction();
  createStrcmpFunction();
  root_->accept(*this);

  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFAsmPrinter();

  std::string targetTriple = "bpf-pc-linux";
  module_->setTargetTriple(targetTriple);

  std::string error;
  const Target *target = TargetRegistry::lookupTarget(targetTriple, error);
  if (!target)
    throw new std::runtime_error("Could not create LLVM target " + error);

  TargetOptions opt;
  auto RM = Reloc::Model();
  TargetMachine *targetMachine = target->createTargetMachine(targetTriple, "generic", "", opt, RM);
  module_->setDataLayout(targetMachine->createDataLayout());

  legacy::PassManager PM;
  PassManagerBuilder PMB;
  PMB.OptLevel = 3;
  PM.add(createFunctionInliningPass());
  /*
   * llvm < 4.0 needs
   * PM.add(createAlwaysInlinerPass());
   * llvm >= 4.0 needs
   * PM.add(createAlwaysInlinerLegacyPass());
   * use below 'stable' workaround
   */
  LLVMAddAlwaysInlinerPass(reinterpret_cast<LLVMPassManagerRef>(&PM));
  PMB.populateModulePassManager(PM);
  PM.run(*module_.get());

  if (debug)
  {
    raw_os_ostream llvm_ostream(out);
    module_->print(llvm_ostream, nullptr, false, true);
  }

  auto bpforc = std::make_unique<BpfOrc>(targetMachine);
  bpforc->compileModule(move(module_));

  return move(bpforc);
}

} // namespace ast
} // namespace bpftrace
