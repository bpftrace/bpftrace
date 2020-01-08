#include "codegen_llvm.h"
#include "arch/arch.h"
#include "ast.h"
#include "bpforc.h"
#include "parser.tab.hh"
#include "signal.h"
#include "tracepoint_format_parser.h"
#include "types.h"
#include "utils.h"
#include <algorithm>
#include <arpa/inet.h>
#include <time.h>

#include <llvm/Support/TargetRegistry.h>
#include <llvm/IR/Constants.h>
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

void CodegenLLVM::visit(PositionalParameter &param)
{
  switch (param.ptype)
  {
    case PositionalParameterType::positional:
      {
        std::string pstr = bpftrace_.get_param(param.n, param.is_in_str);
        if (is_numeric(pstr))
        {
          expr_ = b_.getInt64(std::stoll(pstr));
        }
        else
        {
          Constant *const_str = ConstantDataArray::getString(module_->getContext(), pstr, true);
          AllocaInst *buf = b_.CreateAllocaBPF(ArrayType::get(b_.getInt8Ty(), pstr.length() + 1), "str");
          b_.CreateMemSet(buf, b_.getInt8(0), pstr.length() + 1, 1);
          b_.CreateStore(const_str, buf);
          expr_ = buf;
        }
      }
      break;
    case PositionalParameterType::count:
      expr_ = b_.getInt64(bpftrace_.num_params());
      break;
    default:
      std::cerr << "unknown parameter type" << std::endl;
      abort();
      break;
  }
}

void CodegenLLVM::visit(String &string)
{
  string.str.resize(string.type.size-1);
  Constant *const_str = ConstantDataArray::getString(module_->getContext(), string.str, true);
  AllocaInst *buf = b_.CreateAllocaBPF(string.type, "str");
  b_.CreateStore(const_str, buf);
  expr_ = buf;
}

void CodegenLLVM::visit(Identifier &identifier)
{
  if (bpftrace_.enums_.count(identifier.ident) != 0)
  {
    expr_ = b_.getInt64(bpftrace_.enums_[identifier.ident]);
  }
  else
  {
    std::cerr << "unknown identifier \"" << identifier.ident << "\"" << std::endl;
    abort();
  }
}

void CodegenLLVM::visit(Builtin &builtin)
{
  if (builtin.ident == "nsecs")
  {
    expr_ = b_.CreateGetNs();
  }
  else if (builtin.ident == "elapsed")
  {
    AllocaInst *key = b_.CreateAllocaBPF(b_.getInt64Ty(), "elapsed_key");
    b_.CreateStore(b_.getInt64(0), key);

    auto &map = bpftrace_.elapsed_map_;
    auto type = SizedType(Type::integer, 8);
    auto start = b_.CreateMapLookupElem(map->mapfd_, key, type);
    expr_ = b_.CreateSub(b_.CreateGetNs(), start);
    // start won't be on stack, no need to LifeTimeEnd it
    b_.CreateLifetimeEnd(key);
  }
  else if (builtin.ident == "kstack" || builtin.ident == "ustack")
  {
    Value *stackid = b_.CreateGetStackId(ctx_, builtin.ident == "ustack", builtin.type.stack_type);
    // Kernel stacks should not be differentiated by tid, since the kernel
    // address space is the same between pids (and when aggregating you *want*
    // to be able to correlate between pids in most cases). User-space stacks
    // are special because of ASLR and so we do usym()-style packing.
    if (builtin.ident == "ustack")
    {
      // pack uint64_t with: (uint32_t)stack_id, (uint32_t)pid
      Value *pidhigh = b_.CreateShl(b_.CreateGetPidTgid(), 32);
      stackid = b_.CreateOr(stackid, pidhigh);
    }
    expr_ = stackid;
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
  else if (builtin.ident == "cgroup")
  {
    expr_ = b_.CreateGetCurrentCgroupId();
  }
  else if (builtin.ident == "uid" || builtin.ident == "gid" || builtin.ident == "username")
  {
    Value *uidgid = b_.CreateGetUidGid();
    if (builtin.ident == "uid"  || builtin.ident == "username")
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
  else if ((!builtin.ident.compare(0, 3, "arg") && builtin.ident.size() == 4 &&
      builtin.ident.at(3) >= '0' && builtin.ident.at(3) <= '9') ||
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
      if (probetype(current_attach_point_->provider) == ProbeType::usdt) {
        expr_ = b_.CreateUSDTReadArgument(ctx_, current_attach_point_,
                                          arg_num, builtin, bpftrace_.pid_);
        return;
      }
      offset = arch::arg_offset(arg_num);
    }

    expr_ = b_.CreateLoad(
        b_.getInt64Ty(),
        b_.CreateGEP(ctx_, b_.getInt64(offset * sizeof(uintptr_t))),
        builtin.ident);

    if (builtin.type.type == Type::usym)
    {
      AllocaInst *buf = b_.CreateAllocaBPF(builtin.type, "func");
      b_.CreateMemSet(buf, b_.getInt8(0), builtin.type.size, 1);
      Value *pid = b_.CreateLShr(b_.CreateGetPidTgid(), 32);
      Value *addr_offset = b_.CreateGEP(buf, b_.getInt64(0));
      Value *pid_offset = b_.CreateGEP(buf, {b_.getInt64(0), b_.getInt64(8)});
      b_.CreateStore(expr_, addr_offset);
      b_.CreateStore(pid, pid_offset);
      expr_ = buf;
    }
  }
  else if (!builtin.ident.compare(0, 4, "sarg") && builtin.ident.size() == 5 &&
      builtin.ident.at(4) >= '0' && builtin.ident.at(4) <= '9')
  {
    int sp_offset = arch::offset("sp");
    if (sp_offset == -1)
    {
      std::cerr << "negative offset for stack pointer" << std::endl;
      abort();
    }

    int arg_num = atoi(builtin.ident.substr(4).c_str());
    Value *sp = b_.CreateLoad(
        b_.getInt64Ty(),
        b_.CreateGEP(ctx_, b_.getInt64(sp_offset * sizeof(uintptr_t))),
        "reg_sp");
    AllocaInst *dst = b_.CreateAllocaBPF(builtin.type, builtin.ident);
    Value *src = b_.CreateAdd(sp, b_.getInt64((arg_num + 1) * sizeof(uintptr_t)));
    b_.CreateProbeRead(dst, 8, src);
    expr_ = b_.CreateLoad(dst);
    b_.CreateLifetimeEnd(dst);
  }
  else if (builtin.ident == "probe")
  {
    auto begin = bpftrace_.probe_ids_.begin();
    auto end = bpftrace_.probe_ids_.end();
    auto found = std::find(begin, end, probefull_);
    if (found == end) {
      bpftrace_.probe_ids_.push_back(probefull_);
      builtin.probe_id = bpftrace_.next_probe_id();
    } else {
      builtin.probe_id = std::distance(begin, found);
    }
    expr_ = b_.getInt64(builtin.probe_id);
  }
  else if (builtin.ident == "args")
  {
    expr_ = ctx_;
  }
  else if (builtin.ident == "cpid")
  {
    pid_t cpid = bpftrace_.child_pid();
    if (cpid < 1) {
      std::cerr << "BUG: Invalid cpid: " << cpid << std::endl;
      abort();
    }
    expr_ = b_.getInt32(cpid);
  }
  else if (builtin.ident == "ctx")
  {
    // undocumented builtin: for debugging
    expr_ = ctx_;
  }
  else
  {
    std::cerr << "unknown builtin \"" << builtin.ident << "\"" << std::endl;
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
    // promote int to 64-bit
    expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), call.vargs->front()->type.is_signed);
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
    // elements will always store on the first occurrence. Revent this later when printing.
    Function *parent = b_.GetInsertBlock()->getParent();
    call.vargs->front()->accept(*this);
    // promote int to 64-bit
    expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), call.vargs->front()->type.is_signed);
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
    // promote int to 64-bit
    expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), call.vargs->front()->type.is_signed);
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
    // promote int to 64-bit
    expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), call.vargs->front()->type.is_signed);
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
    // promote int to 64-bit
    expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), call.vargs->front()->type.is_signed);
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

    // promote int to 64-bit
    value = b_.CreateIntCast(value, b_.getInt64Ty(), call.vargs->front()->type.is_signed);
    min = b_.CreateIntCast(min, b_.getInt64Ty(), false);
    max = b_.CreateIntCast(max, b_.getInt64Ty(), false);
    step = b_.CreateIntCast(step, b_.getInt64Ty(), false);

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
    AllocaInst *strlen = b_.CreateAllocaBPF(b_.getInt64Ty(), "strlen");
    b_.CreateMemSet(strlen, b_.getInt8(0), sizeof(uint64_t), 1);
    if (call.vargs->size() > 1) {
      call.vargs->at(1)->accept(*this);
      Value *proposed_strlen = b_.CreateAdd(expr_, b_.getInt64(1)); // add 1 to accommodate probe_read_str's null byte

      // largest read we'll allow = our global string buffer size
      Value *max = b_.getInt64(bpftrace_.strlen_);
      // integer comparison: unsigned less-than-or-equal-to
      CmpInst::Predicate P = CmpInst::ICMP_ULE;
      // check whether proposed_strlen is less-than-or-equal-to maximum
      Value *Cmp = b_.CreateICmp(P, proposed_strlen, max, "str.min.cmp");
      // select proposed_strlen if it's sufficiently low, otherwise choose maximum
      Value *Select = b_.CreateSelect(Cmp, proposed_strlen, max, "str.min.select");
      b_.CreateStore(Select, strlen);
    } else {
      b_.CreateStore(b_.getInt64(bpftrace_.strlen_), strlen);
    }
    AllocaInst *buf = b_.CreateAllocaBPF(bpftrace_.strlen_, "str");
    b_.CreateMemSet(buf, b_.getInt8(0), bpftrace_.strlen_, 1);
    call.vargs->front()->accept(*this);
    b_.CreateProbeReadStr(buf, b_.CreateLoad(strlen), expr_);
    b_.CreateLifetimeEnd(strlen);

    expr_ = buf;
    expr_deleter_ = [this,buf]() { b_.CreateLifetimeEnd(buf); };
  }
  else if (call.func == "kaddr")
  {
    uint64_t addr;
    auto &name = static_cast<String&>(*call.vargs->at(0)).str;
    addr = bpftrace_.resolve_kname(name);
    expr_ = b_.getInt64(addr);
  }
  else if (call.func == "uaddr")
  {
   uint64_t addr;
    auto &name = static_cast<String&>(*call.vargs->at(0)).str;
    addr = bpftrace_.resolve_uname(name, current_attach_point_->target);
    expr_ = b_.getInt64(addr);
  }
  else if (call.func == "cgroupid")
  {
    uint64_t cgroupid;
    auto &path = static_cast<String&>(*call.vargs->at(0)).str;
    cgroupid = bpftrace_.resolve_cgroupid(path);
    expr_ = b_.getInt64(cgroupid);
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
    b_.CreateStore(b_.getInt64(join_id_), b_.CreateGEP(perfdata, {b_.getInt64(8)}));
    join_id_++;
    AllocaInst *arr = b_.CreateAllocaBPF(b_.getInt64Ty(), call.func+"_r0");
    b_.CreateProbeRead(arr, 8, expr_);
    b_.CreateProbeReadStr(b_.CreateAdd(perfdata, b_.getInt64(8+8)), bpftrace_.join_argsize_, b_.CreateLoad(arr));

    for (unsigned int i = 1; i < bpftrace_.join_argnum_; i++) {
      // argi
      b_.CreateStore(b_.CreateAdd(expr_, b_.getInt64(8 * i)), first);
      b_.CreateProbeRead(second, 8, b_.CreateLoad(first));
      b_.CreateProbeReadStr(b_.CreateAdd(perfdata, b_.getInt64(8 + 8 + i * bpftrace_.join_argsize_)), bpftrace_.join_argsize_, b_.CreateLoad(second));
    }

    // emit
    b_.CreatePerfEventOutput(ctx_, perfdata, 8 + 8 + bpftrace_.join_argnum_ * bpftrace_.join_argsize_);

    b_.CreateBr(zero);

    // done
    b_.SetInsertPoint(zero);
    expr_ = nullptr;
  }
  else if (call.func == "ksym")
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
  else if (call.func == "ntop")
  {
    // struct {
    //   int af_type;
    //   union {
    //     char[4] inet4;
    //     char[16] inet6;
    //   }
    // }
    //}
    std::vector<llvm::Type *> elements = {
      b_.getInt64Ty(), // printf ID
      ArrayType::get(b_.getInt8Ty(), 16)
    };
    StructType *inet_struct = StructType::create(elements, "inet_t", false);

    AllocaInst *buf = b_.CreateAllocaBPF(inet_struct, "inet");

    Value *af_offset = b_.CreateGEP(buf, b_.getInt64(0));
    Value *af_type;

    auto inet = call.vargs->at(0);
    if (call.vargs->size() == 1)
    {
      if (inet->type.type == Type::integer || inet->type.size == 4)
      {
        af_type = b_.getInt64(AF_INET);
      }
      else
      {
        af_type = b_.getInt64(AF_INET6);
      }
    }
    else
    {
      inet = call.vargs->at(1);
      call.vargs->at(0)->accept(*this);
      af_type = b_.CreateIntCast(expr_, b_.getInt64Ty(), true);
    }
    b_.CreateStore(af_type, af_offset);

    Value *inet_offset = b_.CreateGEP(buf, {b_.getInt32(0), b_.getInt32(1)});
    b_.CreateMemSet(inet_offset, b_.getInt8(0), 16, 1);

    inet->accept(*this);
    if (inet->type.type == Type::array)
    {
      b_.CreateProbeRead(static_cast<AllocaInst *>(inet_offset), inet->type.size, expr_);
    }
    else
    {
      b_.CreateStore(b_.CreateIntCast(expr_, b_.getInt32Ty(), false), inet_offset);
    }

    expr_ = buf;
  }
  else if (call.func == "reg")
  {
    auto &reg_name = static_cast<String&>(*call.vargs->at(0)).str;
    int offset = arch::offset(reg_name);
    if (offset == -1)
    {
      std::cerr << "negative offset on reg() call" << std::endl;
      abort();
    }

    expr_ = b_.CreateLoad(
        b_.getInt64Ty(),
        b_.CreateGEP(ctx_, b_.getInt64(offset * sizeof(uintptr_t))),
        call.func+"_"+reg_name);
  }
  else if (call.func == "printf")
  {
    createFormatStringCall(call, printf_id_, bpftrace_.printf_args_, "printf", AsyncAction::printf);
  }
  else if (call.func == "system")
  {
    createFormatStringCall(call, system_id_, bpftrace_.system_args_, "system", AsyncAction::syscall);
  }
  else if (call.func == "cat")
  {
    createFormatStringCall(call, cat_id_, bpftrace_.cat_args_, "cat", AsyncAction::cat);
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
    AllocaInst *str_buf = b_.CreateAllocaBPF(ArrayType::get(b_.getInt8Ty(), map.ident.length() + 1), "str");
    b_.CreateMemSet(str_buf, b_.getInt8(0), map.ident.length() + 1, 1);
    b_.CreateStore(const_str, str_buf);
    ArrayType *perfdata_type = ArrayType::get(b_.getInt8Ty(), sizeof(uint64_t) + 2 * sizeof(uint64_t) + map.ident.length() + 1);
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
    b_.CREATE_MEMCPY(b_.CreateGEP(perfdata, {b_.getInt64(0), b_.getInt64(sizeof(uint64_t) + 2 * sizeof(uint64_t))}), str_buf, map.ident.length() + 1, 1);
    b_.CreatePerfEventOutput(ctx_, perfdata, sizeof(uint64_t) + 2 * sizeof(uint64_t) + map.ident.length() + 1);
    b_.CreateLifetimeEnd(perfdata);
    expr_ = nullptr;
  }
  else if (call.func == "clear" || call.func == "zero")
  {
    auto &arg = *call.vargs->at(0);
    auto &map = static_cast<Map&>(arg);
    Constant *const_str = ConstantDataArray::getString(module_->getContext(), map.ident, true);
    AllocaInst *str_buf = b_.CreateAllocaBPF(ArrayType::get(b_.getInt8Ty(), map.ident.length() + 1), "str");
    b_.CreateMemSet(str_buf, b_.getInt8(0), map.ident.length() + 1, 1);
    b_.CreateStore(const_str, str_buf);
    ArrayType *perfdata_type = ArrayType::get(b_.getInt8Ty(), sizeof(uint64_t) + map.ident.length() + 1);
    AllocaInst *perfdata = b_.CreateAllocaBPF(perfdata_type, "perfdata");
    if (call.func == "clear")
      b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::clear)), perfdata);
    else
      b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::zero)), perfdata);
    b_.CREATE_MEMCPY(b_.CreateGEP(perfdata, {b_.getInt64(0), b_.getInt64(sizeof(uint64_t))}), str_buf, map.ident.length() + 1, 1);
    b_.CreatePerfEventOutput(ctx_, perfdata, sizeof(uint64_t) + map.ident.length() + 1);
    b_.CreateLifetimeEnd(perfdata);
    expr_ = nullptr;
  }
  else if (call.func == "time")
  {
    ArrayType *perfdata_type = ArrayType::get(b_.getInt8Ty(), sizeof(uint64_t) * 2);
    AllocaInst *perfdata = b_.CreateAllocaBPF(perfdata_type, "perfdata");
    b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::time)), perfdata);
    b_.CreateStore(b_.getInt64(time_id_), b_.CreateGEP(perfdata, {b_.getInt64(0), b_.getInt64(sizeof(uint64_t))}));

    time_id_++;
    b_.CreatePerfEventOutput(ctx_, perfdata, sizeof(uint64_t) * 2);
    b_.CreateLifetimeEnd(perfdata);
    expr_ = nullptr;
  }
  else if (call.func == "kstack" || call.func == "ustack")
  {
    Value *stackid = b_.CreateGetStackId(ctx_, call.func == "ustack", call.type.stack_type);
    // Kernel stacks should not be differentiated by tid, since the kernel
    // address space is the same between pids (and when aggregating you *want*
    // to be able to correlate between pids in most cases). User-space stacks
    // are special because of ASLR and so we do usym()-style packing.
    if (call.func == "ustack")
    {
      // pack uint64_t with: (uint32_t)stack_id, (uint32_t)pid
      Value *pidhigh = b_.CreateShl(b_.CreateGetPidTgid(), 32);
      stackid = b_.CreateOr(stackid, pidhigh);
    }
    expr_ = stackid;
  }
  else if (call.func == "signal") {
    // int bpf_send_signal(u32 sig)
    auto &arg = *call.vargs->at(0);
    if (arg.type.type == Type::string) {
      auto signame = static_cast<String&>(arg).str;
      int sigid = signal_name_to_num(signame);
      // Should be caught in semantic analyser
      if (sigid < 1) {
        std::cerr << "BUG: Invalid signal ID for \"" << signame << "\"";
        abort();
      }
      b_.CreateSignal(b_.getInt32(sigid));
      return;
    }
    arg.accept(*this);
    if (arg.is_literal) {
      b_.CreateSignal(b_.getInt32(static_cast<Integer&>(arg).n));
    }
    else {
      expr_ = b_.CreateIntCast(expr_, b_.getInt32Ty(), arg.type.is_signed);
      b_.CreateSignal(expr_);
    }
  }
  else if (call.func == "strncmp") {
    uint64_t size = static_cast<Integer *>(call.vargs->at(2))->n;
    const auto& left_arg = call.vargs->at(0);
    const auto& right_arg = call.vargs->at(1);

    // If one of the strings is fixed, we can avoid storing the
    // literal in memory by calling a different function.
    if (right_arg->is_literal) {
      left_arg->accept(*this);
      Value *left_string = expr_;
      const auto& string_literal = static_cast<String *>(right_arg)->str;
      expr_ = b_.CreateStrncmp(left_string, string_literal, size, false);
      if (!left_arg->is_variable && dyn_cast<AllocaInst>(left_string))
        b_.CreateLifetimeEnd(left_string);
    } else if (left_arg->is_literal) {
      right_arg->accept(*this);
      Value *right_string = expr_;
      const auto& string_literal = static_cast<String *>(left_arg)->str;
      expr_ = b_.CreateStrncmp(right_string, string_literal, size, false);
      if (!right_arg->is_variable && dyn_cast<AllocaInst>(right_string))
        b_.CreateLifetimeEnd(right_string);
    } else {
      right_arg->accept(*this);
      Value *right_string = expr_;
      left_arg->accept(*this);
      Value *left_string = expr_;
      expr_ = b_.CreateStrncmp(left_string, right_string, size, false);
      if (!left_arg->is_variable && dyn_cast<AllocaInst>(left_string))
        b_.CreateLifetimeEnd(left_string);
      if (!right_arg->is_variable && dyn_cast<AllocaInst>(right_string))
        b_.CreateLifetimeEnd(right_string);
    }
  }
  else
  {
    std::cerr << "missing codegen for function \"" << call.func << "\"" << std::endl;
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
  if (!var.type.IsArray())
  {
    expr_ = b_.CreateLoad(variables_[var.ident]);
  }
  else
  {
    expr_ = variables_[var.ident];
  }
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

  Type &type = binop.left->type.type;
  if (type == Type::string)
  {

    if (binop.op != bpftrace::Parser::token::EQ && binop.op != bpftrace::Parser::token::NE) {
      std::cerr << "missing codegen to string operator \"" << opstr(binop) << "\"" << std::endl;
      abort();
    }

    std::string string_literal("");

    // strcmp returns 0 when strings are equal
    bool inverse = binop.op == bpftrace::Parser::token::EQ;

    // If one of the strings is fixed, we can avoid storing the
    // literal in memory by calling a different function.
    if (binop.right->is_literal)
    {
      binop.left->accept(*this);
      string_literal = static_cast<String *>(binop.right)->str;
      expr_ = b_.CreateStrcmp(expr_, string_literal, inverse);
    }
    else if (binop.left->is_literal)
    {
      binop.right->accept(*this);
      string_literal = static_cast<String *>(binop.left)->str;
      expr_ = b_.CreateStrcmp(expr_, string_literal, inverse);
    }
    else
    {
      binop.right->accept(*this);
      Value * right_string = expr_;

      binop.left->accept(*this);
      Value * left_string = expr_;

      size_t len = std::min(binop.left->type.size, binop.right->type.size);
      expr_ = b_.CreateStrncmp(left_string, right_string, len + 1, inverse);
    }
  }
  else
  {
    Value *lhs, *rhs;
    binop.left->accept(*this);
    lhs = expr_;
    binop.right->accept(*this);
    rhs = expr_;

    bool lsign = binop.left->type.is_signed;
    bool rsign = binop.right->type.is_signed;
    bool do_signed = lsign && rsign;
    // promote int to 64-bit
    lhs = b_.CreateIntCast(lhs, b_.getInt64Ty(), lsign);
    rhs = b_.CreateIntCast(rhs, b_.getInt64Ty(), rsign);

    switch (binop.op) {
      case bpftrace::Parser::token::EQ:    expr_ = b_.CreateICmpEQ (lhs, rhs); break;
      case bpftrace::Parser::token::NE:    expr_ = b_.CreateICmpNE (lhs, rhs); break;
      case bpftrace::Parser::token::LE: {
        expr_ = do_signed ? b_.CreateICmpSLE(lhs, rhs) : b_.CreateICmpULE(lhs, rhs);
        break;
      }
      case bpftrace::Parser::token::GE: {
        expr_ = do_signed ? b_.CreateICmpSGE(lhs, rhs) : b_.CreateICmpUGE(lhs, rhs);
        break;
      }
      case bpftrace::Parser::token::LT: {
        expr_ = do_signed ? b_.CreateICmpSLT(lhs, rhs) : b_.CreateICmpULT(lhs, rhs);
        break;
      }
      case bpftrace::Parser::token::GT: {
        expr_ = do_signed ? b_.CreateICmpSGT(lhs, rhs) : b_.CreateICmpUGT(lhs, rhs);
        break;
      }
      case bpftrace::Parser::token::LEFT:  expr_ = b_.CreateShl    (lhs, rhs); break;
      case bpftrace::Parser::token::RIGHT: expr_ = b_.CreateLShr   (lhs, rhs); break;
      case bpftrace::Parser::token::PLUS:  expr_ = b_.CreateAdd    (lhs, rhs); break;
      case bpftrace::Parser::token::MINUS: expr_ = b_.CreateSub    (lhs, rhs); break;
      case bpftrace::Parser::token::MUL:   expr_ = b_.CreateMul    (lhs, rhs); break;
      case bpftrace::Parser::token::DIV:   expr_ = b_.CreateUDiv   (lhs, rhs); break;
      case bpftrace::Parser::token::MOD: {
        // Always do an unsigned modulo operation here even if `do_signed`
        // is true. bpf instruction set does not support signed division.
        // We already warn in the semantic analyser that signed modulo can
        // lead to undefined behavior (because we will treat it as unsigned).
        expr_ = b_.CreateURem(lhs, rhs);
        break;
      }
      case bpftrace::Parser::token::BAND:  expr_ = b_.CreateAnd    (lhs, rhs); break;
      case bpftrace::Parser::token::BOR:   expr_ = b_.CreateOr     (lhs, rhs); break;
      case bpftrace::Parser::token::BXOR:  expr_ = b_.CreateXor    (lhs, rhs); break;
      case bpftrace::Parser::token::LAND:
      case bpftrace::Parser::token::LOR:
        std::cerr << "\"" << opstr(binop) << "\" was handled earlier" << std::endl;
        abort();
      default:
        std::cerr << "missing codegen (LLVM) to string operator \""
                  << opstr(binop) << "\"" << std::endl;
        abort();
    }
  }
  // Using signed extension will result in -1 which will likely confuse users
  expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), false);
}

static bool unop_skip_accept(Unop &unop)
{
  if (unop.expr->type.type == Type::integer)
  {
    if (unop.op == bpftrace::Parser::token::INCREMENT ||
        unop.op == bpftrace::Parser::token::DECREMENT)
      return unop.expr->is_map || unop.expr->is_variable;
  }

  return false;
}

void CodegenLLVM::visit(Unop &unop)
{
  if (!unop_skip_accept(unop))
    unop.expr->accept(*this);

  SizedType &type = unop.expr->type;
  if (type.type == Type::integer)
  {
    switch (unop.op) {
      case bpftrace::Parser::token::LNOT: {
	  Value* zero_value = Constant::getNullValue(expr_->getType());
	  expr_ = b_.CreateICmpEQ(expr_, zero_value);
      } break;
      case bpftrace::Parser::token::BNOT: expr_ = b_.CreateNot(expr_); break;
      case bpftrace::Parser::token::MINUS: expr_ = b_.CreateNeg(expr_); break;
      case bpftrace::Parser::token::INCREMENT:
      case bpftrace::Parser::token::DECREMENT:
      {
        bool is_increment = unop.op == bpftrace::Parser::token::INCREMENT;

        if (unop.expr->is_map)
        {
          Map &map = static_cast<Map&>(*unop.expr);
          AllocaInst *key = getMapKey(map);
          Value *oldval = b_.CreateMapLookupElem(map, key);
          AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_newval");
          if (is_increment)
            b_.CreateStore(b_.CreateAdd(oldval, b_.getInt64(1)), newval);
          else
            b_.CreateStore(b_.CreateSub(oldval, b_.getInt64(1)), newval);
          b_.CreateMapUpdateElem(map, key, newval);
          b_.CreateLifetimeEnd(key);

          if (unop.is_post_op)
            expr_ = oldval;
          else
            expr_ = b_.CreateLoad(newval);
          b_.CreateLifetimeEnd(newval);
        }
        else if (unop.expr->is_variable)
        {
          Variable &var = static_cast<Variable&>(*unop.expr);
          Value *oldval = b_.CreateLoad(variables_[var.ident]);
          Value *newval;
          if (is_increment)
            newval = b_.CreateAdd(oldval, b_.getInt64(1));
          else
            newval = b_.CreateSub(oldval, b_.getInt64(1));
          b_.CreateStore(newval, variables_[var.ident]);

          if (unop.is_post_op)
            expr_ = oldval;
          else
            expr_ = newval;
        }
        else
        {
          std::cerr << "invalid expression passed to " << opstr(unop) << std::endl;
          abort();
        }
        break;
      }
      case bpftrace::Parser::token::MUL:
      {
        int size = type.size;
        if (type.is_pointer)
        {
          // When dereferencing a 32-bit integer, only read in 32-bits, etc.
          size = type.pointee_size;
        }
        AllocaInst *dst = b_.CreateAllocaBPF(SizedType(type.type, size), "deref");
        b_.CreateProbeRead(dst, size, expr_);
        expr_ = b_.CreateLoad(dst);
        b_.CreateLifetimeEnd(dst);
        break;
      }
      default:
        std::cerr << "missing codegen for unary operator " << opstr(unop) << std::endl;
        abort();
    }
  }
  else if (type.type == Type::cast)
  {
    switch (unop.op) {
      case bpftrace::Parser::token::MUL:
      {
        if (type.is_pointer && unop.type.type == Type::integer)
        {
          int size = unop.type.size;
          AllocaInst *dst = b_.CreateAllocaBPF(unop.type, "deref");
          b_.CreateProbeRead(dst, size, expr_);
          expr_ = b_.CreateLoad(dst);
          b_.CreateLifetimeEnd(dst);
        }
        break;
      }
      default:
        ; // Do nothing
    }
  }
  else
  {
    std::cerr << "invalid type (" << type << ") passed to unary operator \"" << opstr(unop) << "\"" << std::endl;
    abort();
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
    b_.CREATE_MEMCPY(buf, expr_, ternary.type.size, 1);
    if (!ternary.left->is_variable && dyn_cast<AllocaInst>(expr_))
      b_.CreateLifetimeEnd(expr_);
    b_.CreateBr(done);

    b_.SetInsertPoint(right_block);
    ternary.right->accept(*this);
    b_.CREATE_MEMCPY(buf, expr_, ternary.type.size, 1);
    if (!ternary.right->is_variable && dyn_cast<AllocaInst>(expr_))
      b_.CreateLifetimeEnd(expr_);
    b_.CreateBr(done);

    b_.SetInsertPoint(done);
    expr_ = buf;
  }
}

void CodegenLLVM::visit(FieldAccess &acc)
{
  SizedType &type = acc.expr->type;
  assert(type.type == Type::cast);
  acc.expr->accept(*this);

  std::string cast_type = type.is_tparg ? tracepoint_struct_ : type.cast_type;
  Struct &cstruct = bpftrace_.structs_[cast_type];

  type = SizedType(type);
  type.size = cstruct.size;
  type.cast_type = cast_type;

  auto &field = cstruct.fields[acc.field];

  if (type.is_internal)
  {
    // The struct we are reading from has already been pulled into
    // BPF-memory, e.g. by being stored in a map.
    // Just read from the correct offset of expr_
    Value *src = b_.CreateGEP(expr_, {b_.getInt64(0), b_.getInt64(field.offset)});

    if (field.type.type == Type::cast)
    {
      // TODO This should be do-able without allocating more memory here
      AllocaInst *dst = b_.CreateAllocaBPF(field.type, "internal_" + type.cast_type + "." + acc.field);
      b_.CREATE_MEMCPY(dst, src, field.type.size, 1);
      expr_ = dst;
      // TODO clean up dst memory?
    }
    else if (field.type.type == Type::string)
    {
      expr_ = src;
    }
    else
    {
      expr_ = b_.CreateLoad(b_.GetType(field.type), src);
    }
  }
  else
  {
    // The struct we are reading from has not been pulled into BPF-memory,
    // so expr_ will contain an external pointer to the start of the struct

    Value *src = b_.CreateAdd(expr_, b_.getInt64(field.offset));

    if (field.type.type == Type::cast && !field.type.is_pointer)
    {
      // struct X
      // {
      //   struct Y y;
      // };
      //
      // We are trying to access an embedded struct, e.g. "x.y"
      //
      // Instead of copying the entire struct Y in, we'll just store it as a
      // pointer internally and dereference later when necessary.
      expr_ = src;
    }
    else if (field.type.type == Type::array)
    {
      // For array types, we want to just pass pointer along,
      // since the offset of the field should be the start of the array.
      // The pointer will be dereferenced when the array is accessed by a []
      // operation
      expr_ = src;
    }
    else if (field.type.type == Type::string)
    {
      AllocaInst *dst = b_.CreateAllocaBPF(field.type, type.cast_type + "." + acc.field);
      b_.CreateProbeRead(dst, field.type.size, src);
      expr_ = dst;
    }
    else if (field.type.type == Type::integer && field.is_bitfield)
    {
      AllocaInst *dst = b_.CreateAllocaBPF(field.type, type.cast_type + "." + acc.field);
      // memset so verifier doesn't complain about reading uninitialized stack
      b_.CreateMemSet(dst, b_.getInt8(0), field.type.size, 1);
      b_.CreateProbeRead(dst, field.bitfield.read_bytes, src);
      Value *raw = b_.CreateLoad(dst);
      Value *shifted = b_.CreateLShr(raw, field.bitfield.access_rshift);
      Value *masked = b_.CreateAnd(shifted, field.bitfield.mask);
      expr_ = masked;
      b_.CreateLifetimeEnd(dst);
    }
    else
    {
      AllocaInst *dst = b_.CreateAllocaBPF(field.type, type.cast_type + "." + acc.field);
      b_.CreateProbeRead(dst, field.type.size, src);
      expr_ = b_.CreateLoad(dst);
      b_.CreateLifetimeEnd(dst);
    }
  }
}

void CodegenLLVM::visit(ArrayAccess &arr)
{
  Value *array, *index, *offset;
  SizedType &type = arr.expr->type;

  arr.expr->accept(*this);
  array = expr_;

  arr.indexpr->accept(*this);
  // promote int to 64-bit
  index = b_.CreateIntCast(expr_, b_.getInt64Ty(), arr.expr->type.is_signed);
  offset = b_.CreateMul(index, b_.getInt64(type.pointee_size));

  AllocaInst *dst = b_.CreateAllocaBPF(SizedType(Type::integer, type.pointee_size), "array_access");
  Value *src = b_.CreateAdd(array, offset);
  b_.CreateProbeRead(dst, type.pointee_size, src);
  expr_ = b_.CreateLoad(dst);
  b_.CreateLifetimeEnd(dst);
}

void CodegenLLVM::visit(Cast &cast)
{
  cast.expr->accept(*this);
  if (cast.type.type == Type::integer) {
    expr_ = b_.CreateIntCast(expr_, b_.getIntNTy(8 * cast.type.size), cast.type.is_signed, "cast");
  }
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
  if (map.type.type == Type::string || assignment.expr->type.type == Type::inet)
  {
    val = expr;
  }
  else if (map.type.type == Type::cast)
  {
    if (assignment.expr->type.is_internal)
    {
      val = expr;
    }
    else if (assignment.expr->type.is_pointer)
    {
      // expr currently contains a pointer to the struct
      // and that's what we are saving
      AllocaInst *dst = b_.CreateAllocaBPF(map.type, map.ident + "_ptr");
      b_.CreateStore(expr, dst);
      val = dst;
    }
    else
    {
      // expr currently contains a pointer to the struct
      // We now want to read the entire struct in so we can save it
      AllocaInst *dst = b_.CreateAllocaBPF(map.type, map.ident + "_val");
      b_.CreateProbeRead(dst, map.type.size, expr);
      val = dst;
    }
  }
  else
  {
    if (map.type.type == Type::integer)
    {
      // Integers are always stored as 64-bit in map values
      expr = b_.CreateIntCast(expr, b_.getInt64Ty(), map.type.is_signed);
    }
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

  if (variables_.find(var.ident) == variables_.end())
  {
    AllocaInst *val = b_.CreateAllocaBPFInit(var.type, var.ident);
    variables_[var.ident] = val;
  }

  if (!var.type.IsArray())
  {
    b_.CreateStore(expr_, variables_[var.ident]);
  }
  else
  {
    b_.CREATE_MEMCPY(variables_[var.ident], expr_, var.type.size, 1);
    if (!assignment.expr->is_variable && dyn_cast<AllocaInst>(expr_))
      b_.CreateLifetimeEnd(expr_);
  }
}

void CodegenLLVM::visit(If &if_block)
{
  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *if_true = BasicBlock::Create(module_->getContext(), "if_stmt", parent);
  BasicBlock *if_false = BasicBlock::Create(module_->getContext(), "else_stmt", parent);

  if_block.cond->accept(*this);
  Value *cond = expr_;

  b_.CreateCondBr(b_.CreateICmpNE(cond, b_.getInt64(0), "true_cond"), if_true, if_false);

  b_.SetInsertPoint(if_true);
  for (Statement *stmt : *if_block.stmts)
  {
    stmt->accept(*this);
  }

  if (if_block.else_stmts)
  {
    BasicBlock *done = BasicBlock::Create(module_->getContext(), "done", parent);
    b_.CreateBr(done);

    b_.SetInsertPoint(if_false);
    for (Statement *stmt : *if_block.else_stmts)
    {
      stmt->accept(*this);
    }
    b_.CreateBr(done);

    b_.SetInsertPoint(done);
  }
  else
  {
      b_.CreateBr(if_false);
      b_.SetInsertPoint(if_false);
  }
}

void CodegenLLVM::visit(Unroll &unroll)
{
  for (int i=0; i < unroll.var; i++) {
    for (Statement *stmt : *unroll.stmts)
    {
      stmt->accept(*this);
    }
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

  // allow unop casts in predicates:
  expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), false);

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

  // needed for uaddr() calls and usdt probes:
  for (auto &attach_point : *probe.attach_points) {

    // All usdt probes need expansion to be able to read arguments
    if(probetype(attach_point->provider) == ProbeType::usdt)
      probe.need_expansion = true;

    current_attach_point_ = attach_point;
    // TODO: semantic analyser should ensure targets are equal when uaddr() is used
    break;
  }
  /*
   * Most of the time, we can take a probe like kprobe:do_f* and build a
   * single BPF program for that, called "s_kprobe:do_f*", and attach it to
   * each wildcard match. An exception is the "probe" builtin, where we need
   * to build different BPF programs for each wildcard match that cantains an
   * ID for the match. Those programs will be called "s_kprobe:do_fcntl" etc.
   */
  if (probe.need_expansion == false) {
    // build a single BPF program pre-wildcards
    Function *func = Function::Create(func_type, Function::ExternalLinkage, probe.name(), module_.get());
    probe.set_index(getNextIndexForProbe(probe.name()));
    func->setSection(getSectionNameForProbe(probe.name(), probe.index()));
    BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", func);
    b_.SetInsertPoint(entry);

    ctx_ = func->arg_begin();

    if (probe.pred) {
      probe.pred->accept(*this);
    }
    variables_.clear();
    for (Statement *stmt : *probe.stmts) {
      stmt->accept(*this);
    }

    b_.CreateRet(ConstantInt::get(module_->getContext(), APInt(64, 0)));

  } else {
    /*
     * Build a separate BPF program for each wildcard match.
     * We begin by saving state that gets changed by the codegen pass, so we
     * can restore it for the next pass (printf_id_, time_id_).
     */
    int starting_printf_id = printf_id_;
    int starting_cat_id = cat_id_;
    int starting_system_id = system_id_;
    int starting_time_id = time_id_;
    int starting_join_id = join_id_;

    for (auto attach_point : *probe.attach_points) {
      current_attach_point_ = attach_point;

      std::set<std::string> matches;
      if (attach_point->provider == "BEGIN" || attach_point->provider == "END") {
        matches.insert(attach_point->provider);
      } else {
        matches = bpftrace_.find_wildcard_matches(*attach_point);
      }

      tracepoint_struct_ = "";
      for (auto &match_ : matches) {
        printf_id_ = starting_printf_id;
        cat_id_ = starting_cat_id;
        system_id_ = starting_system_id;
        time_id_ = starting_time_id;
        join_id_ = starting_join_id;

        std::string full_func_id = match_;

        // USDT probes must specify both a provider and a function name
        // So we will extract out the provider namespace to get just the function name
        if (probetype(attach_point->provider) == ProbeType::usdt) {
          std::string func_id = match_;
          std::string orig_ns = attach_point->ns;
          std::string ns = func_id.substr(0, func_id.find(":"));

          func_id.erase(0, func_id.find(":")+1);

          // Ensure that the full probe name used is the resolved one for this probe,
          attach_point->ns = ns;
          probefull_ = attach_point->name(func_id);

          // But propagate the originally specified namespace in case it has a wildcard,
          attach_point->ns = orig_ns;

          // Set the probe identifier so that we can read arguments later
          attach_point->usdt = USDTHelper::find(bpftrace_.pid_, attach_point->target, ns, func_id);
        } else if (attach_point->provider == "BEGIN" || attach_point->provider == "END") {
          probefull_ = attach_point->provider;
        } else {
          probefull_ = attach_point->name(full_func_id);
        }

        // tracepoint wildcard expansion, part 3 of 3. Set tracepoint_struct_ for use by args builtin.
        if (probetype(attach_point->provider) == ProbeType::tracepoint)
          tracepoint_struct_ = TracepointFormatParser::get_struct_name(attach_point->target, full_func_id);
        int index = getNextIndexForProbe(probe.name());
        attach_point->set_index(full_func_id, index);
        Function *func = Function::Create(func_type, Function::ExternalLinkage, probefull_, module_.get());
        func->setSection(getSectionNameForProbe(probefull_, index));
        BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", func);
        b_.SetInsertPoint(entry);

        // check: do the following 8 lines need to be in the wildcard loop?
        ctx_ = func->arg_begin();
        if (probe.pred) {
          probe.pred->accept(*this);
        }
        variables_.clear();
        for (Statement *stmt : *probe.stmts) {
          stmt->accept(*this);
        }
        b_.CreateRet(ConstantInt::get(module_->getContext(), APInt(64, 0)));
      }
    }
  }
  bpftrace_.add_probe(probe);
  current_attach_point_ = nullptr;
}

void CodegenLLVM::visit(Program &program)
{
  for (Probe *probe : *program.probes)
    probe->accept(*this);
}

int CodegenLLVM::getNextIndexForProbe(const std::string &probe_name) {
  if (next_probe_index_.count(probe_name) == 0)
    next_probe_index_[probe_name] = 1;
  int index = next_probe_index_[probe_name];
  next_probe_index_[probe_name] += 1;
  return index;
}

std::string CodegenLLVM::getSectionNameForProbe(const std::string &probe_name, int index) {
  return "s_" + probe_name + "_" + std::to_string(index);
}

AllocaInst *CodegenLLVM::getMapKey(Map &map)
{
  AllocaInst *key;
  if (map.vargs) {
    // A single value as a map key (e.g., @[comm] = 0;)
    if (map.vargs->size() == 1)
    {
      Expression *expr = map.vargs->at(0);
      expr->accept(*this);
      if (expr->type.type == Type::string || expr->type.type == Type::usym ||
        expr->type.type == Type::inet)
      {
        // The value is already in the stack; Skip copy
        key = dyn_cast<AllocaInst>(expr_);
      }
      else
      {
        key = b_.CreateAllocaBPF(expr->type.size, map.ident + "_key");
        b_.CreateStore(
            b_.CreateIntCast(expr_, b_.getInt64Ty(), expr->type.is_signed),
            key);
      }
    }
    else
    {
      // Two or more values as a map key (e.g, @[comm, pid] = 1;)
      size_t size = 0;
      for (Expression *expr : *map.vargs)
      {
        size += expr->type.size;
      }
      key = b_.CreateAllocaBPF(size, map.ident + "_key");

      int offset = 0;
      // Construct a map key in the stack
      for (Expression *expr : *map.vargs)
      {
        expr->accept(*this);
        Value *offset_val =
            b_.CreateGEP(key, { b_.getInt64(0), b_.getInt64(offset) });
        if (expr->type.type == Type::string || expr->type.type == Type::usym ||
            expr->type.type == Type::inet)
        {
          b_.CREATE_MEMCPY(offset_val, expr_, expr->type.size, 1);
          if (!expr->is_variable && dyn_cast<AllocaInst>(expr_))
            b_.CreateLifetimeEnd(expr_);
        }
        else
        {
          // promote map key to 64-bit:
          b_.CreateStore(
              b_.CreateIntCast(expr_, b_.getInt64Ty(), expr->type.is_signed),
              offset_val);
        }
        offset += expr->type.size;
      }
    }
  }
  else
  {
    // No map key (e.g., @ = 1;). Use 0 as a key.
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
    key = b_.CreateAllocaBPF(size, map.ident + "_key");

    int offset = 0;
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
      Value *offset_val = b_.CreateGEP(key, {b_.getInt64(0), b_.getInt64(offset)});
      if (expr->type.type == Type::string || expr->type.type == Type::usym ||
        expr->type.type == Type::inet)
      {
        b_.CREATE_MEMCPY(offset_val, expr_, expr->type.size, 1);
        if (!expr->is_variable && dyn_cast<AllocaInst>(expr_))
          b_.CreateLifetimeEnd(expr_);
      }
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
  b_.CreateCondBr(b_.CreateICmpNE(lhs, b_.GetIntSameSize(0, lhs), "lhs_true_cond"),
                  lhs_true_block,
                  false_block);

  b_.SetInsertPoint(lhs_true_block);
  Value *rhs;
  binop.right->accept(*this);
  rhs = expr_;
  b_.CreateCondBr(b_.CreateICmpNE(rhs, b_.GetIntSameSize(0, rhs), "rhs_true_cond"),
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
  b_.CreateCondBr(b_.CreateICmpNE(lhs, b_.GetIntSameSize(0, lhs), "lhs_true_cond"),
                  true_block,
                  lhs_false_block);

  b_.SetInsertPoint(lhs_false_block);
  Value *rhs;
  binop.right->accept(*this);
  rhs = expr_;
  b_.CreateCondBr(b_.CreateICmpNE(rhs, b_.GetIntSameSize(0, rhs), "rhs_true_cond"),
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
  // log2() returns a bucket index for the given value. Index 0 is for
  // values less than 0, index 1 is for 0, and indexes 2 onwards is the
  // power-of-2 histogram index.
  //
  // log2(int n)
  // {
  //   int result = 0;
  //   int shift;
  //   if (n < 0) return result;
  //   result++;
  //   if (n == 0) return result;
  //   result++;
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

  // setup n and result registers
  Value *arg = log2_func->arg_begin();
  Value *n_alloc = b_.CreateAllocaBPF(SizedType(Type::integer, 8));
  b_.CreateStore(arg, n_alloc);
  Value *result = b_.CreateAllocaBPF(SizedType(Type::integer, 8));
  b_.CreateStore(b_.getInt64(0), result);

  // test for less than zero
  BasicBlock *is_less_than_zero = BasicBlock::Create(module_->getContext(), "hist.is_less_than_zero", log2_func);
  BasicBlock *is_not_less_than_zero = BasicBlock::Create(module_->getContext(), "hist.is_not_less_than_zero", log2_func);
  b_.CreateCondBr(b_.CreateICmpSLT(b_.CreateLoad(n_alloc), b_.getInt64(0)),
                  is_less_than_zero,
                  is_not_less_than_zero);
  b_.SetInsertPoint(is_less_than_zero);
  b_.CreateRet(b_.CreateLoad(result));
  b_.SetInsertPoint(is_not_less_than_zero);

  // test for equal to zero
  BasicBlock *is_zero = BasicBlock::Create(module_->getContext(), "hist.is_zero", log2_func);
  BasicBlock *is_not_zero = BasicBlock::Create(module_->getContext(), "hist.is_not_zero", log2_func);
  b_.CreateCondBr(b_.CreateICmpEQ(b_.CreateLoad(n_alloc), b_.getInt64(0)),
                  is_zero,
                  is_not_zero);
  b_.SetInsertPoint(is_zero);
  b_.CreateStore(b_.getInt64(1), result);
  b_.CreateRet(b_.CreateLoad(result));
  b_.SetInsertPoint(is_not_zero);

  // power-of-2 index, offset by +2
  b_.CreateStore(b_.getInt64(2), result);
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
  //   int result;
  //
  //   if (value < min)
  //     return 0;
  //   if (value > max)
  //     return 1 + (max - min) / step;
  //   result = 1 + (value - min) / step;
  //
  //   return result;
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
  Value *div = b_.CreateUDiv(b_.CreateSub(b_.CreateLoad(max_alloc), b_.CreateLoad(min_alloc)), b_.CreateLoad(step_alloc));
  b_.CreateStore(b_.CreateAdd(div, b_.getInt64(1)), result_alloc);
  b_.CreateRet(b_.CreateLoad(result_alloc));

  b_.SetInsertPoint(le_max);
  Value *div3 = b_.CreateUDiv(b_.CreateSub(b_.CreateLoad(value_alloc), b_.CreateLoad(min_alloc)), b_.CreateLoad(step_alloc));
  b_.CreateStore(b_.CreateAdd(div3, b_.getInt64(1)), result_alloc);
  b_.CreateRet(b_.CreateLoad(result_alloc));
}

void CodegenLLVM::createFormatStringCall(Call &call, int &id, CallArgs &call_args,
                                         const std::string &call_name, AsyncAction async_action)
{
  /*
   * perf event output has: uint64_t id, vargs
   * The id maps to bpftrace_.*_args_, and is a way to define the
   * types and offsets of each of the arguments, and share that between BPF and
   * user-space for printing.
   */
  std::vector<llvm::Type *> elements = { b_.getInt64Ty() }; // ID

  auto &args = std::get<1>(call_args.at(id));
  for (Field &arg : args)
  {
    llvm::Type *ty = b_.GetType(arg.type);
    elements.push_back(ty);
  }
  StructType *fmt_struct = StructType::create(elements, call_name + "_t", false);
  int struct_size = layout_.getTypeAllocSize(fmt_struct);

  auto *struct_layout = layout_.getStructLayout(fmt_struct);
  for (size_t i=0; i<args.size(); i++)
  {
    Field &arg = args[i];
    arg.offset = struct_layout->getElementOffset(i+1); // +1 for the id field
  }

  AllocaInst *fmt_args = b_.CreateAllocaBPF(fmt_struct, call_name + "_args");
  b_.CreateMemSet(fmt_args, b_.getInt8(0), struct_size, 1);

  Value *id_offset = b_.CreateGEP(fmt_args, {b_.getInt32(0), b_.getInt32(0)});
  b_.CreateStore(b_.getInt64(id + asyncactionint(async_action)), id_offset);
  for (size_t i=1; i<call.vargs->size(); i++)
  {
    Expression &arg = *call.vargs->at(i);
    expr_deleter_ = nullptr;
    arg.accept(*this);
    Value *offset = b_.CreateGEP(fmt_args, {b_.getInt32(0), b_.getInt32(i)});
    if (arg.type.IsArray())
    {
      b_.CREATE_MEMCPY(offset, expr_, arg.type.size, 1);
      if (!arg.is_variable && dyn_cast<AllocaInst>(expr_))
        b_.CreateLifetimeEnd(expr_);
    }
    else
      b_.CreateStore(expr_, offset);

    if (expr_deleter_)
      expr_deleter_();
  }

  id++;
  b_.CreatePerfEventOutput(ctx_, fmt_args, struct_size);
  b_.CreateLifetimeEnd(fmt_args);
  expr_ = nullptr;
}

std::unique_ptr<BpfOrc> CodegenLLVM::compile(DebugLevel debug, std::ostream &out)
{
  createLog2Function();
  createLinearFunction();
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
  if (debug == DebugLevel::kFullDebug)
  {
    raw_os_ostream llvm_ostream(out);
    llvm_ostream << "Before optimization\n";
    llvm_ostream << "-------------------\n\n";
    DumpIR(llvm_ostream);
  }

  PM.run(*module_.get());

  if (debug != DebugLevel::kNone)
  {
    raw_os_ostream llvm_ostream(out);
    if (debug == DebugLevel::kFullDebug) {
      llvm_ostream << "\nAfter optimization\n";
      llvm_ostream << "------------------\n\n";
    }
    DumpIR(llvm_ostream);
  }

  auto bpforc = std::make_unique<BpfOrc>(targetMachine);
  bpforc->compileModule(move(module_));

  return bpforc;
}

void CodegenLLVM::DumpIR() {
  raw_os_ostream llvm_ostream(std::cout);
  DumpIR(llvm_ostream);
}

void CodegenLLVM::DumpIR(raw_os_ostream &out) {
  module_->print(out, nullptr, false, true);
}

} // namespace ast
} // namespace bpftrace
