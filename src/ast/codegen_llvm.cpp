#include "codegen_llvm.h"
#include "arch/arch.h"
#include "ast.h"
#include "ast/async_event_types.h"
#include "bpforc.h"
#include "codegen_helper.h"
#include "log.h"
#include "parser.tab.hh"
#include "signal_bt.h"
#include "tracepoint_format_parser.h"
#include "types.h"
#include "usdt.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <ctime>
#include <fstream>

#include <llvm-c/Transforms/IPO.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

namespace bpftrace {
namespace ast {

CodegenLLVM::CodegenLLVM(Node *root, BPFtrace &bpftrace)
    : root_(root),
      bpftrace_(bpftrace),
      orc_(BpfOrc::Create()),
      module_(std::make_unique<Module>("bpftrace", orc_->getContext())),
      b_(orc_->getContext(), *module_.get(), bpftrace)
{
  module_->setDataLayout(datalayout());
  module_->setTargetTriple(LLVMTargetTriple);
}

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
        if (!param.is_in_str)
        {
          expr_ = b_.getInt64(std::stoll(pstr, nullptr, 0));
        }
        else
        {
          Constant *const_str = ConstantDataArray::getString(module_->getContext(), pstr, true);
          AllocaInst *buf = b_.CreateAllocaBPF(ArrayType::get(b_.getInt8Ty(), pstr.length() + 1), "str");
          b_.CREATE_MEMSET(buf, b_.getInt8(0), pstr.length() + 1, 1);
          b_.CreateStore(const_str, buf);
          expr_ = b_.CreatePtrToInt(buf, b_.getInt64Ty());
          expr_deleter_ = [this, buf]() { b_.CreateLifetimeEnd(buf); };
        }
      }
      break;
    case PositionalParameterType::count:
      expr_ = b_.getInt64(bpftrace_.num_params());
      break;
  }
}

void CodegenLLVM::visit(String &string)
{
  string.str.resize(string.type.GetSize() - 1);
  Constant *const_str = ConstantDataArray::getString(module_->getContext(), string.str, true);
  AllocaInst *buf = b_.CreateAllocaBPF(string.type, "str");
  b_.CreateStore(const_str, buf);
  expr_ = buf;
  expr_deleter_ = [this, buf]() { b_.CreateLifetimeEnd(buf); };
}

// NB: we do not resolve identifiers that are structs. That is because in
// bpftrace you cannot really instantiate a struct.
void CodegenLLVM::visit(Identifier &identifier)
{
  if (bpftrace_.enums_.count(identifier.ident) != 0)
  {
    expr_ = b_.getInt64(bpftrace_.enums_[identifier.ident]);
  }
  else
  {
    LOG(FATAL) << "unknown identifier \"" << identifier.ident << "\"";
  }
}

void CodegenLLVM::kstack_ustack(const std::string &ident,
                                StackType stack_type,
                                const location &loc)
{
  Value *stackid = b_.CreateGetStackId(
      ctx_, ident == "ustack", stack_type, loc);

  // Kernel stacks should not be differentiated by tid, since the kernel
  // address space is the same between pids (and when aggregating you *want*
  // to be able to correlate between pids in most cases). User-space stacks
  // are special because of ASLR and so we do usym()-style packing.
  if (ident == "ustack")
  {
    // pack uint64_t with: (uint32_t)stack_id, (uint32_t)pid
    Value *pidhigh = b_.CreateShl(b_.CreateGetPidTgid(), 32);
    stackid = b_.CreateOr(stackid, pidhigh);
  }

  expr_ = stackid;
}

void CodegenLLVM::visit(Builtin &builtin)
{
  if (builtin.ident == "nsecs")
  {
    expr_ = b_.CreateGetNs(bpftrace_.feature_->has_helper_ktime_get_boot_ns());
  }
  else if (builtin.ident == "elapsed")
  {
    AllocaInst *key = b_.CreateAllocaBPF(b_.getInt64Ty(), "elapsed_key");
    b_.CreateStore(b_.getInt64(0), key);

    auto *map = bpftrace_.maps[MapManager::Type::Elapsed].value();
    auto type = CreateUInt64();
    auto start = b_.CreateMapLookupElem(ctx_, map->id, key, type, builtin.loc);
    expr_ = b_.CreateGetNs(bpftrace_.feature_->has_helper_ktime_get_boot_ns());
    expr_ = b_.CreateSub(expr_, start);
    // start won't be on stack, no need to LifeTimeEnd it
    b_.CreateLifetimeEnd(key);
  }
  else if (builtin.ident == "kstack" || builtin.ident == "ustack")
  {
    kstack_ustack(builtin.ident, builtin.type.stack_type, builtin.loc);
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
    b_.CREATE_MEMSET(buf, b_.getInt8(0), builtin.type.GetSize(), 1);
    b_.CreateGetCurrentComm(ctx_, buf, builtin.type.GetSize(), builtin.loc);
    expr_ = buf;
    expr_deleter_ = [this, buf]() { b_.CreateLifetimeEnd(buf); };
  }
  else if ((!builtin.ident.compare(0, 3, "arg") && builtin.ident.size() == 4 &&
      builtin.ident.at(3) >= '0' && builtin.ident.at(3) <= '9') ||
      builtin.ident == "retval" ||
      builtin.ident == "func")
  {
    if (builtin.type.is_kfarg)
    {
      expr_ = b_.CreatKFuncArg(ctx_, builtin.type, builtin.ident);
      return;
    }

    int offset;
    if (builtin.ident == "retval")
      offset = arch::ret_offset();
    else if (builtin.ident == "func")
      offset = arch::pc_offset();
    else // argX
    {
      int arg_num = atoi(builtin.ident.substr(3).c_str());
      if (probetype(current_attach_point_->provider) == ProbeType::usdt) {
        expr_ = b_.CreateUSDTReadArgument(ctx_,
                                          current_attach_point_,
                                          current_usdt_location_index_,
                                          arg_num,
                                          builtin,
                                          bpftrace_.pid(),
                                          AddrSpace::user,
                                          builtin.loc);
        return;
      }
      offset = arch::arg_offset(arg_num);
    }

    Value *ctx = b_.CreatePointerCast(ctx_, b_.getInt64Ty()->getPointerTo());
    // LLVM optimization is possible to transform `(uint64*)ctx` into
    // `(uint8*)ctx`, but sometimes this causes invalid context access.
    // Mark every context acess to supporess any LLVM optimization.
    expr_ = b_.CreateLoad(b_.getInt64Ty(),
                          b_.CreateGEP(ctx, b_.getInt64(offset)),
                          builtin.ident);
    // LLVM 7.0 <= does not have CreateLoad(*Ty, *Ptr, isVolatile, Name),
    // so call setVolatile() manually
    dyn_cast<LoadInst>(expr_)->setVolatile(true);

    if (builtin.type.IsUsymTy())
    {
      expr_ = b_.CreateUSym(expr_);
      Value *expr = expr_;
      expr_deleter_ = [this, expr]() { b_.CreateLifetimeEnd(expr); };
    }
  }
  else if (!builtin.ident.compare(0, 4, "sarg") && builtin.ident.size() == 5 &&
      builtin.ident.at(4) >= '0' && builtin.ident.at(4) <= '9')
  {
    int sp_offset = arch::sp_offset();
    if (sp_offset == -1)
    {
      LOG(FATAL) << "negative offset for stack pointer";
    }

    int arg_num = atoi(builtin.ident.substr(4).c_str());
    Value *ctx = b_.CreatePointerCast(ctx_, b_.getInt64Ty()->getPointerTo());
    Value *sp = b_.CreateLoad(b_.getInt64Ty(),
                              b_.CreateGEP(ctx, b_.getInt64(sp_offset)),
                              "reg_sp");
    dyn_cast<LoadInst>(sp)->setVolatile(true);
    AllocaInst *dst = b_.CreateAllocaBPF(builtin.type, builtin.ident);
    Value *src = b_.CreateAdd(sp,
                              b_.getInt64((arg_num + arch::arg_stack_offset()) *
                                          sizeof(uintptr_t)));
    b_.CreateProbeRead(ctx_, dst, 8, src, builtin.type.GetAS(), builtin.loc);
    expr_ = b_.CreateLoad(dst);
    b_.CreateLifetimeEnd(dst);
  }
  else if (builtin.ident == "probe")
  {
    auto begin = bpftrace_.resources.probe_ids.begin();
    auto end = bpftrace_.resources.probe_ids.end();
    auto found = std::find(begin, end, probefull_);
    builtin.probe_id = std::distance(begin, found);
    if (found == end) {
      bpftrace_.resources.probe_ids.push_back(probefull_);
    }
    expr_ = b_.getInt64(builtin.probe_id);
  }
  else if (builtin.ident == "args" || builtin.ident == "ctx")
  {
    // ctx is undocumented builtin: for debugging
    // ctx_ is casted to int for arithmetic operation
    // it will be casted to a pointer when loading
    expr_ = b_.CreatePtrToInt(ctx_, b_.getInt64Ty());
  }
  else if (builtin.ident == "cpid")
  {
    pid_t cpid = bpftrace_.child_->pid();
    if (cpid < 1) {
      LOG(FATAL) << "BUG: Invalid cpid: " << cpid;
    }
    expr_ = b_.getInt64(cpid);
  }
  else
  {
    LOG(FATAL) << "unknown builtin \"" << builtin.ident << "\"";
  }
}

void CodegenLLVM::visit(Call &call)
{
  if (call.func == "count")
  {
    Map &map = *call.map;
    auto [key, scoped_key_deleter] = getMapKey(map);
    Value *oldval = b_.CreateMapLookupElem(ctx_, map, key, call.loc);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");
    b_.CreateStore(b_.CreateAdd(oldval, b_.getInt64(1)), newval);
    b_.CreateMapUpdateElem(ctx_, map, key, newval, call.loc);

    // oldval can only be an integer so won't be in memory and doesn't need lifetime end
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "sum")
  {
    Map &map = *call.map;
    auto [key, scoped_key_deleter] = getMapKey(map);
    Value *oldval = b_.CreateMapLookupElem(ctx_, map, key, call.loc);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");

    auto scoped_del = accept(call.vargs->front());
    // promote int to 64-bit
    expr_ = b_.CreateIntCast(expr_,
                             b_.getInt64Ty(),
                             call.vargs->front()->type.IsSigned());
    b_.CreateStore(b_.CreateAdd(expr_, oldval), newval);
    b_.CreateMapUpdateElem(ctx_, map, key, newval, call.loc);

    // oldval can only be an integer so won't be in memory and doesn't need lifetime end
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "min")
  {
    Map &map = *call.map;
    auto [key, scoped_key_deleter] = getMapKey(map);
    Value *oldval = b_.CreateMapLookupElem(ctx_, map, key, call.loc);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");

    // Store the max of (0xffffffff - val), so that our SGE comparison with uninitialized
    // elements will always store on the first occurrence. Revent this later when printing.
    Function *parent = b_.GetInsertBlock()->getParent();
    auto scoped_del = accept(call.vargs->front());
    // promote int to 64-bit
    expr_ = b_.CreateIntCast(expr_,
                             b_.getInt64Ty(),
                             call.vargs->front()->type.IsSigned());
    Value *inverted = b_.CreateSub(b_.getInt64(0xffffffff), expr_);
    BasicBlock *lt = BasicBlock::Create(module_->getContext(), "min.lt", parent);
    BasicBlock *ge = BasicBlock::Create(module_->getContext(), "min.ge", parent);
    b_.CreateCondBr(b_.CreateICmpSGE(inverted, oldval), ge, lt);

    b_.SetInsertPoint(ge);
    b_.CreateStore(inverted, newval);
    b_.CreateMapUpdateElem(ctx_, map, key, newval, call.loc);
    b_.CreateBr(lt);

    b_.SetInsertPoint(lt);
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "max")
  {
    Map &map = *call.map;
    auto [key, scoped_key_deleter] = getMapKey(map);
    Value *oldval = b_.CreateMapLookupElem(ctx_, map, key, call.loc);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");

    Function *parent = b_.GetInsertBlock()->getParent();
    auto scoped_del = accept(call.vargs->front());
    // promote int to 64-bit
    expr_ = b_.CreateIntCast(expr_,
                             b_.getInt64Ty(),
                             call.vargs->front()->type.IsSigned());
    BasicBlock *lt = BasicBlock::Create(module_->getContext(), "min.lt", parent);
    BasicBlock *ge = BasicBlock::Create(module_->getContext(), "min.ge", parent);
    b_.CreateCondBr(b_.CreateICmpSGE(expr_, oldval), ge, lt);

    b_.SetInsertPoint(ge);
    b_.CreateStore(expr_, newval);
    b_.CreateMapUpdateElem(ctx_, map, key, newval, call.loc);
    b_.CreateBr(lt);

    b_.SetInsertPoint(lt);
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "avg" || call.func == "stats")
  {
    // avg stores the count and total in a hist map using indexes 0 and 1
    // respectively, and the calculation is made when printing.
    Map &map = *call.map;

    AllocaInst *count_key = getHistMapKey(map, b_.getInt64(0));
    Value *count_old = b_.CreateMapLookupElem(ctx_, map, count_key, call.loc);
    AllocaInst *count_new = b_.CreateAllocaBPF(map.type, map.ident + "_num");
    b_.CreateStore(b_.CreateAdd(count_old, b_.getInt64(1)), count_new);
    b_.CreateMapUpdateElem(ctx_, map, count_key, count_new, call.loc);
    b_.CreateLifetimeEnd(count_key);
    b_.CreateLifetimeEnd(count_new);

    AllocaInst *total_key = getHistMapKey(map, b_.getInt64(1));
    Value *total_old = b_.CreateMapLookupElem(ctx_, map, total_key, call.loc);
    AllocaInst *total_new = b_.CreateAllocaBPF(map.type, map.ident + "_val");
    auto scoped_del = accept(call.vargs->front());
    // promote int to 64-bit
    expr_ = b_.CreateIntCast(expr_,
                             b_.getInt64Ty(),
                             call.vargs->front()->type.IsSigned());
    b_.CreateStore(b_.CreateAdd(expr_, total_old), total_new);
    b_.CreateMapUpdateElem(ctx_, map, total_key, total_new, call.loc);
    b_.CreateLifetimeEnd(total_key);
    b_.CreateLifetimeEnd(total_new);

    expr_ = nullptr;
  }
  else if (call.func == "hist")
  {
    if (!log2_func_)
      log2_func_ = createLog2Function();

    Map &map = *call.map;
    auto scoped_del = accept(call.vargs->front());
    // promote int to 64-bit
    expr_ = b_.CreateIntCast(expr_,
                             b_.getInt64Ty(),
                             call.vargs->front()->type.IsSigned());
    Value *log2 = b_.CreateCall(log2_func_, expr_, "log2");
    AllocaInst *key = getHistMapKey(map, log2);

    Value *oldval = b_.CreateMapLookupElem(ctx_, map, key, call.loc);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");
    b_.CreateStore(b_.CreateAdd(oldval, b_.getInt64(1)), newval);
    b_.CreateMapUpdateElem(ctx_, map, key, newval, call.loc);

    // oldval can only be an integer so won't be in memory and doesn't need lifetime end
    b_.CreateLifetimeEnd(key);
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "lhist")
  {
    if (!linear_func_)
      linear_func_ = createLinearFunction();

    Map &map = *call.map;
    auto scoped_del = accept(call.vargs->front());

    // prepare arguments
    auto *value_arg = call.vargs->at(0);
    auto *min_arg = call.vargs->at(1);
    auto *max_arg = call.vargs->at(2);
    auto *step_arg = call.vargs->at(3);
    Value *value, *min, *max, *step;
    auto scoped_del_value_arg = accept(value_arg);
    value = expr_;
    auto scoped_del_min_arg = accept(min_arg);
    min = expr_;
    auto scoped_del_max_arg = accept(max_arg);
    max = expr_;
    auto scoped_del_step_arg = accept(step_arg);
    step = expr_;

    // promote int to 64-bit
    value = b_.CreateIntCast(value,
                             b_.getInt64Ty(),
                             call.vargs->front()->type.IsSigned());
    min = b_.CreateIntCast(min, b_.getInt64Ty(), false);
    max = b_.CreateIntCast(max, b_.getInt64Ty(), false);
    step = b_.CreateIntCast(step, b_.getInt64Ty(), false);

    Value *linear = b_.CreateCall(linear_func_,
                                  { value, min, max, step },
                                  "linear");

    AllocaInst *key = getHistMapKey(map, linear);

    Value *oldval = b_.CreateMapLookupElem(ctx_, map, key, call.loc);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_val");
    b_.CreateStore(b_.CreateAdd(oldval, b_.getInt64(1)), newval);
    b_.CreateMapUpdateElem(ctx_, map, key, newval, call.loc);

    // oldval can only be an integer so won't be in memory and doesn't need lifetime end
    b_.CreateLifetimeEnd(key);
    b_.CreateLifetimeEnd(newval);
    expr_ = nullptr;
  }
  else if (call.func == "delete")
  {
    auto &arg = *call.vargs->at(0);
    auto &map = static_cast<Map&>(arg);
    auto [key, scoped_key_deleter] = getMapKey(map);
    auto imap = *bpftrace_.maps.Lookup(map.ident);
    if (!imap->is_clearable())
    {
      // store zero insted of calling bpf_map_delete_elem()
      AllocaInst *val = b_.CreateAllocaBPF(map.type, map.ident + "_zero");
      b_.CreateStore(Constant::getNullValue(b_.GetType(map.type)), val);
      b_.CreateMapUpdateElem(ctx_, map, key, val, call.loc);
      b_.CreateLifetimeEnd(val);
    }
    else
    {
      b_.CreateMapDeleteElem(ctx_, map, key, call.loc);
    }
    expr_ = nullptr;
  }
  else if (call.func == "str")
  {
    AllocaInst *strlen = b_.CreateAllocaBPF(b_.getInt64Ty(), "strlen");
    b_.CREATE_MEMSET(strlen, b_.getInt8(0), sizeof(uint64_t), 1);
    if (call.vargs->size() > 1) {
      auto scoped_del = accept(call.vargs->at(1));
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
    b_.CREATE_MEMSET(buf, b_.getInt8(0), bpftrace_.strlen_, 1);
    auto arg0 = call.vargs->front();
    auto scoped_del = accept(call.vargs->front());
    b_.CreateProbeReadStr(
        ctx_, buf, b_.CreateLoad(strlen), expr_, arg0->type.GetAS(), call.loc);
    b_.CreateLifetimeEnd(strlen);

    expr_ = buf;
    expr_deleter_ = [this,buf]() { b_.CreateLifetimeEnd(buf); };
  }
  else if (call.func == "buf")
  {
    Value *max_length = b_.getInt64(bpftrace_.strlen_);
    size_t fixed_buffer_length = bpftrace_.strlen_;
    Value *length;

    if (call.vargs->size() > 1)
    {
      auto &arg = *call.vargs->at(1);
      auto scoped_del = accept(&arg);

      Value *proposed_length = expr_;
      Value *cmp = b_.CreateICmp(
          CmpInst::ICMP_ULE, proposed_length, max_length, "length.cmp");
      length = b_.CreateSelect(
          cmp, proposed_length, max_length, "length.select");

      if (arg.is_literal)
        fixed_buffer_length = static_cast<Integer &>(arg).n;
    }
    else
    {
      auto &arg = *call.vargs->at(0);
      fixed_buffer_length = arg.type.GetNumElements() *
                            arg.type.GetElementTy()->GetSize();
      length = b_.getInt8(fixed_buffer_length);
    }

    auto elements = AsyncEvent::Buf().asLLVMType(b_, fixed_buffer_length);
    std::ostringstream dynamic_sized_struct_name;
    dynamic_sized_struct_name << "buffer_" << fixed_buffer_length << "_t";
    StructType *buf_struct = b_.GetStructType(dynamic_sized_struct_name.str(),
                                              elements,
                                              false);
    AllocaInst *buf = b_.CreateAllocaBPF(buf_struct, "buffer");

    Value *buf_len_offset = b_.CreateGEP(buf,
                                         { b_.getInt32(0), b_.getInt32(0) });
    length = b_.CreateIntCast(length, buf_struct->getElementType(0), false);
    b_.CreateStore(length, buf_len_offset);

    Value *buf_data_offset = b_.CreateGEP(buf,
                                          { b_.getInt32(0), b_.getInt32(1) });
    b_.CREATE_MEMSET(buf_data_offset,
                     b_.GetIntSameSize(0, elements.at(0)),
                     fixed_buffer_length,
                     1);

    auto scoped_del = accept(call.vargs->front());
    auto arg0 = call.vargs->front();
    // arg0 is already on the bpf stack -> use probe kernel
    // otherwise ->  addrspace of arg0->type
    // case : struct MyStruct { char b[4]; };
    // $s = (struct MyStruct *)arg0; buf($s->b, 4)
    b_.CreateProbeRead(ctx_,
                       static_cast<AllocaInst *>(buf_data_offset),
                       length,
                       expr_,
                       find_addrspace_stack(arg0->type),
                       call.loc);

    expr_ = buf;
    expr_deleter_ = [this, buf]() { b_.CreateLifetimeEnd(buf); };
  }
  else if (call.func == "path")
  {
    AllocaInst *buf = b_.CreateAllocaBPF(bpftrace_.strlen_, "path");
    b_.CREATE_MEMSET(buf, b_.getInt8(0), bpftrace_.strlen_, 1);
    call.vargs->front()->accept(*this);
    b_.CreatePath(ctx_, buf, expr_, call.loc);
    expr_ = buf;
    expr_deleter_ = [this, buf]() { b_.CreateLifetimeEnd(buf); };
  }
  else if (call.func == "kaddr")
  {
    uint64_t addr;
    auto name = bpftrace_.get_string_literal(call.vargs->at(0));
    addr = bpftrace_.resolve_kname(name);
    if (!addr)
      throw std::runtime_error("Failed to resolve kernel symbol: " + name);
    expr_ = b_.getInt64(addr);
  }
  else if (call.func == "uaddr")
  {
    auto name = bpftrace_.get_string_literal(call.vargs->at(0));
    struct symbol sym = {};
    int err =
        bpftrace_.resolve_uname(name, &sym, current_attach_point_->target);
    if (err < 0 || sym.address == 0)
      throw std::runtime_error("Could not resolve symbol: " +
                               current_attach_point_->target + ":" + name);
    expr_ = b_.getInt64(sym.address);
  }
  else if (call.func == "cgroupid")
  {
    uint64_t cgroupid;
    auto path = bpftrace_.get_string_literal(call.vargs->at(0));
    cgroupid = bpftrace_.resolve_cgroupid(path);
    expr_ = b_.getInt64(cgroupid);
  }
  else if (call.func == "join")
  {
    auto arg0 = call.vargs->front();
    auto scoped_del = accept(arg0);
    auto addrspace = arg0->type.GetAS();
    AllocaInst *first = b_.CreateAllocaBPF(b_.getInt64Ty(),
                                           call.func + "_first");
    AllocaInst *second = b_.CreateAllocaBPF(b_.getInt64Ty(),
                                            call.func + "_second");
    Value *perfdata = b_.CreateGetJoinMap(ctx_, call.loc);
    Function *parent = b_.GetInsertBlock()->getParent();

    BasicBlock *zero = BasicBlock::Create(module_->getContext(),
                                          "joinzero",
                                          parent);
    BasicBlock *notzero = BasicBlock::Create(module_->getContext(),
                                             "joinnotzero",
                                             parent);

    b_.CreateCondBr(b_.CreateICmpNE(perfdata,
                                    ConstantExpr::getCast(Instruction::IntToPtr,
                                                          b_.getInt64(0),
                                                          b_.getInt8PtrTy()),
                                    "joinzerocond"),
                    notzero,
                    zero);

    // arg0
    b_.SetInsertPoint(notzero);
    b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::join)), perfdata);
    b_.CreateStore(b_.getInt64(join_id_),
                   b_.CreateGEP(perfdata, b_.getInt64(8)));
    join_id_++;
    AllocaInst *arr = b_.CreateAllocaBPF(b_.getInt64Ty(), call.func + "_r0");
    b_.CreateProbeRead(ctx_, arr, 8, expr_, addrspace, call.loc);
    b_.CreateProbeReadStr(ctx_,
                          b_.CreateAdd(perfdata, b_.getInt64(8 + 8)),
                          bpftrace_.join_argsize_,
                          b_.CreateLoad(arr),
                          addrspace,
                          call.loc);

    for (unsigned int i = 1; i < bpftrace_.join_argnum_; i++)
    {
      // argi
      b_.CreateStore(b_.CreateAdd(expr_, b_.getInt64(8 * i)), first);
      b_.CreateProbeRead(
          ctx_, second, 8, b_.CreateLoad(first), addrspace, call.loc);
      b_.CreateProbeReadStr(
          ctx_,
          b_.CreateAdd(perfdata,
                       b_.getInt64(8 + 8 + i * bpftrace_.join_argsize_)),
          bpftrace_.join_argsize_,
          b_.CreateLoad(second),
          addrspace,
          call.loc);
    }

    // emit
    b_.CreatePerfEventOutput(
        ctx_,
        perfdata,
        8 + 8 + bpftrace_.join_argnum_ * bpftrace_.join_argsize_);

    b_.CreateBr(zero);

    // done
    b_.SetInsertPoint(zero);
    expr_ = nullptr;
  }
  else if (call.func == "ksym")
  {
    // We want expr_ to just pass through from the child node - don't set it here
    auto scoped_del = accept(call.vargs->front());
  }
  else if (call.func == "usym")
  {
    auto scoped_del = accept(call.vargs->front());
    expr_ = b_.CreateUSym(expr_);
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
    std::vector<llvm::Type *> elements = { b_.getInt64Ty(),
                                           ArrayType::get(b_.getInt8Ty(), 16) };
    StructType *inet_struct = b_.GetStructType("inet_t", elements, false);

    AllocaInst *buf = b_.CreateAllocaBPF(inet_struct, "inet");

    Value *af_offset = b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(0) });
    Value *af_type;

    auto inet = call.vargs->at(0);
    if (call.vargs->size() == 1)
    {
      if (inet->type.IsIntegerTy() || inet->type.GetSize() == 4)
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
      auto scoped_del = accept(call.vargs->at(0));
      af_type = b_.CreateIntCast(expr_, b_.getInt64Ty(), true);
    }
    b_.CreateStore(af_type, af_offset);

    Value *inet_offset = b_.CreateGEP(buf, {b_.getInt32(0), b_.getInt32(1)});
    b_.CREATE_MEMSET(inet_offset, b_.getInt8(0), 16, 1);

    auto scoped_del = accept(inet);
    if (inet->type.IsArrayTy() || inet->type.IsStringTy())
    {
      b_.CreateProbeRead(ctx_,
                         static_cast<AllocaInst *>(inet_offset),
                         inet->type.GetSize(),
                         expr_,
                         inet->type.GetAS(),
                         call.loc);
    }
    else
    {
      b_.CreateStore(b_.CreateIntCast(expr_, b_.getInt32Ty(), false),
                     b_.CreatePointerCast(inet_offset,
                                          b_.getInt32Ty()->getPointerTo()));
    }

    expr_ = buf;
    expr_deleter_ = [this, buf]() { b_.CreateLifetimeEnd(buf); };
  }
  else if (call.func == "reg")
  {
    auto reg_name = bpftrace_.get_string_literal(call.vargs->at(0));
    int offset = arch::offset(reg_name);
    if (offset == -1)
    {
      LOG(FATAL) << "negative offset on reg() call";
    }

    Value *ctx = b_.CreatePointerCast(ctx_, b_.getInt64Ty()->getPointerTo());
    expr_ = b_.CreateLoad(b_.getInt64Ty(),
                          b_.CreateGEP(ctx, b_.getInt64(offset)),
                          call.func + "_" + reg_name);
    dyn_cast<LoadInst>(expr_)->setVolatile(true);
  }
  else if (call.func == "printf")
  {
    // We overload printf call for iterator probe's seq_printf helper.
    if (probetype(current_attach_point_->provider) == ProbeType::iter)
    {
      auto mapid = bpftrace_.maps[MapManager::Type::SeqPrintfData].value()->id;
      auto nargs = call.vargs->size() - 1;

      int ptr_size = sizeof(unsigned long);
      int data_size = 0;

      // create buffer to store the argument expression values
      SizedType data_type = CreateBuffer(nargs * 8);
      AllocaInst *data = b_.CreateAllocaBPFInit(data_type, "data");

      for (size_t i = 1; i < call.vargs->size(); i++)
      {
        // process argument expression
        Expression &arg = *call.vargs->at(i);
        auto scoped_del = accept(&arg);

        // and store it to data area
        Value *offset = b_.CreateGEP(
            data, { b_.getInt64(0), b_.getInt64((i - 1) * ptr_size) });
        b_.CreateStore(expr_, offset);

        // keep the expression alive, so it's still there
        // for following seq_printf call
        expr_deleter_ = scoped_del.disarm();
        data_size += ptr_size;
      }

      // pick to current format string
      auto ids = bpftrace_.resources.seq_printf_ids.at(seq_printf_id_);
      auto idx = std::get<0>(ids);
      auto size = std::get<1>(ids);

      // and load it from the map
      Value *map_data = b_.CreateBpfPseudoCallValue(mapid);
      Value *fmt = b_.CreateAdd(map_data, b_.getInt64(idx));

      // and finally the seq_printf call
      b_.CreateSeqPrintf(
          ctx_, fmt, b_.getInt64(size), data, b_.getInt64(data_size), call.loc);

      seq_printf_id_++;
    }
    else
    {
      createFormatStringCall(call,
                             printf_id_,
                             bpftrace_.resources.printf_args,
                             "printf",
                             AsyncAction::printf);
    }
  }
  else if (call.func == "system")
  {
    createFormatStringCall(call,
                           system_id_,
                           bpftrace_.resources.system_args,
                           "system",
                           AsyncAction::syscall);
  }
  else if (call.func == "cat")
  {
    createFormatStringCall(
        call, cat_id_, bpftrace_.resources.cat_args, "cat", AsyncAction::cat);
  }
  else if (call.func == "exit")
  {
    /*
     * perf event output has: uint64_t asyncaction_id
     * The asyncaction_id informs user-space that this is not a printf(), but is a
     * special asynchronous action. The ID maps to exit().
     */
    AllocaInst *perfdata = b_.CreateAllocaBPF(b_.getInt64Ty(), "perfdata");
    b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::exit)), perfdata);
    b_.CreatePerfEventOutput(ctx_, perfdata, sizeof(uint64_t));
    b_.CreateLifetimeEnd(perfdata);
    expr_ = nullptr;
    createRet();

    // create an unreachable basic block for all the "dead instructions" that
    // may come after exit(). If we don't, LLVM will emit the instructions
    // leading to a `unreachable insn` warning from the verifier
    BasicBlock *deadcode = BasicBlock::Create(module_->getContext(),
                                              "deadcode",
                                              b_.GetInsertBlock()->getParent());
    b_.SetInsertPoint(deadcode);
  }
  else if (call.func == "print")
  {
    if (call.vargs->at(0)->is_map)
      createPrintMapCall(call);
    else
      createPrintNonMapCall(call, non_map_print_id_);
  }
  else if (call.func == "clear" || call.func == "zero")
  {
    auto elements = AsyncEvent::MapEvent().asLLVMType(b_);
    StructType *event_struct = b_.GetStructType(call.func + "_t",
                                                elements,
                                                true);

    auto &arg = *call.vargs->at(0);
    auto &map = static_cast<Map&>(arg);

    AllocaInst *buf = b_.CreateAllocaBPF(event_struct,
                                         call.func + "_" + map.ident);

    auto aa_ptr = b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(0) });
    if (call.func == "clear")
      b_.CreateStore(b_.GetIntSameSize(asyncactionint(AsyncAction::clear),
                                       elements.at(0)),
                     aa_ptr);
    else
      b_.CreateStore(b_.GetIntSameSize(asyncactionint(AsyncAction::zero),
                                       elements.at(0)),
                     aa_ptr);

    auto id = bpftrace_.maps[map.ident].value()->id;
    auto *ident_ptr = b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(1) });
    b_.CreateStore(b_.GetIntSameSize(id, elements.at(1)), ident_ptr);

    b_.CreatePerfEventOutput(ctx_, buf, getStructSize(event_struct));
    b_.CreateLifetimeEnd(buf);
    expr_ = nullptr;
  }
  else if (call.func == "time")
  {
    auto elements = AsyncEvent::Time().asLLVMType(b_);
    StructType *time_struct = b_.GetStructType(call.func + "_t",
                                               elements,
                                               true);

    AllocaInst *buf = b_.CreateAllocaBPF(time_struct, call.func + "_t");

    b_.CreateStore(b_.GetIntSameSize(asyncactionint(AsyncAction::time),
                                     elements.at(0)),
                   b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(0) }));

    b_.CreateStore(b_.GetIntSameSize(time_id_, elements.at(1)),
                   b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(1) }));

    time_id_++;
    b_.CreatePerfEventOutput(ctx_, buf, getStructSize(time_struct));
    b_.CreateLifetimeEnd(buf);
    expr_ = nullptr;
  }
  else if (call.func == "strftime")
  {
    auto elements = AsyncEvent::Strftime().asLLVMType(b_);
    StructType *strftime_struct = b_.GetStructType(call.func + "_t",
                                                   elements,
                                                   true);

    AllocaInst *buf = b_.CreateAllocaBPF(strftime_struct, call.func + "_args");
    b_.CreateStore(b_.GetIntSameSize(strftime_id_, elements.at(0)),
                   b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(0) }));
    strftime_id_++;
    Expression *arg = call.vargs->at(1);
    auto scoped_del = accept(arg);
    b_.CreateStore(expr_,
                   b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(1) }));
    expr_ = buf;
  }
  else if (call.func == "kstack" || call.func == "ustack")
  {
    kstack_ustack(call.func, call.type.stack_type, call.loc);
  }
  else if (call.func == "signal") {
    // int bpf_send_signal(u32 sig)
    auto &arg = *call.vargs->at(0);
    if (arg.type.IsStringTy())
    {
      auto signame = bpftrace_.get_string_literal(&arg);
      int sigid = signal_name_to_num(signame);
      // Should be caught in semantic analyser
      if (sigid < 1) {
        LOG(FATAL) << "BUG: Invalid signal ID for \"" << signame << "\"";
      }
      b_.CreateSignal(ctx_, b_.getInt32(sigid), call.loc);
      return;
    }
    auto scoped_del = accept(&arg);
    expr_ = b_.CreateIntCast(expr_, b_.getInt32Ty(), arg.type.IsSigned());
    b_.CreateSignal(ctx_, expr_, call.loc);
  }
  else if (call.func == "sizeof")
  {
    expr_ = b_.getInt64(call.vargs->at(0)->type.GetSize());
  }
  else if (call.func == "strncmp") {
    uint64_t size = static_cast<Integer *>(call.vargs->at(2))->n;
    const auto& left_arg = call.vargs->at(0);
    const auto& right_arg = call.vargs->at(1);
    auto left_as = left_arg->type.GetAS();
    auto right_as = right_arg->type.GetAS();

    // If one of the strings is fixed, we can avoid storing the
    // literal in memory by calling a different function.
    if (right_arg->is_literal)
    {
      auto scoped_del = accept(left_arg);
      Value *left_string = expr_;
      const auto string_literal = bpftrace_.get_string_literal(right_arg);
      expr_ = b_.CreateStrncmp(
          ctx_, left_string, left_as, string_literal, size, call.loc, false);
    }
    else if (left_arg->is_literal)
    {
      auto scoped_del = accept(right_arg);
      Value *right_string = expr_;
      const auto string_literal = bpftrace_.get_string_literal(left_arg);
      expr_ = b_.CreateStrncmp(
          ctx_, right_string, right_as, string_literal, size, call.loc, false);
    }
    else
    {
      auto scoped_del_right = accept(right_arg);
      Value *right_string = expr_;
      auto scoped_del_left = accept(left_arg);
      Value *left_string = expr_;
      expr_ = b_.CreateStrncmp(ctx_,
                               left_string,
                               left_as,
                               right_string,
                               right_as,
                               size,
                               call.loc,
                               false);
    }
  }
  else if (call.func == "override")
  {
    // int bpf_override(struct pt_regs *regs, u64 rc)
    // returns: 0
    auto &arg = *call.vargs->at(0);
    auto scoped_del = accept(&arg);
    expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), arg.type.IsSigned());
    b_.CreateOverrideReturn(ctx_, expr_);
  }
  else if (call.func == "kptr" || call.func == "uptr")
  {
    auto arg = call.vargs->at(0);
    auto scoped_del = accept(arg);
  }
  else if (call.func == "macaddr")
  {
    // MAC addresses are presented as char[6]
    AllocaInst *buf = b_.CreateAllocaBPFInit(call.type, "macaddr");
    auto macaddr = call.vargs->front();
    auto scoped_del = accept(macaddr);

    if (onStack(macaddr->type))
      b_.CREATE_MEMCPY(buf, expr_, macaddr->type.GetSize(), 1);
    else
      b_.CreateProbeRead(ctx_,
                         static_cast<AllocaInst *>(buf),
                         macaddr->type.GetSize(),
                         expr_,
                         macaddr->type.GetAS(),
                         call.loc);

    expr_ = buf;
    expr_deleter_ = [this, buf]() { b_.CreateLifetimeEnd(buf); };
  }
  else if (call.func == "unwatch")
  {
    Expression *addr = call.vargs->at(0);
    addr->accept(*this);

    auto elements = AsyncEvent::WatchpointUnwatch().asLLVMType(b_);
    StructType *unwatch_struct = b_.GetStructType("unwatch_t", elements, true);
    AllocaInst *buf = b_.CreateAllocaBPF(unwatch_struct, "unwatch");
    size_t struct_size = datalayout().getTypeAllocSize(unwatch_struct);

    b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::watchpoint_detach)),
                   b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(0) }));
    b_.CreateStore(
        b_.CreateIntCast(expr_, b_.getInt64Ty(), false /* unsigned */),
        b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(1) }));
    b_.CreatePerfEventOutput(ctx_, buf, struct_size);
    b_.CreateLifetimeEnd(buf);
    expr_ = nullptr;
  }
  else
  {
    LOG(FATAL) << "missing codegen for function \"" << call.func << "\"";
  }
}

void CodegenLLVM::visit(Map &map)
{
  auto [key, scoped_key_deleter] = getMapKey(map);
  Value *value = b_.CreateMapLookupElem(ctx_, map, key, map.loc);
  expr_ = value;

  if (dyn_cast<AllocaInst>(value))
    expr_deleter_ = [this, value]() { b_.CreateLifetimeEnd(value); };
}

void CodegenLLVM::visit(Variable &var)
{
  // Arrays and structs are not memcopied for local variables
  if (needMemcpy(var.type) && !(var.type.IsArrayTy() || var.type.IsRecordTy()))
  {
    expr_ = variables_[var.ident];
  }
  else
  {
    expr_ = b_.CreateLoad(variables_[var.ident]);
  }
}

void CodegenLLVM::binop_string(Binop &binop)
{
  if (binop.op != bpftrace::Parser::token::EQ &&
      binop.op != bpftrace::Parser::token::NE)
  {
    LOG(FATAL) << "missing codegen to string operator \"" << opstr(binop)
               << "\"";
  }

  std::string string_literal;

  // strcmp returns 0 when strings are equal
  bool inverse = binop.op == bpftrace::Parser::token::EQ;

  auto left_as = binop.left->type.GetAS();
  auto right_as = binop.right->type.GetAS();

  // If one of the strings is fixed, we can avoid storing the
  // literal in memory by calling a different function.
  if (binop.right->is_literal)
  {
    auto scoped_del = accept(binop.left);
    string_literal = bpftrace_.get_string_literal(binop.right);
    expr_ = b_.CreateStrcmp(
        ctx_, expr_, left_as, string_literal, binop.loc, inverse);
  }
  else if (binop.left->is_literal)
  {
    auto scoped_del = accept(binop.right);
    string_literal = bpftrace_.get_string_literal(binop.left);
    expr_ = b_.CreateStrcmp(
        ctx_, expr_, right_as, string_literal, binop.loc, inverse);
  }
  else
  {
    auto scoped_del_right = accept(binop.right);
    Value *right_string = expr_;

    auto scoped_del_left = accept(binop.left);
    Value *left_string = expr_;

    size_t len = std::min(binop.left->type.GetSize(),
                          binop.right->type.GetSize());
    expr_ = b_.CreateStrncmp(ctx_,
                             left_string,
                             left_as,
                             right_string,
                             right_as,
                             len + 1,
                             binop.loc,
                             inverse);
  }
}

void CodegenLLVM::binop_buf(Binop &binop)
{
  if (binop.op != bpftrace::Parser::token::EQ &&
      binop.op != bpftrace::Parser::token::NE)
  {
    LOG(FATAL) << "missing codegen to buffer operator \"" << opstr(binop)
               << "\"";
  }

  std::string string_literal("");

  // strcmp returns 0 when strings are equal
  bool inverse = binop.op == bpftrace::Parser::token::EQ;

  auto scoped_del_right = accept(binop.right);
  Value *right_string = expr_;
  auto right_as = binop.right->type.GetAS();

  auto scoped_del_left = accept(binop.left);
  Value *left_string = expr_;
  auto left_as = binop.left->type.GetAS();

  size_t len = std::min(binop.left->type.GetSize(),
                        binop.right->type.GetSize());
  expr_ = b_.CreateStrncmp(ctx_,
                           left_string,
                           left_as,
                           right_string,
                           right_as,
                           len,
                           binop.loc,
                           inverse);
}

void CodegenLLVM::binop_int(Binop &binop)
{
  Value *lhs, *rhs;
  auto scoped_del_left = accept(binop.left);
  lhs = expr_;
  auto scoped_del_right = accept(binop.right);
  rhs = expr_;

  // If left or right is PositionalParameter, that means the syntax is
  // str($1 + num) or str(num + $1). The positional params returns a pointer
  // to a buffer, and the buffer should live untill str() is accepted.
  // Extend the liftime of the buffer
  if (dynamic_cast<PositionalParameter *>(binop.left))
    expr_deleter_ = scoped_del_left.disarm();
  if (dynamic_cast<PositionalParameter *>(binop.right))
    expr_deleter_ = scoped_del_right.disarm();

  bool lsign = binop.left->type.IsSigned();
  bool rsign = binop.right->type.IsSigned();
  bool do_signed = lsign && rsign;
  // promote int to 64-bit
  lhs = b_.CreateIntCast(lhs, b_.getInt64Ty(), lsign);
  rhs = b_.CreateIntCast(rhs, b_.getInt64Ty(), rsign);

  switch (binop.op)
  {
    case bpftrace::Parser::token::EQ:
      expr_ = b_.CreateICmpEQ(lhs, rhs);
      break;
    case bpftrace::Parser::token::NE:
      expr_ = b_.CreateICmpNE(lhs, rhs);
      break;
    case bpftrace::Parser::token::LE:
    {
      expr_ = do_signed ? b_.CreateICmpSLE(lhs, rhs)
                        : b_.CreateICmpULE(lhs, rhs);
      break;
    }
    case bpftrace::Parser::token::GE:
    {
      expr_ = do_signed ? b_.CreateICmpSGE(lhs, rhs)
                        : b_.CreateICmpUGE(lhs, rhs);
      break;
    }
    case bpftrace::Parser::token::LT:
    {
      expr_ = do_signed ? b_.CreateICmpSLT(lhs, rhs)
                        : b_.CreateICmpULT(lhs, rhs);
      break;
    }
    case bpftrace::Parser::token::GT:
    {
      expr_ = do_signed ? b_.CreateICmpSGT(lhs, rhs)
                        : b_.CreateICmpUGT(lhs, rhs);
      break;
    }
    case bpftrace::Parser::token::LEFT:
      expr_ = b_.CreateShl(lhs, rhs);
      break;
    case bpftrace::Parser::token::RIGHT:
      expr_ = b_.CreateLShr(lhs, rhs);
      break;
    case bpftrace::Parser::token::PLUS:
      expr_ = b_.CreateAdd(lhs, rhs);
      break;
    case bpftrace::Parser::token::MINUS:
      expr_ = b_.CreateSub(lhs, rhs);
      break;
    case bpftrace::Parser::token::MUL:
      expr_ = b_.CreateMul(lhs, rhs);
      break;
    case bpftrace::Parser::token::DIV:
      expr_ = b_.CreateUDiv(lhs, rhs);
      break;
    case bpftrace::Parser::token::MOD:
    {
      // Always do an unsigned modulo operation here even if `do_signed`
      // is true. bpf instruction set does not support signed division.
      // We already warn in the semantic analyser that signed modulo can
      // lead to undefined behavior (because we will treat it as unsigned).
      expr_ = b_.CreateURem(lhs, rhs);
      break;
    }
    case bpftrace::Parser::token::BAND:
      expr_ = b_.CreateAnd(lhs, rhs);
      break;
    case bpftrace::Parser::token::BOR:
      expr_ = b_.CreateOr(lhs, rhs);
      break;
    case bpftrace::Parser::token::BXOR:
      expr_ = b_.CreateXor(lhs, rhs);
      break;
    case bpftrace::Parser::token::LAND:
    case bpftrace::Parser::token::LOR:
      LOG(FATAL) << "\"" << opstr(binop) << "\" was handled earlier";
  }
  // Using signed extension will result in -1 which will likely confuse users
  expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), false);
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

  SizedType &type = binop.left->type;
  if (type.IsStringTy())
  {
    binop_string(binop);
  }
  else if (type.IsBufferTy())
  {
    binop_buf(binop);
  }
  else
  {
    binop_int(binop);
  }
}

static bool unop_skip_accept(Unop &unop)
{
  if (unop.expr->type.IsIntTy())
  {
    if (unop.op == bpftrace::Parser::token::INCREMENT ||
        unop.op == bpftrace::Parser::token::DECREMENT)
      return unop.expr->is_map || unop.expr->is_variable;
  }

  return false;
}

void CodegenLLVM::visit(Unop &unop)
{
  auto scoped_del = ScopedExprDeleter(nullptr);
  if (!unop_skip_accept(unop))
    scoped_del = accept(unop.expr);

  SizedType &type = unop.expr->type;
  if (type.IsIntegerTy())
  {
    switch (unop.op)
    {
      case bpftrace::Parser::token::LNOT:
      {
        auto ty = expr_->getType();
        Value *zero_value = Constant::getNullValue(ty);
        expr_ = b_.CreateICmpEQ(expr_, zero_value);
        // CreateICmpEQ() returns 1-bit integer
        // Cast it to the same type of the operand
        // Use unsigned extention, otherwise !0 becomes -1
        expr_ = b_.CreateIntCast(expr_, ty, false);
        break;
      }
      case bpftrace::Parser::token::BNOT: expr_ = b_.CreateNot(expr_); break;
      case bpftrace::Parser::token::MINUS: expr_ = b_.CreateNeg(expr_); break;
      case bpftrace::Parser::token::INCREMENT:
      case bpftrace::Parser::token::DECREMENT:
      {
        bool is_increment = unop.op == bpftrace::Parser::token::INCREMENT;

        if (unop.expr->is_map)
        {
          Map &map = static_cast<Map&>(*unop.expr);
          auto [key, scoped_key_deleter] = getMapKey(map);
          Value *oldval = b_.CreateMapLookupElem(ctx_, map, key, unop.loc);
          AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_newval");
          if (is_increment)
            b_.CreateStore(b_.CreateAdd(oldval, b_.getInt64(1)), newval);
          else
            b_.CreateStore(b_.CreateSub(oldval, b_.getInt64(1)), newval);
          b_.CreateMapUpdateElem(ctx_, map, key, newval, unop.loc);

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
          LOG(FATAL) << "invalid expression passed to " << opstr(unop);
        }
        break;
      }
      case bpftrace::Parser::token::MUL:
      {
        // When dereferencing a 32-bit integer, only read in 32-bits, etc.
        int size = type.IsPtrTy() ? type.GetPointeeTy()->GetSize()
                                  : type.GetSize();
        auto as =  type.GetAS();

        AllocaInst *dst = b_.CreateAllocaBPF(SizedType(type.type, size), "deref");
        b_.CreateProbeRead(ctx_, dst, size, expr_, as, unop.loc);
        expr_ = b_.CreateIntCast(b_.CreateLoad(dst),
                                 b_.getInt64Ty(),
                                 type.IsSigned());
        b_.CreateLifetimeEnd(dst);
        break;
      }
    }
  }
  else if (type.IsPtrTy())
  {
    switch (unop.op)
    {
      case bpftrace::Parser::token::MUL:
      {
        if (unop.type.IsIntegerTy() || unop.type.IsPtrTy())
        {
          auto *et = type.GetPointeeTy();
          // Pointer always 64 bits wide
          int size = unop.type.IsIntegerTy() ? et->GetIntBitWidth() / 8 : 8;
          AllocaInst *dst = b_.CreateAllocaBPF(*et, "deref");
          b_.CreateProbeRead(ctx_, dst, size, expr_, type.GetAS(), unop.loc);
          expr_ = b_.CreateIntCast(b_.CreateLoad(dst),
                                   b_.getInt64Ty(),
                                   unop.type.IsSigned());
          b_.CreateLifetimeEnd(dst);
        }
        break;
      }
      default:; // Do nothing
    }
  }
  else
  {
    LOG(FATAL) << "invalid type (" << type << ") passed to unary operator \""
               << opstr(unop) << "\"";
  }
}

void CodegenLLVM::visit(Ternary &ternary)
{
  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *left_block = BasicBlock::Create(module_->getContext(), "left", parent);
  BasicBlock *right_block = BasicBlock::Create(module_->getContext(), "right", parent);
  BasicBlock *done = BasicBlock::Create(module_->getContext(), "done", parent);
  // ordering of all the following statements is important
  Value *result = ternary.type.IsNoneTy()
                      ? nullptr
                      : b_.CreateAllocaBPF(ternary.type, "result");
  AllocaInst *buf = ternary.type.IsNoneTy()
                        ? nullptr
                        : b_.CreateAllocaBPF(ternary.type, "buf");
  Value *cond;
  auto scoped_del = accept(ternary.cond);
  cond = expr_;
  Value *zero_value = Constant::getNullValue(cond->getType());
  b_.CreateCondBr(b_.CreateICmpNE(cond, zero_value, "true_cond"),
                  left_block,
                  right_block);

  if (ternary.type.IsIntTy())
  {
    // fetch selected integer via CreateStore
    b_.SetInsertPoint(left_block);
    auto scoped_del_left = accept(ternary.left);
    expr_ = b_.CreateIntCast(expr_,
                             b_.GetType(ternary.type),
                             ternary.type.IsSigned());
    b_.CreateStore(expr_, result);
    b_.CreateBr(done);

    b_.SetInsertPoint(right_block);
    auto scoped_del_right = accept(ternary.right);
    expr_ = b_.CreateIntCast(expr_,
                             b_.GetType(ternary.type),
                             ternary.type.IsSigned());
    b_.CreateStore(expr_, result);
    b_.CreateBr(done);

    b_.SetInsertPoint(done);
    expr_ = b_.CreateLoad(result);
  }
  else if (ternary.type.IsStringTy())
  {
    // copy selected string via CreateMemCpy
    b_.SetInsertPoint(left_block);
    auto scoped_del_left = accept(ternary.left);
    b_.CREATE_MEMCPY(buf, expr_, ternary.type.GetSize(), 1);
    b_.CreateBr(done);

    b_.SetInsertPoint(right_block);
    auto scoped_del_right = accept(ternary.right);
    b_.CREATE_MEMCPY(buf, expr_, ternary.type.GetSize(), 1);
    b_.CreateBr(done);

    b_.SetInsertPoint(done);
    expr_ = buf;
    expr_deleter_ = [this, buf]() { b_.CreateLifetimeEnd(buf); };
  }
  else
  {
    // Type::none
    b_.SetInsertPoint(left_block);
    {
      auto scoped_del = accept(ternary.left);
    }
    b_.CreateBr(done);
    b_.SetInsertPoint(right_block);
    {
      auto scoped_del = accept(ternary.right);
    }
    b_.CreateBr(done);
    b_.SetInsertPoint(done);
    expr_ = nullptr;
  }
}

void CodegenLLVM::visit(FieldAccess &acc)
{
  SizedType &type = acc.expr->type;
  AddrSpace addrspace = acc.expr->type.GetAS();
  assert(type.IsRecordTy() || type.IsTupleTy());
  auto scoped_del = accept(acc.expr);

  bool is_ctx = type.IsCtxAccess();
  bool is_tparg = type.is_tparg;
  bool is_internal = type.is_internal;
  bool is_kfarg = type.is_kfarg;
  assert(type.IsRecordTy() || type.IsTupleTy());

  if (type.is_kfarg)
  {
    expr_ = b_.CreatKFuncArg(ctx_, acc.type, acc.field);
    return;
  }
  else if (type.IsTupleTy())
  {
    Value *src = b_.CreateGEP(expr_,
                              { b_.getInt32(0), b_.getInt32(acc.index) });
    SizedType &elem_type = type.GetFields()[acc.index].type;

    if (shouldBeOnStackAlready(elem_type))
    {
      expr_ = src;
      // Extend lifetime of source buffer
      expr_deleter_ = scoped_del.disarm();
    }
    else
      expr_ = b_.CreateLoad(b_.GetType(elem_type), src);

    return;
  }

  std::string cast_type = is_tparg ? tracepoint_struct_ : type.GetName();

  // This overwrites the stored type!
  type = CreateRecord(cast_type, bpftrace_.structs.Lookup(cast_type));
  if (is_ctx)
    type.MarkCtxAccess();
  type.is_tparg = is_tparg;
  type.is_internal = is_internal;
  type.is_kfarg = is_kfarg;
  // Restore the addrspace info
  // struct MyStruct { const int* a; };  $s = (struct MyStruct *)arg0;  $s->a
  type.SetAS(addrspace);

  auto &field = type.GetField(acc.field);

  if (onStack(type))
  {
    readDatastructElemFromStack(
        expr_, b_.getInt64(field.offset), type, field.type, scoped_del);
  }
  else
  {
    // Structs may contain two kinds of fields that must be handled separately
    // (bitfields and _data_loc)
    if (field.type.IsIntTy() && (field.is_bitfield || field.is_data_loc))
    {
      Value *src = b_.CreateAdd(expr_, b_.getInt64(field.offset));

      if (field.is_bitfield)
      {
        Value *raw;
        if (type.IsCtxAccess())
          raw = b_.CreateLoad(
              b_.CreateIntToPtr(src, b_.GetType(field.type)->getPointerTo()),
              true);
        else
        {
          AllocaInst *dst = b_.CreateAllocaBPF(field.type,
                                               type.GetName() + "." +
                                                   acc.field);
          // memset so verifier doesn't complain about reading uninitialized
          // stack
          b_.CREATE_MEMSET(dst, b_.getInt8(0), field.type.GetSize(), 1);
          b_.CreateProbeRead(
              ctx_, dst, field.bitfield.read_bytes, src, type.GetAS(), acc.loc);
          raw = b_.CreateLoad(dst);
          b_.CreateLifetimeEnd(dst);
        }
        size_t rshiftbits;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        rshiftbits = field.bitfield.access_rshift;
#else
        rshiftbits = (field.type.GetSize() - field.bitfield.read_bytes) * 8;
        rshiftbits += field.bitfield.access_rshift;
#endif
        Value *shifted = b_.CreateLShr(raw, rshiftbits);
        Value *masked = b_.CreateAnd(shifted, field.bitfield.mask);
        expr_ = masked;
      }
      else
      {
        // `is_data_loc` should only be set if field access is on `args` which
        // has to be a ctx access
        assert(type.IsCtxAccess());
        assert(ctx_->getType() == b_.getInt8PtrTy());
        // Parser needs to have rewritten field to be a u64
        assert(field.type.IsIntTy());
        assert(field.type.GetIntBitWidth() == 64);

        // Top 2 bytes are length (which we'll ignore). Bottom two bytes are
        // offset which we add to the start of the tracepoint struct.
        expr_ = b_.CreateLoad(
            b_.getInt32Ty(),
            b_.CreateGEP(b_.CreatePointerCast(ctx_,
                                              b_.getInt32Ty()->getPointerTo()),
                         b_.getInt64(field.offset / 4)));
        expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), false);
        expr_ = b_.CreateAnd(expr_, b_.getInt64(0xFFFF));
        expr_ = b_.CreateAdd(expr_, b_.CreatePtrToInt(ctx_, b_.getInt64Ty()));
      }
    }
    else
    {
      probereadDatastructElem(expr_,
                              b_.getInt64(field.offset),
                              type,
                              field.type,
                              scoped_del,
                              acc.loc,
                              type.GetName() + "." + acc.field);
    }
  }
}

void CodegenLLVM::visit(ArrayAccess &arr)
{
  SizedType &type = arr.expr->type;
  auto elem_type = type.IsArrayTy() ? *type.GetElementTy()
                                    : *type.GetPointeeTy();
  size_t elem_size = elem_type.GetSize();

  auto scoped_del_expr = accept(arr.expr);
  Value *array = expr_;

  auto scoped_del_index = accept(arr.indexpr);

  if (onStack(type))
    readDatastructElemFromStack(array, expr_, type, elem_type, scoped_del_expr);
  else
  {
    if (array->getType()->isPointerTy())
      array = b_.CreatePtrToInt(array, b_.getInt64Ty());

    Value *index = b_.CreateIntCast(expr_, b_.getInt64Ty(), type.IsSigned());
    Value *offset = b_.CreateMul(index, b_.getInt64(elem_size));

    probereadDatastructElem(array,
                            offset,
                            type,
                            elem_type,
                            scoped_del_expr,
                            arr.loc,
                            "array_access");
  }
}

void CodegenLLVM::visit(Cast &cast)
{
  auto scoped_del = accept(cast.expr);
  if (cast.type.IsIntTy())
  {
    expr_ = b_.CreateIntCast(expr_,
                             b_.getIntNTy(8 * cast.type.GetSize()),
                             cast.type.IsSigned(),
                             "cast");
  }
}

void CodegenLLVM::compareStructure(SizedType &our_type, llvm::Type *llvm_type)
{
  // Validate that what we thought the struct looks like
  // and LLVM made of it are equal to avoid issues.
  //
  // As the size is used throughout the semantic phase for
  // sizing buffers and maps we have to abort if it doesn't
  // match.
  // But offset is only used for printing, so we can recover
  // from that by storing the correct offset.
  //
  size_t our_size = our_type.GetSize();
  size_t llvm_size = datalayout().getTypeAllocSize(llvm_type);

  if (llvm_size != our_size)
  {
    LOG(FATAL) << "BUG: Struct size mismatch: expected: " << our_size
               << ", real: " << llvm_size;
  }

  auto *layout = datalayout().getStructLayout(
      reinterpret_cast<llvm::StructType *>(llvm_type));

  for (ssize_t i = 0; i < our_type.GetFieldCount(); i++)
  {
    ssize_t llvm_offset = layout->getElementOffset(i);
    auto &field = our_type.GetField(i);
    ssize_t our_offset = field.offset;
    if (llvm_offset != our_offset)
    {
      LOG(DEBUG) << "Struct offset mismatch for: " << field.type << "(" << i
                 << ")"
                 << ": (llvm) " << llvm_offset << " != " << our_offset;

      field.offset = llvm_offset;
    }
  }
}

void CodegenLLVM::visit(Tuple &tuple)
{
  // Store elements on stack
  llvm::Type *tuple_ty = b_.GetType(tuple.type);

  compareStructure(tuple.type, tuple_ty);

  size_t tuple_size = datalayout().getTypeAllocSize(tuple_ty);
  AllocaInst *buf = b_.CreateAllocaBPF(tuple_ty, "tuple");
  b_.CREATE_MEMSET(buf, b_.getInt8(0), tuple_size, 1);
  for (size_t i = 0; i < tuple.elems->size(); ++i)
  {
    Expression *elem = tuple.elems->at(i);
    auto scoped_del = accept(elem);

    Value *dst = b_.CreateGEP(buf, { b_.getInt32(0), b_.getInt32(i) });

    if (onStack(elem->type))
      b_.CREATE_MEMCPY(dst, expr_, elem->type.GetSize(), 1);
    else if (elem->type.IsArrayTy() || elem->type.IsRecordTy())
      b_.CreateProbeRead(ctx_,
                         dst,
                         elem->type.GetSize(),
                         expr_,
                         elem->type.GetAS(),
                         elem->loc);
    else
      b_.CreateStore(expr_, dst);
  }

  expr_ = buf;
  expr_deleter_ = [this, buf]() { b_.CreateLifetimeEnd(buf); };
}

void CodegenLLVM::visit(ExprStatement &expr)
{
  auto scoped_del = accept(expr.expr);
}

void CodegenLLVM::visit(AssignMapStatement &assignment)
{
  Map &map = *assignment.map;
  auto scoped_del = accept(assignment.expr);
  bool self_alloca = false;

  if (!expr_) // Some functions do the assignments themselves
    return;

  Value *val, *expr;
  expr = expr_;
  auto [key, scoped_key_deleter] = getMapKey(map);
  if (shouldBeOnStackAlready(assignment.expr->type))
  {
    val = expr;
  }
  else if (map.type.IsRecordTy() || map.type.IsArrayTy())
  {
    if (assignment.expr->type.is_internal)
    {
      val = expr;
    }
    else
    {
      // expr currently contains a pointer to the struct or array
      // We now want to read the entire struct/array in so we can save it
      AllocaInst *dst = b_.CreateAllocaBPF(map.type, map.ident + "_val");
      b_.CreateProbeRead(ctx_,
                         dst,
                         map.type.GetSize(),
                         expr,
                         assignment.expr->type.GetAS(),
                         assignment.loc);
      val = dst;
      self_alloca = true;
    }
  }
  else if (map.type.IsPtrTy())
  {
    // expr currently contains a pointer to the struct
    // and that's what we are saving
    AllocaInst *dst = b_.CreateAllocaBPF(map.type, map.ident + "_ptr");
    b_.CreateStore(expr, dst);
    val = dst;
    self_alloca = true;
  }
  else
  {
    if (map.type.IsIntTy())
    {
      // Integers are always stored as 64-bit in map values
      expr = b_.CreateIntCast(expr, b_.getInt64Ty(), map.type.IsSigned());
    }
    val = b_.CreateAllocaBPF(map.type, map.ident + "_val");
    b_.CreateStore(expr, val);
    self_alloca = true;
  }
  b_.CreateMapUpdateElem(ctx_, map, key, val, assignment.loc);
  if (self_alloca)
    b_.CreateLifetimeEnd(val);
}

void CodegenLLVM::visit(AssignVarStatement &assignment)
{
  Variable &var = *assignment.var;

  auto scoped_del = accept(assignment.expr);

  if (variables_.find(var.ident) == variables_.end())
  {
    SizedType alloca_type = var.type;

    // Arrays and structs need not to be copied when assigned to local variables
    // since they are treated as read-only - it is sufficient to assign
    // the pointer and do the memcpy/proberead later when necessary
    if (var.type.IsArrayTy() || var.type.IsRecordTy())
    {
      auto &pointee_type = var.type.IsArrayTy() ? *var.type.GetElementTy()
                                                : var.type;
      alloca_type = CreatePointer(pointee_type, var.type.GetAS());
    }

    AllocaInst *val = b_.CreateAllocaBPFInit(alloca_type, var.ident);
    variables_[var.ident] = val;
  }

  if (var.type.IsArrayTy() || var.type.IsRecordTy())
  {
    // For arrays and structs, only the pointer is stored
    b_.CreateStore(b_.CreatePtrToInt(expr_, b_.getInt64Ty()),
                   variables_[var.ident]);
    // Extend lifetime of RHS up to the end of probe
    scoped_del.disarm();
  }
  else if (needMemcpy(var.type))
  {
    b_.CREATE_MEMCPY(variables_[var.ident], expr_, var.type.GetSize(), 1);
  }
  else
  {
    b_.CreateStore(expr_, variables_[var.ident]);
  }
}

void CodegenLLVM::visit(If &if_block)
{
  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *if_true = BasicBlock::Create(module_->getContext(),
                                           "if_body",
                                           parent);
  BasicBlock *if_end = BasicBlock::Create(module_->getContext(),
                                          "if_end",
                                          parent);
  BasicBlock *if_else = nullptr;

  auto scoped_del = accept(if_block.cond);
  Value *zero_value = Constant::getNullValue(expr_->getType());
  Value *cond = b_.CreateICmpNE(expr_, zero_value, "true_cond");

  // 3 possible flows:
  //
  // if condition is true
  //   parent -> if_body -> if_end
  //
  // if condition is false, no else
  //   parent -> if_end
  //
  // if condition is false, with else
  //   parent -> if_else -> if_end
  //
  if (if_block.else_stmts)
  {
    // LLVM doesn't accept empty basic block, only create when needed
    if_else = BasicBlock::Create(module_->getContext(), "else_body", parent);
    b_.CreateCondBr(cond, if_true, if_else);
  }
  else
  {
    b_.CreateCondBr(cond, if_true, if_end);
  }

  b_.SetInsertPoint(if_true);
  for (Statement *stmt : *if_block.stmts)
    auto scoped_del = accept(stmt);

  b_.CreateBr(if_end);

  b_.SetInsertPoint(if_end);

  if (if_block.else_stmts)
  {
    b_.SetInsertPoint(if_else);
    for (Statement *stmt : *if_block.else_stmts)
      auto scoped_del = accept(stmt);

    b_.CreateBr(if_end);
    b_.SetInsertPoint(if_end);
  }
}

void CodegenLLVM::visit(Unroll &unroll)
{
  for (int i=0; i < unroll.var; i++) {
    for (Statement *stmt : *unroll.stmts)
    {
      auto scoped_del = accept(stmt);
    }
  }
}

void CodegenLLVM::visit(Jump &jump)
{
  switch (jump.ident)
  {
    case bpftrace::Parser::token::RETURN:
      // return can be used outside of loops
      createRet();
      break;
    case bpftrace::Parser::token::BREAK:
      b_.CreateBr(std::get<1>(loops_.back()));
      break;
    case bpftrace::Parser::token::CONTINUE:
      b_.CreateBr(std::get<0>(loops_.back()));
      break;
  }

  // LLVM doesn't like having instructions after an unconditional branch (segv)
  // This can be avoided by putting all instructions in a unreachable basicblock
  // which will be optimize out.
  //
  // e.g. in the case of `while (..) { $i++; break; $i++ }` the ir will be:
  //
  // while_body:
  //   ...
  //   br label %while_end
  //
  // while_end:
  //   ...
  //
  // unreach:
  //   $i++
  //   br label %while_cond
  //

  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *unreach = BasicBlock::Create(module_->getContext(),
                                           "unreach",
                                           parent);
  b_.SetInsertPoint(unreach);
}

void CodegenLLVM::visit(While &while_block)
{
  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *while_cond = BasicBlock::Create(module_->getContext(),
                                              "while_cond",
                                              parent);
  BasicBlock *while_body = BasicBlock::Create(module_->getContext(),
                                              "while_body",
                                              parent);
  BasicBlock *while_end = BasicBlock::Create(module_->getContext(),
                                             "while_end",
                                             parent);

  loops_.push_back(std::make_tuple(while_cond, while_end));

  b_.CreateBr(while_cond);

  b_.SetInsertPoint(while_cond);
  auto scoped_del = accept(while_block.cond);
  Value *zero_value = Constant::getNullValue(expr_->getType());
  auto *cond = b_.CreateICmpNE(expr_, zero_value, "true_cond");
  b_.CreateCondBr(cond, while_body, while_end);

  b_.SetInsertPoint(while_body);
  for (Statement *stmt : *while_block.stmts)
  {
    auto scoped_del = accept(stmt);
  }
  b_.CreateBr(while_cond);

  b_.SetInsertPoint(while_end);
  loops_.pop_back();
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

  auto scoped_del = accept(pred.expr);

  // allow unop casts in predicates:
  expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), false);

  expr_ = b_.CreateICmpEQ(expr_, b_.getInt64(0), "predcond");

  b_.CreateCondBr(expr_, pred_false_block, pred_true_block);
  b_.SetInsertPoint(pred_false_block);
  createRet();

  b_.SetInsertPoint(pred_true_block);
}

void CodegenLLVM::visit(AttachPoint &)
{
  // Empty
}

void CodegenLLVM::generateProbe(Probe &probe,
                                const std::string &full_func_id,
                                const std::string &section_name,
                                FunctionType *func_type,
                                bool expansion,
                                std::optional<int> usdt_location_index)
{
  // tracepoint wildcard expansion, part 3 of 3. Set tracepoint_struct_ for use
  // by args builtin.
  if (probetype(current_attach_point_->provider) == ProbeType::tracepoint)
    tracepoint_struct_ = TracepointFormatParser::get_struct_name(full_func_id);
  int index = getNextIndexForProbe(probe.name());
  if (expansion)
    current_attach_point_->set_index(full_func_id, index);
  else
    probe.set_index(index);
  Function *func = Function::Create(
      func_type, Function::ExternalLinkage, section_name, module_.get());
  func->setSection(
      get_section_name_for_probe(section_name, index, usdt_location_index));
  BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", func);
  b_.SetInsertPoint(entry);

  // check: do the following 8 lines need to be in the wildcard loop?
  ctx_ = func->arg_begin();
  if (probe.pred)
  {
    auto scoped_del = accept(probe.pred);
  }
  variables_.clear();
  for (Statement *stmt : *probe.stmts)
  {
    auto scoped_del = accept(stmt);
  }
  createRet();

  auto pt = probetype(current_attach_point_->provider);
  if ((pt == ProbeType::watchpoint || pt == ProbeType::asyncwatchpoint) &&
      current_attach_point_->func.size())
    generateWatchpointSetupProbe(
        func_type, section_name, current_attach_point_->address, index);
}

void CodegenLLVM::createRet(Value *value)
{
  // If value is explicitly provided, use it
  if (value)
  {
    b_.CreateRet(value);
    return;
  }

  // Fall back to default return value
  switch (probetype(current_attach_point_->provider))
  {
    case ProbeType::invalid:
      LOG(FATAL) << "Returning from invalid probetype";
      break;
    case ProbeType::tracepoint:
      // Classic (ie. *not* raw) tracepoints have a kernel quirk stopping perf
      // subsystem from seeing a tracepoint event if BPF program returns 0.
      // This breaks perf in some situations and generally makes such BPF
      // programs bad citizens. Return 1 instead.
      b_.CreateRet(b_.getInt64(1));
      break;
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::software:
    case ProbeType::hardware:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
    case ProbeType::kfunc:
    case ProbeType::kretfunc:
    case ProbeType::iter:
      b_.CreateRet(b_.getInt64(0));
      break;
  }
}

void CodegenLLVM::visit(Probe &probe)
{
  FunctionType *func_type = FunctionType::get(
      b_.getInt64Ty(),
      {b_.getInt8PtrTy()}, // struct pt_regs *ctx
      false);

  // Probe has at least one attach point (required by the parser)
  auto &attach_point = (*probe.attach_points)[0];

  // All usdt probes need expansion to be able to read arguments
  if (probetype(attach_point->provider) == ProbeType::usdt)
    probe.need_expansion = true;

  current_attach_point_ = attach_point;

  /*
   * Most of the time, we can take a probe like kprobe:do_f* and build a
   * single BPF program for that, called "s_kprobe:do_f*", and attach it to
   * each wildcard match. An exception is the "probe" builtin, where we need
   * to build different BPF programs for each wildcard match that cantains an
   * ID for the match. Those programs will be called "s_kprobe:do_fcntl" etc.
   */
  if (probe.need_expansion == false) {
    // build a single BPF program pre-wildcards
    probefull_ = probe.name();
    generateProbe(probe, probefull_, probefull_, func_type, false);
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
    int starting_strftime_id = strftime_id_;
    int starting_join_id = join_id_;
    int starting_helper_error_id = b_.helper_error_id_;
    int starting_non_map_print_id = non_map_print_id_;
    int starting_seq_printf_id = seq_printf_id_;

    auto reset_ids = [&]() {
      printf_id_ = starting_printf_id;
      cat_id_ = starting_cat_id;
      system_id_ = starting_system_id;
      time_id_ = starting_time_id;
      strftime_id_ = starting_strftime_id;
      join_id_ = starting_join_id;
      b_.helper_error_id_ = starting_helper_error_id;
      non_map_print_id_ = starting_non_map_print_id;
      seq_printf_id_ = starting_seq_printf_id;
    };

    for (auto attach_point : *probe.attach_points) {
      current_attach_point_ = attach_point;

      std::set<std::string> matches;
      if (attach_point->provider == "BEGIN" || attach_point->provider == "END") {
        matches.insert(attach_point->provider);
      } else {
        matches = bpftrace_.probe_matcher_->get_matches_for_ap(*attach_point);
      }

      tracepoint_struct_ = "";
      for (const auto &m : matches)
      {
        reset_ids();
        std::string match = m;

        // USDT probes must specify a target binary path, a provider,
        // and a function name.
        // So we will extract out the path and the provider namespace to get
        // just the function name.
        if (probetype(attach_point->provider) == ProbeType::usdt) {
          std::string func_id = match;
          std::string target = erase_prefix(func_id);
          std::string ns = erase_prefix(func_id);

          std::string orig_target = attach_point->target;
          std::string orig_ns = attach_point->ns;

          // Ensure that the full probe name used is the resolved one for this
          // probe.
          attach_point->target = target;
          attach_point->ns = ns;
          probefull_ = attach_point->name(func_id);

          // Set the probe identifier so that we can read arguments later
          auto usdt = USDTHelper::find(bpftrace_.pid(), target, ns, func_id);
          if (!usdt.has_value())
            throw std::runtime_error("Failed to find usdt probe: " +
                                     probefull_);
          attach_point->usdt = *usdt;

          // A "unique" USDT probe can be present in a binary in multiple
          // locations. One case where this happens is if a function containing
          // a USDT probe is inlined into a caller. So we must generate a new
          // program for each instance. We _must_ regenerate because argument
          // locations may differ between instance locations (eg arg0. may not
          // be found in the same offset from the same register in each
          // location)
          current_usdt_location_index_ = 0;
          for (int i = 0; i < attach_point->usdt.num_locations; ++i)
          {
            reset_ids();

            std::string full_func_id = match + "_loc" + std::to_string(i);
            generateProbe(probe, full_func_id, probefull_, func_type, true, i);
            current_usdt_location_index_++;
          }

          // Propagate the originally specified target and namespace in case
          // they contain a wildcard.
          attach_point->target = orig_target;
          attach_point->ns = orig_ns;
        }
        else
        {
          if (attach_point->provider == "BEGIN" ||
              attach_point->provider == "END")
            probefull_ = attach_point->provider;
          else if ((probetype(attach_point->provider) ==
                        ProbeType::tracepoint ||
                    probetype(attach_point->provider) == ProbeType::uprobe ||
                    probetype(attach_point->provider) == ProbeType::uretprobe))
          {
            // Tracepoint and uprobe probes must specify both a target
            // (tracepoint category) and a function name
            std::string func = match;
            std::string category = erase_prefix(func);

            probefull_ = attach_point->name(category, func);
          }
          else if (probetype(attach_point->provider) == ProbeType::watchpoint ||
                   probetype(attach_point->provider) ==
                       ProbeType::asyncwatchpoint)
          {
            // Watchpoint probes comes with target prefix. Strip the target to
            // get the function
            erase_prefix(match);
            probefull_ = attach_point->name(match);
          }
          else
            probefull_ = attach_point->name(match);

          generateProbe(probe, match, probefull_, func_type, true);
        }
      }
    }
  }
  bpftrace_.add_probe(probe);
  current_attach_point_ = nullptr;
}

void CodegenLLVM::visit(Program &program)
{
  for (Probe *probe : *program.probes)
    auto scoped_del = accept(probe);
}

int CodegenLLVM::getNextIndexForProbe(const std::string &probe_name) {
  if (next_probe_index_.count(probe_name) == 0)
    next_probe_index_[probe_name] = 1;
  int index = next_probe_index_[probe_name];
  next_probe_index_[probe_name] += 1;
  return index;
}

std::tuple<Value *, CodegenLLVM::ScopedExprDeleter> CodegenLLVM::getMapKey(
    Map &map)
{
  Value *key;
  if (map.vargs) {
    // A single value as a map key (e.g., @[comm] = 0;)
    if (map.vargs->size() == 1)
    {
      Expression *expr = map.vargs->at(0);
      auto scoped_del = accept(expr);
      if (onStack(expr->type))
      {
        key = expr_;
        // Call-ee freed
        scoped_del.disarm();
      }
      else
      {
        key = b_.CreateAllocaBPF(expr->type, map.ident + "_key");
        if (expr->type.IsArrayTy() || expr->type.IsRecordTy())
        {
          // We need to read the entire array/struct and save it
          b_.CreateProbeRead(ctx_,
                             key,
                             expr->type.GetSize(),
                             expr_,
                             expr->type.GetAS(),
                             expr->loc);
        }
        else
        {
          b_.CreateStore(
              b_.CreateIntCast(expr_, b_.getInt64Ty(), expr->type.IsSigned()),
              b_.CreatePointerCast(key, expr_->getType()->getPointerTo()));
        }
      }
    }
    else
    {
      // Two or more values as a map key (e.g, @[comm, pid] = 1;)
      size_t size = 0;
      for (Expression *expr : *map.vargs)
      {
        size += expr->type.GetSize();
      }
      key = b_.CreateAllocaBPF(size, map.ident + "_key");

      int offset = 0;
      // Construct a map key in the stack
      for (Expression *expr : *map.vargs)
      {
        auto scoped_del = accept(expr);
        Value *offset_val = b_.CreateGEP(
            key, { b_.getInt64(0), b_.getInt64(offset) });

        if (onStack(expr->type))
          b_.CREATE_MEMCPY(offset_val, expr_, expr->type.GetSize(), 1);
        else
        {
          if (expr->type.IsArrayTy() || expr->type.IsRecordTy())
          {
            // Read the array/struct into the key
            b_.CreateProbeRead(ctx_,
                               offset_val,
                               expr->type.GetSize(),
                               expr_,
                               expr->type.GetAS(),
                               expr->loc);
          }
          else
          {
            // promote map key to 64-bit:
            b_.CreateStore(
                b_.CreateIntCast(expr_, b_.getInt64Ty(), expr->type.IsSigned()),
                b_.CreatePointerCast(offset_val,
                                     expr_->getType()->getPointerTo()));
          }
        }
        offset += expr->type.GetSize();
      }
    }
  }
  else
  {
    // No map key (e.g., @ = 1;). Use 0 as a key.
    key = b_.CreateAllocaBPF(CreateUInt64(), map.ident + "_key");
    b_.CreateStore(b_.getInt64(0), key);
  }

  auto key_deleter = [this, key]() {
    if (dyn_cast<AllocaInst>(key))
      b_.CreateLifetimeEnd(key);
  };
  return std::make_tuple(key, ScopedExprDeleter(std::move(key_deleter)));
}

AllocaInst *CodegenLLVM::getHistMapKey(Map &map, Value *log2)
{
  AllocaInst *key;
  if (map.vargs) {
    size_t size = 8; // Extra space for the bucket value
    for (Expression *expr : *map.vargs)
    {
      size += expr->type.GetSize();
    }
    key = b_.CreateAllocaBPF(size, map.ident + "_key");

    int offset = 0;
    for (Expression *expr : *map.vargs) {
      auto scoped_del = accept(expr);
      Value *offset_val = b_.CreateGEP(key, {b_.getInt64(0), b_.getInt64(offset)});
      if (shouldBeOnStackAlready(expr->type))
        b_.CREATE_MEMCPY(offset_val, expr_, expr->type.GetSize(), 1);
      else
        b_.CreateStore(expr_, offset_val);
      offset += expr->type.GetSize();
    }
    Value *offset_val = b_.CreateGEP(key, {b_.getInt64(0), b_.getInt64(offset)});
    b_.CreateStore(log2, offset_val);
  }
  else
  {
    key = b_.CreateAllocaBPF(CreateUInt64(), map.ident + "_key");
    b_.CreateStore(log2, key);
  }
  return key;
}

Value *CodegenLLVM::createLogicalAnd(Binop &binop)
{
  assert(binop.left->type.IsIntTy());
  assert(binop.right->type.IsIntTy());

  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *lhs_true_block = BasicBlock::Create(module_->getContext(), "&&_lhs_true", parent);
  BasicBlock *true_block = BasicBlock::Create(module_->getContext(), "&&_true", parent);
  BasicBlock *false_block = BasicBlock::Create(module_->getContext(), "&&_false", parent);
  BasicBlock *merge_block = BasicBlock::Create(module_->getContext(), "&&_merge", parent);

  Value *result = b_.CreateAllocaBPF(b_.getInt64Ty(), "&&_result");
  Value *lhs;
  auto scoped_del_left = accept(binop.left);
  lhs = expr_;
  b_.CreateCondBr(b_.CreateICmpNE(lhs, b_.GetIntSameSize(0, lhs), "lhs_true_cond"),
                  lhs_true_block,
                  false_block);

  b_.SetInsertPoint(lhs_true_block);
  Value *rhs;
  auto scoped_del_right = accept(binop.right);
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
  assert(binop.left->type.IsIntTy());
  assert(binop.right->type.IsIntTy());

  Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *lhs_false_block = BasicBlock::Create(module_->getContext(), "||_lhs_false", parent);
  BasicBlock *false_block = BasicBlock::Create(module_->getContext(), "||_false", parent);
  BasicBlock *true_block = BasicBlock::Create(module_->getContext(), "||_true", parent);
  BasicBlock *merge_block = BasicBlock::Create(module_->getContext(), "||_merge", parent);

  Value *result = b_.CreateAllocaBPF(b_.getInt64Ty(), "||_result");
  Value *lhs;
  auto scoped_del_left = accept(binop.left);
  lhs = expr_;
  b_.CreateCondBr(b_.CreateICmpNE(lhs, b_.GetIntSameSize(0, lhs), "lhs_true_cond"),
                  true_block,
                  lhs_false_block);

  b_.SetInsertPoint(lhs_false_block);
  Value *rhs;
  auto scoped_del_right = accept(binop.right);
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

Function *CodegenLLVM::createLog2Function()
{
  auto ip = b_.saveIP();
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
  Value *n_alloc = b_.CreateAllocaBPF(CreateUInt64());
  b_.CreateStore(arg, n_alloc);
  Value *result = b_.CreateAllocaBPF(CreateUInt64());
  b_.CreateStore(b_.getInt64(0), result);

  // test for less than zero
  BasicBlock *is_less_than_zero = BasicBlock::Create(module_->getContext(), "hist.is_less_than_zero", log2_func);
  BasicBlock *is_not_less_than_zero = BasicBlock::Create(module_->getContext(), "hist.is_not_less_than_zero", log2_func);
  b_.CreateCondBr(b_.CreateICmpSLT(b_.CreateLoad(n_alloc), b_.getInt64(0)),
                  is_less_than_zero,
                  is_not_less_than_zero);
  b_.SetInsertPoint(is_less_than_zero);
  createRet(b_.CreateLoad(result));
  b_.SetInsertPoint(is_not_less_than_zero);

  // test for equal to zero
  BasicBlock *is_zero = BasicBlock::Create(module_->getContext(), "hist.is_zero", log2_func);
  BasicBlock *is_not_zero = BasicBlock::Create(module_->getContext(), "hist.is_not_zero", log2_func);
  b_.CreateCondBr(b_.CreateICmpEQ(b_.CreateLoad(n_alloc), b_.getInt64(0)),
                  is_zero,
                  is_not_zero);
  b_.SetInsertPoint(is_zero);
  b_.CreateStore(b_.getInt64(1), result);
  createRet(b_.CreateLoad(result));
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
  createRet(b_.CreateLoad(result));
  b_.restoreIP(ip);
  return module_->getFunction("log2");
}

Function *CodegenLLVM::createLinearFunction()
{
  auto ip = b_.saveIP();
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
  Value *value_alloc = b_.CreateAllocaBPF(CreateUInt64());
  Value *min_alloc = b_.CreateAllocaBPF(CreateUInt64());
  Value *max_alloc = b_.CreateAllocaBPF(CreateUInt64());
  Value *step_alloc = b_.CreateAllocaBPF(CreateUInt64());
  Value *result_alloc = b_.CreateAllocaBPF(CreateUInt64());

  b_.CreateStore(linear_func->arg_begin() + 0, value_alloc);
  b_.CreateStore(linear_func->arg_begin() + 1, min_alloc);
  b_.CreateStore(linear_func->arg_begin() + 2, max_alloc);
  b_.CreateStore(linear_func->arg_begin() + 3, step_alloc);

  Value *cmp = nullptr;

  // algorithm
  {
    Value *min = b_.CreateLoad(min_alloc);
    Value *val = b_.CreateLoad(value_alloc);
    cmp = b_.CreateICmpSLT(val, min);
  }
  BasicBlock *lt_min = BasicBlock::Create(module_->getContext(), "lhist.lt_min", linear_func);
  BasicBlock *ge_min = BasicBlock::Create(module_->getContext(), "lhist.ge_min", linear_func);
  b_.CreateCondBr(cmp, lt_min, ge_min);

  b_.SetInsertPoint(lt_min);
  createRet(b_.getInt64(0));

  b_.SetInsertPoint(ge_min);
  {
    Value *max = b_.CreateLoad(max_alloc);
    Value *val = b_.CreateLoad(value_alloc);
    cmp = b_.CreateICmpSGT(val, max);
  }
  BasicBlock *le_max = BasicBlock::Create(module_->getContext(), "lhist.le_max", linear_func);
  BasicBlock *gt_max = BasicBlock::Create(module_->getContext(), "lhist.gt_max", linear_func);
  b_.CreateCondBr(cmp, gt_max, le_max);

  b_.SetInsertPoint(gt_max);
  {
    Value *step = b_.CreateLoad(step_alloc);
    Value *min = b_.CreateLoad(min_alloc);
    Value *max = b_.CreateLoad(max_alloc);
    Value *div = b_.CreateUDiv(b_.CreateSub(max, min), step);
    b_.CreateStore(b_.CreateAdd(div, b_.getInt64(1)), result_alloc);
    createRet(b_.CreateLoad(result_alloc));
  }

  b_.SetInsertPoint(le_max);
  {
    Value *step = b_.CreateLoad(step_alloc);
    Value *min = b_.CreateLoad(min_alloc);
    Value *val = b_.CreateLoad(value_alloc);
    Value *div3 = b_.CreateUDiv(b_.CreateSub(val, min), step);
    b_.CreateStore(b_.CreateAdd(div3, b_.getInt64(1)), result_alloc);
    createRet(b_.CreateLoad(result_alloc));
  }

  b_.restoreIP(ip);
  return module_->getFunction("linear");
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
  int struct_size = datalayout().getTypeAllocSize(fmt_struct);

  auto *struct_layout = datalayout().getStructLayout(fmt_struct);
  for (size_t i=0; i<args.size(); i++)
  {
    Field &arg = args[i];
    arg.offset = struct_layout->getElementOffset(i+1); // +1 for the id field
  }

  AllocaInst *fmt_args = b_.CreateAllocaBPF(fmt_struct, call_name + "_args");
  // as the struct is not packed we need to memset it.
  b_.CREATE_MEMSET(fmt_args, b_.getInt8(0), struct_size, 1);

  Value *id_offset = b_.CreateGEP(fmt_args, {b_.getInt32(0), b_.getInt32(0)});
  b_.CreateStore(b_.getInt64(id + asyncactionint(async_action)), id_offset);

  for (size_t i=1; i<call.vargs->size(); i++)
  {
    Expression &arg = *call.vargs->at(i);
    auto scoped_del = accept(&arg);
    Value *offset = b_.CreateGEP(fmt_args, {b_.getInt32(0), b_.getInt32(i)});
    if (needMemcpy(arg.type))
      b_.CREATE_MEMCPY(offset, expr_, arg.type.GetSize(), 1);
    else if (arg.type.IsIntegerTy() && arg.type.GetSize() < 8)
      b_.CreateStore(
          b_.CreateIntCast(expr_, b_.getInt64Ty(), arg.type.IsSigned()),
          offset);
    else
      b_.CreateStore(expr_, offset);
  }

  id++;
  b_.CreatePerfEventOutput(ctx_, fmt_args, struct_size);
  b_.CreateLifetimeEnd(fmt_args);
  expr_ = nullptr;
}

void CodegenLLVM::generateWatchpointSetupProbe(
    FunctionType *func_type,
    const std::string &expanded_probe_name,
    int arg_num,
    int index)
{
  Function *func = Function::Create(func_type,
                                    Function::ExternalLinkage,
                                    get_watchpoint_setup_probe_name(
                                        expanded_probe_name),
                                    module_.get());
  func->setSection(
      get_section_name_for_watchpoint_setup(expanded_probe_name, index));
  BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", func);
  b_.SetInsertPoint(entry);

  // Send SIGSTOP to curtask
  if (!current_attach_point_->async)
    b_.CreateSignal(ctx_, b_.getInt32(SIGSTOP), current_attach_point_->loc);

  // Pull out function argument
  Value *ctx = func->arg_begin();
  int offset = arch::arg_offset(arg_num);
  Value *addr = b_.CreateLoad(
      b_.getInt64Ty(),
      b_.CreateGEP(ctx, b_.getInt64(offset * sizeof(uintptr_t))),
      "arg" + std::to_string(arg_num));

  // Tell userspace to setup the real watchpoint
  auto elements = AsyncEvent::Watchpoint().asLLVMType(b_);
  StructType *watchpoint_struct = b_.GetStructType("watchpoint_t",
                                                   elements,
                                                   true);
  AllocaInst *buf = b_.CreateAllocaBPF(watchpoint_struct, "watchpoint");
  size_t struct_size = datalayout().getTypeAllocSize(watchpoint_struct);

  // Fill in perf event struct
  b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::watchpoint_attach)),
                 b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(0) }));
  b_.CreateStore(b_.getInt64(watchpoint_id_),
                 b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(1) }));
  watchpoint_id_++;
  b_.CreateStore(addr, b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(2) }));
  b_.CreatePerfEventOutput(ctx, buf, struct_size);
  b_.CreateLifetimeEnd(buf);

  createRet();
}

void CodegenLLVM::createPrintMapCall(Call &call)
{
  auto elements = AsyncEvent::Print().asLLVMType(b_);
  StructType *print_struct = b_.GetStructType(call.func + "_t", elements, true);

  auto &arg = *call.vargs->at(0);
  auto &map = static_cast<Map &>(arg);

  AllocaInst *buf = b_.CreateAllocaBPF(print_struct,
                                       call.func + "_" + map.ident);

  // store asyncactionid:
  b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::print)),
                 b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(0) }));

  auto id = bpftrace_.maps[map.ident].value()->id;
  auto *ident_ptr = b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(1) });
  b_.CreateStore(b_.GetIntSameSize(id, elements.at(1)), ident_ptr);

  // top, div
  // first loops sets the arguments as passed by user. The second one zeros
  // the rest
  size_t arg_idx = 1;
  for (; arg_idx < call.vargs->size(); arg_idx++)
  {
    auto scoped_del = accept(call.vargs->at(arg_idx));

    b_.CreateStore(b_.CreateIntCast(expr_, elements.at(arg_idx), false),
                   b_.CreateGEP(buf,
                                { b_.getInt64(0), b_.getInt32(arg_idx + 1) }));
  }

  for (; arg_idx < 3; arg_idx++)
  {
    b_.CreateStore(b_.GetIntSameSize(0, elements.at(arg_idx)),
                   b_.CreateGEP(buf,
                                { b_.getInt64(0), b_.getInt32(arg_idx + 1) }));
  }

  b_.CreatePerfEventOutput(ctx_, buf, getStructSize(print_struct));
  b_.CreateLifetimeEnd(buf);
  expr_ = nullptr;
}

void CodegenLLVM::createPrintNonMapCall(Call &call, int &id)
{
  auto &arg = *call.vargs->at(0);
  auto scoped_del = accept(&arg);

  auto elements = AsyncEvent::PrintNonMap().asLLVMType(b_, arg.type.GetSize());
  std::ostringstream struct_name;
  struct_name << call.func << "_" << arg.type.type << "_" << arg.type.GetSize()
              << "_t";
  StructType *print_struct = b_.GetStructType(struct_name.str(),
                                              elements,
                                              true);
  AllocaInst *buf = b_.CreateAllocaBPF(print_struct, struct_name.str());
  size_t struct_size = datalayout().getTypeAllocSize(print_struct);

  // Store asyncactionid:
  b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::print_non_map)),
                 b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(0) }));

  // Store print id
  b_.CreateStore(b_.getInt64(id),
                 b_.CreateGEP(buf, { b_.getInt64(0), b_.getInt32(1) }));

  // Store content
  Value *content_offset = b_.CreateGEP(buf, { b_.getInt32(0), b_.getInt32(2) });
  b_.CREATE_MEMSET(content_offset, b_.getInt8(0), arg.type.GetSize(), 1);
  if (needMemcpy(arg.type))
  {
    if (onStack(arg.type))
      b_.CREATE_MEMCPY(content_offset, expr_, arg.type.GetSize(), 1);
    else
      b_.CreateProbeRead(ctx_,
                         content_offset,
                         arg.type.GetSize(),
                         expr_,
                         arg.type.GetAS(),
                         arg.loc);
  }
  else
  {
    auto ptr = b_.CreatePointerCast(content_offset,
                                    expr_->getType()->getPointerTo());
    b_.CreateStore(expr_, ptr);
  }

  id++;
  b_.CreatePerfEventOutput(ctx_, buf, struct_size);
  b_.CreateLifetimeEnd(buf);
  expr_ = nullptr;
}

void CodegenLLVM::generate_ir()
{
  assert(state_ == State::INIT);
  auto scoped_del = accept(root_);
  state_ = State::IR;
}

void CodegenLLVM::emit_elf(const std::string &filename)
{
  assert(state_ == State::OPT);
  legacy::PassManager PM;

#if LLVM_VERSION_MAJOR >= 10
  auto type = llvm::CGFT_ObjectFile;
#else
  auto type = llvm::TargetMachine::CGFT_ObjectFile;
#endif

#if LLVM_VERSION_MAJOR >= 7
  std::error_code err;
  raw_fd_ostream out(filename, err);

  if (err)
    throw std::system_error(err.value(),
                            std::generic_category(),
                            "Failed to open: " + filename);
  if (orc_->getTargetMachine().addPassesToEmitFile(PM, out, nullptr, type))
    throw std::runtime_error("Cannot emit a file of this type");
  PM.run(*module_.get());

  return;

#else
  std::ofstream file(filename);
  if (!file.is_open())
    throw std::system_error(errno,
                            std::generic_category(),
                            "Failed to open: " + filename);
  std::unique_ptr<SmallVectorImpl<char>> buf(new SmallVector<char, 0>());
  raw_svector_ostream out(*buf);

  if (orc_->getTargetMachine().addPassesToEmitFile(
          PM, out, type, true, nullptr))
    throw std::runtime_error("Cannot emit a file of this type");

  file.write(buf->data(), buf->size_in_bytes());
#endif
}

void CodegenLLVM::optimize()
{
  assert(state_ == State::IR);
  PassManagerBuilder PMB;
  PMB.OptLevel = 3;
  legacy::PassManager PM;
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
  state_ = State::OPT;
}

std::unique_ptr<BpfOrc> CodegenLLVM::emit(void)
{
  assert(state_ == State::OPT);
  orc_->compile(move(module_));
  state_ = State::DONE;

#ifdef LLVM_ORC_V2
  auto has_sym = [this](const std::string &s) {
    auto sym = orc_->lookup(s);
    return (sym && sym->getAddress());
  };
  for (const auto &probe : bpftrace_.special_probes_)
  {
    if (has_sym(probe.name) || has_sym(probe.orig_name))
      return std::move(orc_);
  }
  for (const auto &probe : bpftrace_.probes_)
  {
    if (has_sym(probe.name) || has_sym(probe.orig_name))
      return std::move(orc_);
  }
#endif

  return std::move(orc_);
}

std::unique_ptr<BpfOrc> CodegenLLVM::compile(void)
{
  generate_ir();
  optimize();
  return emit();
}

void CodegenLLVM::DumpIR(void)
{
  DumpIR(std::cout);
}

void CodegenLLVM::DumpIR(std::ostream &out)
{
  assert(module_.get() != nullptr);
  raw_os_ostream os(out);
  module_->print(os, nullptr, false, true);
}

CodegenLLVM::ScopedExprDeleter CodegenLLVM::accept(Node *node)
{
  expr_deleter_ = nullptr;
  node->accept(*this);
  auto deleter = std::move(expr_deleter_);
  expr_deleter_ = nullptr;
  return ScopedExprDeleter(deleter);
}

// Read a single element from a compound data structure (i.e. an array or
// a struct) that has been pulled onto BPF stack.
// Params:
//   src_data   pointer to the entire data structure
//   index      index of the field to read
//   data_type  type of the structure
//   elem_type  type of the element
//   scoped_del scope deleter for the data structure
void CodegenLLVM::readDatastructElemFromStack(Value *src_data,
                                              Value *index,
                                              const SizedType &data_type,
                                              const SizedType &elem_type,
                                              ScopedExprDeleter &scoped_del)
{
  // src_data should contain a pointer to the data structure, but it may be
  // internally represented as an integer and then we need to cast it
  if (src_data->getType()->isIntegerTy())
    src_data = b_.CreateIntToPtr(src_data,
                                 b_.GetType(data_type)->getPointerTo());

  Value *src = b_.CreateGEP(src_data, { b_.getInt32(0), index });

  // It may happen that the result pointer type is not correct, in such case
  // do a typecast
  auto dst_type = b_.GetType(elem_type);
  if (src->getType() != dst_type->getPointerTo())
    src = b_.CreatePointerCast(src, dst_type->getPointerTo());

  if (elem_type.IsIntegerTy() || elem_type.IsPtrTy())
  {
    // Load the correct type from src
    expr_ = b_.CreateLoad(src, true);
  }
  else
  {
    // The inner type is an aggregate - instead of copying it, just pass
    // the pointer and extend lifetime of the source data
    expr_ = src;
    expr_deleter_ = scoped_del.disarm();
  }
}

// Read a single element from a compound data structure (i.e. an array or
// a struct) that has not been yet pulled into BPF memory.
// Params:
//   src_data  (external) pointer to the entire data structure
//   offset     offset of the requested element from the structure beginning
//   data_type  type of the data structure
//   elem_type  type of the requested element
//   scoped_del scoped deleter for the source structure
//   loc        location of the element access (for proberead)
//   temp_name  name of a temporary variable, if the function creates any
void CodegenLLVM::probereadDatastructElem(Value *src_data,
                                          Value *offset,
                                          const SizedType &data_type,
                                          const SizedType &elem_type,
                                          ScopedExprDeleter &scoped_del,
                                          location loc,
                                          const std::string &temp_name)
{
  Value *src = b_.CreateAdd(src_data, offset);

  auto dst_type = b_.GetType(elem_type);
  if (elem_type.IsRecordTy() || elem_type.IsArrayTy())
  {
    // For nested arrays and structs, just pass the pointer along and
    // dereference it later when necessary. We just need to extend lifetime
    // of the source pointer.
    expr_ = src;
    expr_deleter_ = scoped_del.disarm();
  }
  else if (elem_type.IsStringTy() || elem_type.IsBufferTy())
  {
    // Read data onto stack
    AllocaInst *dst = b_.CreateAllocaBPF(elem_type, temp_name);
    if (data_type.IsCtxAccess())
    {
      // Map functions only accept a pointer to a element in the stack
      // Copy data to avoid the above issue
      b_.CREATE_MEMCPY_VOLATILE(dst,
                                b_.CreateIntToPtr(src,
                                                  dst_type->getPointerTo()),
                                elem_type.GetSize(),
                                1);
    }
    else
    {
      b_.CreateProbeRead(
          ctx_, dst, elem_type.GetSize(), src, data_type.GetAS(), loc);
    }
    expr_ = dst;
    expr_deleter_ = [this, dst]() { b_.CreateLifetimeEnd(dst); };
  }
  else
  {
    // Read data onto stack
    if (data_type.IsCtxAccess())
    {
      expr_ = b_.CreateLoad(b_.CreateIntToPtr(src, dst_type->getPointerTo()),
                            true);
      expr_ = b_.CreateIntCast(expr_, b_.getInt64Ty(), elem_type.IsSigned());

      // check context access for iter probes (required by kernel)
      if (probetype(current_attach_point_->provider) == ProbeType::iter)
      {
        Function *parent = b_.GetInsertBlock()->getParent();
        BasicBlock *pred_false_block = BasicBlock::Create(module_->getContext(),
                                                          "pred_false",
                                                          parent);
        BasicBlock *pred_true_block = BasicBlock::Create(module_->getContext(),
                                                         "pred_true",
                                                         parent);
        Value *expr = expr_;

        expr = b_.CreateIntCast(expr, b_.getInt64Ty(), false);
        expr = b_.CreateICmpEQ(expr, b_.getInt64(0), "predcond");

        b_.CreateCondBr(expr, pred_false_block, pred_true_block);
        b_.SetInsertPoint(pred_false_block);
        createRet();

        b_.SetInsertPoint(pred_true_block);
      }
    }
    else
    {
      AllocaInst *dst = b_.CreateAllocaBPF(elem_type, temp_name);
      b_.CreateProbeRead(
          ctx_, dst, elem_type.GetSize(), src, data_type.GetAS(), loc);
      expr_ = b_.CreateIntCast(b_.CreateLoad(dst),
                               b_.getInt64Ty(),
                               elem_type.IsSigned());
      b_.CreateLifetimeEnd(dst);
    }
  }
}

} // namespace ast
} // namespace bpftrace
