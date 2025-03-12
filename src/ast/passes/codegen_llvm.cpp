#include "codegen_llvm.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <limits>
#include <llvm/IR/GlobalValue.h>

#if LLVM_VERSION_MAJOR <= 16
#include <llvm-c/Transforms/IPO.h>
#endif
#include <llvm/CodeGen/UnreachableBlockElim.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/IPO.h>
#if LLVM_VERSION_MAJOR <= 16
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#endif
#include <llvm/MC/TargetRegistry.h>

#include <llvm/Support/TargetSelect.h>

#include "arch/arch.h"
#include "ast/ast.h"
#include "ast/async_event_types.h"
#include "ast/codegen_helper.h"
#include "ast/signal_bt.h"
#include "bpfmap.h"
#include "collect_nodes.h"
#include "globalvars.h"
#include "log.h"
#include "tracepoint_format_parser.h"
#include "types.h"
#include "usdt.h"

namespace bpftrace::ast {

CodegenLLVM::CodegenLLVM(ASTContext &ctx, BPFtrace &bpftrace)
    : CodegenLLVM(ctx, bpftrace, std::make_unique<USDTHelper>())
{
}

CodegenLLVM::CodegenLLVM(ASTContext &ctx,
                         BPFtrace &bpftrace,
                         std::unique_ptr<USDTHelper> usdt_helper)
    : Visitor<CodegenLLVM, ScopedExpr>(ctx),
      bpftrace_(bpftrace),
      usdt_helper_(std::move(usdt_helper)),
      context_(std::make_unique<LLVMContext>()),
      module_(std::make_unique<Module>("bpftrace", *context_)),
      async_ids_(AsyncIds()),
      b_(*context_, *module_, bpftrace, async_ids_),
      debug_(*module_)
{
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFAsmPrinter();
  std::string error_str;
  auto target = llvm::TargetRegistry::lookupTarget(LLVMTargetTriple, error_str);
  if (!target)
    throw FatalUserException(
        "Could not find bpf llvm target, does your llvm support it?");

  target_machine_.reset(
      target->createTargetMachine(LLVMTargetTriple,
                                  "generic",
                                  "",
                                  TargetOptions(),
                                  std::optional<Reloc::Model>()));
#if LLVM_VERSION_MAJOR >= 18
  target_machine_->setOptLevel(llvm::CodeGenOptLevel::Aggressive);
#else
  target_machine_->setOptLevel(llvm::CodeGenOpt::Aggressive);
#endif

  module_->setTargetTriple(LLVMTargetTriple);
  module_->setDataLayout(target_machine_->createDataLayout());

  debug_.createCompileUnit(dwarf::DW_LANG_C,
                           debug_.file,
                           "bpftrace",
                           false,
                           "",
                           0,
                           StringRef(),
                           DICompileUnit::DebugEmissionKind::LineTablesOnly);
  module_->addModuleFlag(llvm::Module::Warning,
                         "Debug Info Version",
                         llvm::DEBUG_METADATA_VERSION);

  // Set license of BPF programs
  const std::string license = "GPL";
  auto license_var = llvm::dyn_cast<GlobalVariable>(module_->getOrInsertGlobal(
      "LICENSE", ArrayType::get(b_.getInt8Ty(), license.size() + 1)));
  license_var->setInitializer(
      ConstantDataArray::getString(module_->getContext(), license.c_str()));
  license_var->setSection("license");
}

ScopedExpr CodegenLLVM::visit(Integer &integer)
{
  return ScopedExpr(b_.getInt64(integer.n));
}

ScopedExpr CodegenLLVM::visit(PositionalParameter &param)
{
  switch (param.ptype) {
    case PositionalParameterType::positional: {
      std::string pstr = bpftrace_.get_param(param.n, param.is_in_str);
      if (!param.is_in_str) {
        if (param.type.IsSigned()) {
          return ScopedExpr(b_.getInt64(std::stoll(pstr, nullptr, 0)));
        } else {
          return ScopedExpr(b_.getInt64(std::stoull(pstr, nullptr, 0)));
        }
      } else {
        auto string_param = llvm::dyn_cast<GlobalVariable>(
            module_->getOrInsertGlobal(
                pstr, ArrayType::get(b_.getInt8Ty(), pstr.length() + 1)));
        string_param->setInitializer(
            ConstantDataArray::getString(module_->getContext(), pstr));
        return ScopedExpr(b_.CreatePtrToInt(string_param, b_.getInt64Ty()));
      }
    }
    case PositionalParameterType::count:
      return ScopedExpr(b_.getInt64(bpftrace_.num_params()));
    default:
      LOG(BUG) << "unknown positional parameter type";
      __builtin_unreachable();
  }
}

ScopedExpr CodegenLLVM::visit(String &string)
{
  string.str.resize(string.type.GetSize() - 1);
  auto string_var = llvm::dyn_cast<GlobalVariable>(module_->getOrInsertGlobal(
      string.str, ArrayType::get(b_.getInt8Ty(), string.type.GetSize())));
  string_var->setInitializer(
      ConstantDataArray::getString(module_->getContext(), string.str));
  return ScopedExpr(string_var);
}

// NB: we do not resolve identifiers that are structs. That is because in
// bpftrace you cannot really instantiate a struct.
ScopedExpr CodegenLLVM::visit(Identifier &identifier)
{
  if (bpftrace_.enums_.count(identifier.ident) != 0) {
    return ScopedExpr(
        b_.getInt64(std::get<0>(bpftrace_.enums_[identifier.ident])));
  } else {
    LOG(BUG) << "unknown identifier \"" << identifier.ident << "\"";
    __builtin_unreachable();
  }
}

ScopedExpr CodegenLLVM::kstack_ustack(const std::string &ident,
                                      StackType stack_type,
                                      const location &loc)
{
  if (!murmur_hash_2_func_)
    murmur_hash_2_func_ = createMurmurHash2Func();

  const bool is_ustack = ident == "ustack";
  const auto uint64_size = sizeof(uint64_t);

  StructType *stack_key_struct = b_.GetStackStructType(is_ustack);
  AllocaInst *stack_key = b_.CreateAllocaBPF(stack_key_struct, "stack_key");
  b_.CreateMemsetBPF(stack_key,
                     b_.getInt8(0),
                     datalayout().getTypeStoreSize(stack_key_struct));

  llvm::Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *stack_scratch_failure = BasicBlock::Create(
      module_->getContext(), "stack_scratch_failure", parent);
  BasicBlock *merge_block = BasicBlock::Create(module_->getContext(),
                                               "merge_block",
                                               parent);

  Value *stack_trace = b_.CreateGetStackScratchMap(stack_type,
                                                   stack_scratch_failure,
                                                   loc);
  b_.CreateMemsetBPF(stack_trace,
                     b_.getInt8(0),
                     uint64_size * stack_type.limit);

  BasicBlock *get_stack_success = BasicBlock::Create(module_->getContext(),
                                                     "get_stack_success",
                                                     parent);
  BasicBlock *get_stack_fail = BasicBlock::Create(module_->getContext(),
                                                  "get_stack_fail",
                                                  parent);

  Value *stack_size = b_.CreateGetStack(
      ctx_, is_ustack, stack_trace, stack_type, loc);
  Value *condition = b_.CreateICmpSGE(stack_size, b_.getInt64(0));
  b_.CreateCondBr(condition, get_stack_success, get_stack_fail);

  b_.SetInsertPoint(get_stack_fail);
  b_.CreateDebugOutput("Failed to get stack. Error: %d",
                       std::vector<Value *>{ stack_size },
                       loc);
  b_.CreateBr(merge_block);
  b_.SetInsertPoint(get_stack_success);

  Value *num_frames = b_.CreateUDiv(stack_size, b_.getInt64(uint64_size));
  b_.CreateStore(num_frames,
                 b_.CreateGEP(stack_key_struct,
                              stack_key,
                              { b_.getInt64(0), b_.getInt32(1) }));
  // A random seed (or using pid) is probably unnecessary in this situation
  // and might hurt storage as the same pids may have the same stack and
  // we don't need to store it twice
  Value *seed = b_.getInt64(1);

  // LLVM-12 produces code that fails the BPF verifier because it
  // can't determine the bounds of nr_stack_frames. The only thing that seems
  // to work is truncating the type, which is fine because 255 is long enough.
  Value *trunc_nr_stack_frames = b_.CreateTrunc(num_frames, b_.getInt8Ty());

  // Here we use the murmur2 hash function to create the stack ids because
  // bpf_get_stackid() is kind of broken by design and can suffer from hash
  // collisions.
  // More details here: https://github.com/bpftrace/bpftrace/issues/2962
  Value *murmur_hash_2 = b_.CreateCall(
      murmur_hash_2_func_,
      { stack_trace, trunc_nr_stack_frames, seed },
      "murmur_hash_2");

  b_.CreateStore(murmur_hash_2,
                 b_.CreateGEP(stack_key_struct,
                              stack_key,
                              { b_.getInt64(0), b_.getInt32(0) }));
  // Add the stack and id to the stack map
  b_.CreateMapUpdateElem(
      ctx_, stack_type.name(), stack_key, stack_trace, loc, BPF_ANY);
  b_.CreateBr(merge_block);

  b_.SetInsertPoint(stack_scratch_failure);
  b_.CreateDebugOutput("Failed to get stack from scratch map.",
                       std::vector<Value *>{},
                       loc);
  b_.CreateBr(merge_block);
  b_.SetInsertPoint(merge_block);

  // ustack keys are special: see IRBuilderBPF::GetStackStructType()
  if (is_ustack) {
    // store pid
    b_.CreateStore(b_.CreateGetPid(ctx_, loc),
                   b_.CreateGEP(stack_key_struct,
                                stack_key,
                                { b_.getInt64(0), b_.getInt32(2) }));
    // store probe id
    b_.CreateStore(b_.GetIntSameSize(get_probe_id(),
                                     stack_key_struct->getTypeAtIndex(3)),
                   b_.CreateGEP(stack_key_struct,
                                stack_key,
                                { b_.getInt64(0), b_.getInt32(3) }));
  }

  return ScopedExpr(stack_key);
}

int CodegenLLVM::get_probe_id()
{
  auto begin = bpftrace_.resources.probe_ids.begin();
  auto end = bpftrace_.resources.probe_ids.end();
  auto found = std::find(begin, end, probefull_);
  if (found == end) {
    bpftrace_.resources.probe_ids.push_back(probefull_);
  }
  return std::distance(begin, found);
}

ScopedExpr CodegenLLVM::visit(Builtin &builtin)
{
  if (builtin.ident == "nsecs") {
    return ScopedExpr(b_.CreateGetNs(TimestampMode::boot, builtin.loc));
  } else if (builtin.ident == "elapsed") {
    AllocaInst *key = b_.CreateAllocaBPF(b_.getInt64Ty(), "elapsed_key");
    b_.CreateStore(b_.getInt64(0), key);

    auto type = CreateUInt64();
    auto start = b_.CreateMapLookupElem(
        ctx_, to_string(MapType::Elapsed), key, type, builtin.loc);
    Value *ns_value = b_.CreateGetNs(TimestampMode::boot, builtin.loc);
    Value *ns_delta = b_.CreateSub(ns_value, start);
    // start won't be on stack, no need to LifeTimeEnd it
    b_.CreateLifetimeEnd(key);
    return ScopedExpr(ns_delta);
  } else if (builtin.ident == "kstack" || builtin.ident == "ustack") {
    return kstack_ustack(builtin.ident, builtin.type.stack_type, builtin.loc);
  } else if (builtin.ident == "pid") {
    return ScopedExpr(b_.CreateGetPid(ctx_, builtin.loc));
  } else if (builtin.ident == "tid") {
    return ScopedExpr(b_.CreateGetTid(ctx_, builtin.loc));
  } else if (builtin.ident == "cgroup") {
    return ScopedExpr(b_.CreateGetCurrentCgroupId(builtin.loc));
  } else if (builtin.ident == "uid" || builtin.ident == "gid" ||
             builtin.ident == "username") {
    Value *uidgid = b_.CreateGetUidGid(builtin.loc);
    if (builtin.ident == "uid" || builtin.ident == "username") {
      return ScopedExpr(b_.CreateAnd(uidgid, 0xffffffff));
    } else if (builtin.ident == "gid") {
      return ScopedExpr(b_.CreateLShr(uidgid, 32));
    }
    __builtin_unreachable();
  } else if (builtin.ident == "numaid") {
    return ScopedExpr(b_.CreateGetNumaId(builtin.loc));
  } else if (builtin.ident == "cpu") {
    Value *cpu = b_.CreateGetCpuId(builtin.loc);
    return ScopedExpr(b_.CreateZExt(cpu, b_.getInt64Ty()));
  } else if (builtin.ident == "curtask") {
    return ScopedExpr(b_.CreateGetCurrentTask(builtin.loc));
  } else if (builtin.ident == "rand") {
    Value *random = b_.CreateGetRandom(builtin.loc);
    return ScopedExpr(b_.CreateZExt(random, b_.getInt64Ty()));
  } else if (builtin.ident == "comm") {
    AllocaInst *buf = b_.CreateAllocaBPF(builtin.type, "comm");
    // initializing memory needed for older kernels:
    b_.CreateMemsetBPF(buf, b_.getInt8(0), builtin.type.GetSize());
    b_.CreateGetCurrentComm(ctx_, buf, builtin.type.GetSize(), builtin.loc);
    return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
  } else if (builtin.ident == "func") {
    // fentry/fexit probes do not have access to registers, so require use of
    // the get_func_ip helper to get the instruction pointer.
    //
    // For [ku]retprobes, the IP register will not be pointing to the function
    // we want to trace. It may point to a kernel trampoline, or it may point to
    // the caller of the traced function, as it fires after the "ret"
    // instruction has executed.
    //
    // The get_func_ip helper resolves these issues for us.
    //
    // But do not use the it for non-ret [ku]probes (which can be used with
    // offsets), as the helper will fail for probes placed within a function
    // (not at the entry).
    Value *value = nullptr;
    auto probe_type = probetype(current_attach_point_->provider);
    if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit ||
        probe_type == ProbeType::kretprobe ||
        probe_type == ProbeType::uretprobe) {
      value = b_.CreateGetFuncIp(ctx_, builtin.loc);
    } else {
      value = b_.CreateRegisterRead(ctx_, builtin.ident);
    }

    if (builtin.type.IsUsymTy()) {
      value = b_.CreateUSym(ctx_, value, get_probe_id(), builtin.loc);
      return ScopedExpr(value,
                        [this, value]() { b_.CreateLifetimeEnd(value); });
    }
    return ScopedExpr(value);
  } else if (builtin.is_argx() || builtin.ident == "retval") {
    auto probe_type = probetype(current_attach_point_->provider);

    if (builtin.type.is_funcarg) {
      return ScopedExpr(b_.CreateKFuncArg(ctx_, builtin.type, builtin.ident));
    }

    if (builtin.ident.find("arg") != std::string::npos &&
        probe_type == ProbeType::usdt) {
      return ScopedExpr(
          b_.CreateUSDTReadArgument(ctx_,
                                    current_attach_point_,
                                    current_usdt_location_index_,
                                    atoi(builtin.ident.substr(3).c_str()),
                                    builtin,
                                    bpftrace_.pid(),
                                    AddrSpace::user,
                                    builtin.loc));
    }

    Value *value = nullptr;
    if (builtin.is_argx() && probe_type == ProbeType::rawtracepoint)
      value = b_.CreateRawTracepointArg(ctx_, builtin.ident);
    else
      value = b_.CreateRegisterRead(ctx_, builtin.ident);

    if (builtin.type.IsUsymTy()) {
      value = b_.CreateUSym(ctx_, value, get_probe_id(), builtin.loc);
      return ScopedExpr(value,
                        [this, value]() { b_.CreateLifetimeEnd(value); });
    }
    return ScopedExpr(value);

  } else if (!builtin.ident.compare(0, 4, "sarg") &&
             builtin.ident.size() == 5 && builtin.ident.at(4) >= '0' &&
             builtin.ident.at(4) <= '9') {
    int sp_offset = arch::sp_offset();
    if (sp_offset == -1) {
      LOG(BUG) << "negative offset for stack pointer";
    }

    int arg_num = atoi(builtin.ident.substr(4).c_str());
    Value *sp = b_.CreateRegisterRead(ctx_, sp_offset, "reg_sp");
    AllocaInst *dst = b_.CreateAllocaBPF(builtin.type, builtin.ident);

    // Pointer width is used when calculating the SP offset and the number of
    // bytes to read from stack for each argument. We pass a pointer SizedType
    // to CreateProbeRead to make sure it uses the correct read size while
    // keeping builtin.type an int64.
    size_t arg_width =
        b_.getPointerStorageTy(builtin.type.GetAS())->getIntegerBitWidth() / 8;
    SizedType arg_type = CreatePointer(CreateInt8(), builtin.type.GetAS());
    assert(builtin.type.GetSize() == arg_type.GetSize());

    Value *src = b_.CreateAdd(
        sp, b_.getInt64((arg_num + arch::arg_stack_offset()) * arg_width));
    b_.CreateProbeRead(ctx_, dst, arg_type, src, builtin.loc);
    Value *expr = b_.CreateLoad(b_.GetType(builtin.type), dst);
    b_.CreateLifetimeEnd(dst);
    return ScopedExpr(expr);
  } else if (builtin.ident == "probe") {
    auto probe_str = probefull_;
    probe_str.resize(builtin.type.GetSize() - 1);
    auto probe_var = llvm::dyn_cast<GlobalVariable>(module_->getOrInsertGlobal(
        probe_str, ArrayType::get(b_.getInt8Ty(), builtin.type.GetSize())));
    probe_var->setInitializer(
        ConstantDataArray::getString(module_->getContext(), probe_str));
    return ScopedExpr(probe_var);
  } else if (builtin.ident == "args" &&
             probetype(current_attach_point_->provider) == ProbeType::uprobe) {
    // uprobe args record is built on stack
    return ScopedExpr(b_.CreateUprobeArgsRecord(ctx_, builtin.type));
  } else if (builtin.ident == "args" || builtin.ident == "ctx") {
    // ctx is undocumented builtin: for debugging.
    return ScopedExpr(ctx_);
  } else if (builtin.ident == "cpid") {
    pid_t cpid = bpftrace_.child_->pid();
    if (cpid < 1) {
      LOG(BUG) << "Invalid cpid: " << cpid;
    }
    return ScopedExpr(b_.getInt64(cpid));
  } else if (builtin.ident == "jiffies") {
    return ScopedExpr(b_.CreateJiffies64(builtin.loc));
  } else {
    LOG(BUG) << "unknown builtin \"" << builtin.ident << "\"";
    __builtin_unreachable();
  }
}

ScopedExpr CodegenLLVM::visit(Call &call)
{
  if (call.func == "count") {
    Map &map = *call.map;
    auto scoped_key = getMapKey(map);
    b_.CreateMapElemAdd(
        ctx_, map, scoped_key.value(), b_.getInt64(1), call.loc);
    return ScopedExpr();

  } else if (call.func == "sum") {
    Map &map = *call.map;
    ScopedExpr scoped_key = getMapKey(map);
    ScopedExpr scoped_expr = visit(*call.vargs.front());
    // promote int to 64-bit
    Value *cast = b_.CreateIntCast(scoped_expr.value(),
                                   b_.getInt64Ty(),
                                   call.vargs.front()->type.IsSigned());
    b_.CreateMapElemAdd(ctx_, map, scoped_key.value(), cast, call.loc);
    return ScopedExpr();

  } else if (call.func == "max" || call.func == "min") {
    bool is_max = call.func == "max";
    Map &map = *call.map;

    ScopedExpr scoped_key = getMapKey(map);
    CallInst *lookup = b_.CreateMapLookup(map, scoped_key.value());
    ScopedExpr scoped_expr = visit(*call.vargs.front());
    // promote int to 64-bit
    Value *expr = b_.CreateIntCast(scoped_expr.value(),
                                   b_.getInt64Ty(),
                                   call.vargs.front()->type.IsSigned());

    llvm::Type *mm_struct_ty = b_.GetMapValueType(map.type);

    llvm::Function *parent = b_.GetInsertBlock()->getParent();
    BasicBlock *lookup_success_block = BasicBlock::Create(module_->getContext(),
                                                          "lookup_success",
                                                          parent);
    BasicBlock *lookup_failure_block = BasicBlock::Create(module_->getContext(),
                                                          "lookup_failure",
                                                          parent);
    BasicBlock *lookup_merge_block = BasicBlock::Create(module_->getContext(),
                                                        "lookup_merge",
                                                        parent);

    Value *lookup_condition = b_.CreateICmpNE(
        b_.CreateIntCast(lookup, b_.getPtrTy(), true),
        b_.GetNull(),
        "lookup_cond");
    b_.CreateCondBr(lookup_condition,
                    lookup_success_block,
                    lookup_failure_block);

    b_.SetInsertPoint(lookup_success_block);

    Value *mm_val = b_.CreateLoad(
        b_.getInt64Ty(),
        b_.CreateGEP(mm_struct_ty, lookup, { b_.getInt64(0), b_.getInt32(0) }));

    Value *is_set_val = b_.CreateLoad(
        b_.getInt64Ty(),
        b_.CreateGEP(mm_struct_ty, lookup, { b_.getInt64(0), b_.getInt32(1) }));

    BasicBlock *is_set_block = BasicBlock::Create(module_->getContext(),
                                                  "is_set",
                                                  parent);
    BasicBlock *min_max_block = BasicBlock::Create(module_->getContext(),
                                                   "min_max",
                                                   parent);

    Value *is_set_condition = b_.CreateICmpEQ(is_set_val,
                                              b_.getInt64(1),
                                              "is_set_cond");

    // If the value has not been set jump past the min_max_condition
    b_.CreateCondBr(is_set_condition, is_set_block, min_max_block);

    b_.SetInsertPoint(is_set_block);

    Value *min_max_condition;

    if (is_max) {
      min_max_condition = map.type.IsSigned() ? b_.CreateICmpSGE(expr, mm_val)
                                              : b_.CreateICmpUGE(expr, mm_val);
    } else {
      min_max_condition = map.type.IsSigned() ? b_.CreateICmpSGE(mm_val, expr)
                                              : b_.CreateICmpUGE(mm_val, expr);
    }

    b_.CreateCondBr(min_max_condition, min_max_block, lookup_merge_block);

    b_.SetInsertPoint(min_max_block);

    b_.CreateStore(
        expr,
        b_.CreateGEP(mm_struct_ty, lookup, { b_.getInt64(0), b_.getInt32(0) }));
    b_.CreateStore(
        b_.getInt64(1),
        b_.CreateGEP(mm_struct_ty, lookup, { b_.getInt64(0), b_.getInt32(1) }));

    b_.CreateBr(lookup_merge_block);

    b_.SetInsertPoint(lookup_failure_block);

    AllocaInst *mm_struct = b_.CreateAllocaBPF(mm_struct_ty, "mm_struct");

    b_.CreateStore(expr,
                   b_.CreateGEP(mm_struct_ty,
                                mm_struct,
                                { b_.getInt64(0), b_.getInt32(0) }));
    b_.CreateStore(b_.getInt64(1),
                   b_.CreateGEP(mm_struct_ty,
                                mm_struct,
                                { b_.getInt64(0), b_.getInt32(1) }));

    b_.CreateMapUpdateElem(
        ctx_, map.ident, scoped_key.value(), mm_struct, call.loc);

    b_.CreateLifetimeEnd(mm_struct);

    b_.CreateBr(lookup_merge_block);
    b_.SetInsertPoint(lookup_merge_block);

    return ScopedExpr();

  } else if (call.func == "avg" || call.func == "stats") {
    Map &map = *call.map;

    ScopedExpr scoped_key = getMapKey(map);

    CallInst *lookup = b_.CreateMapLookup(map, scoped_key.value());

    ScopedExpr scoped_expr = visit(*call.vargs.front());
    // promote int to 64-bit
    Value *expr = b_.CreateIntCast(scoped_expr.value(),
                                   b_.getInt64Ty(),
                                   call.vargs.front()->type.IsSigned());

    llvm::Type *avg_struct_ty = b_.GetMapValueType(map.type);

    llvm::Function *parent = b_.GetInsertBlock()->getParent();
    BasicBlock *lookup_success_block = BasicBlock::Create(module_->getContext(),
                                                          "lookup_success",
                                                          parent);
    BasicBlock *lookup_failure_block = BasicBlock::Create(module_->getContext(),
                                                          "lookup_failure",
                                                          parent);
    BasicBlock *lookup_merge_block = BasicBlock::Create(module_->getContext(),
                                                        "lookup_merge",
                                                        parent);

    Value *lookup_condition = b_.CreateICmpNE(
        b_.CreateIntCast(lookup, b_.getPtrTy(), true),
        b_.GetNull(),
        "lookup_cond");
    b_.CreateCondBr(lookup_condition,
                    lookup_success_block,
                    lookup_failure_block);

    b_.SetInsertPoint(lookup_success_block);

    Value *total_val = b_.CreateLoad(b_.getInt64Ty(),
                                     b_.CreateGEP(avg_struct_ty,
                                                  lookup,
                                                  { b_.getInt64(0),
                                                    b_.getInt32(0) }));

    Value *count_val = b_.CreateLoad(b_.getInt64Ty(),
                                     b_.CreateGEP(avg_struct_ty,
                                                  lookup,
                                                  { b_.getInt64(0),
                                                    b_.getInt32(1) }));

    b_.CreateStore(b_.CreateAdd(total_val, expr),
                   b_.CreateGEP(avg_struct_ty,
                                lookup,
                                { b_.getInt64(0), b_.getInt32(0) }));
    b_.CreateStore(b_.CreateAdd(b_.getInt64(1), count_val),
                   b_.CreateGEP(avg_struct_ty,
                                lookup,
                                { b_.getInt64(0), b_.getInt32(1) }));

    b_.CreateBr(lookup_merge_block);

    b_.SetInsertPoint(lookup_failure_block);

    AllocaInst *avg_struct = b_.CreateAllocaBPF(avg_struct_ty, "avg_struct");

    b_.CreateStore(expr,
                   b_.CreateGEP(avg_struct_ty,
                                avg_struct,
                                { b_.getInt64(0), b_.getInt32(0) }));
    b_.CreateStore(b_.getInt64(1),
                   b_.CreateGEP(avg_struct_ty,
                                avg_struct,
                                { b_.getInt64(0), b_.getInt32(1) }));

    b_.CreateMapUpdateElem(
        ctx_, map.ident, scoped_key.value(), avg_struct, call.loc);

    b_.CreateLifetimeEnd(avg_struct);

    b_.CreateBr(lookup_merge_block);
    b_.SetInsertPoint(lookup_merge_block);

    return ScopedExpr();

  } else if (call.func == "hist") {
    if (!log2_func_)
      log2_func_ = createLog2Function();

    Map &map = *call.map;
    // There is only one log2_func_ so the second argument must be passed
    // as an argument even though it is a constant 0..5
    // Possible optimization is create one function per different value
    // of the second argument.
    ScopedExpr scoped_arg2 = visit(call.vargs.at(1));
    Value *k = b_.CreateIntCast(scoped_arg2.value(), b_.getInt64Ty(), false);

    ScopedExpr scoped_arg = visit(*call.vargs.front());
    // promote int to 64-bit
    Value *expr = b_.CreateIntCast(scoped_arg.value(),
                                   b_.getInt64Ty(),
                                   call.vargs.front()->type.IsSigned());
    Value *log2 = b_.CreateCall(log2_func_, { expr, k }, "log2");
    ScopedExpr scoped_key = getHistMapKey(map, log2, call.loc);
    b_.CreateMapElemAdd(
        ctx_, map, scoped_key.value(), b_.getInt64(1), call.loc);

    return ScopedExpr();

  } else if (call.func == "lhist") {
    if (!linear_func_)
      linear_func_ = createLinearFunction();

    Map &map = *call.map;

    // prepare arguments
    auto *value_arg = call.vargs.at(0);
    auto *min_arg = call.vargs.at(1);
    auto *max_arg = call.vargs.at(2);
    auto *step_arg = call.vargs.at(3);
    auto scoped_value_arg = visit(value_arg);
    auto scoped_min_arg = visit(min_arg);
    auto scoped_max_arg = visit(max_arg);
    auto scoped_step_arg = visit(step_arg);

    // promote int to 64-bit
    Value *value = b_.CreateIntCast(scoped_value_arg.value(),
                                    b_.getInt64Ty(),
                                    call.vargs.front()->type.IsSigned());
    Value *min = b_.CreateIntCast(scoped_min_arg.value(),
                                  b_.getInt64Ty(),
                                  false);
    Value *max = b_.CreateIntCast(scoped_max_arg.value(),
                                  b_.getInt64Ty(),
                                  false);
    Value *step = b_.CreateIntCast(scoped_step_arg.value(),
                                   b_.getInt64Ty(),
                                   false);

    Value *linear = b_.CreateCall(linear_func_,
                                  { value, min, max, step },
                                  "linear");

    ScopedExpr scoped_key = getHistMapKey(map, linear, call.loc);
    b_.CreateMapElemAdd(
        ctx_, map, scoped_key.value(), b_.getInt64(1), call.loc);

    return ScopedExpr();

  } else if (call.func == "delete") {
    auto &arg0 = *call.vargs.at(0);
    auto &map = static_cast<Map &>(arg0);
    // Current API: delete accepts two arguments except in the case of scalar
    // maps (maps with no keys) in which case it you can just pass it the map
    // and it will act similar to `clear` e.g. `delete(@scalar);`
    // Legacy API: delete accepts a single argument that is the map with a
    // key expression e.g. `delete(@mymap[1, 2]);` or no key if the map
    // is a scalar
    auto scoped_key = call.vargs.size() > 1 ? getMapKey(map, call.vargs.at(1))
                                            : getMapKey(map);
    if (!is_bpf_map_clearable(map_types_[map.ident])) {
      // store zero instead of calling bpf_map_delete_elem()
      auto val = b_.CreateWriteMapValueAllocation(map.type,
                                                  map.ident + "_zero",
                                                  call.loc);
      b_.CreateStore(Constant::getNullValue(b_.GetType(map.type)), val);
      b_.CreateMapUpdateElem(
          ctx_, map.ident, scoped_key.value(), val, call.loc);
      return ScopedExpr();
    } else {
      b_.CreateMapDeleteElem(ctx_, map, scoped_key.value(), call.loc);
      return ScopedExpr();
    }
  } else if (call.func == "has_key") {
    auto &arg = *call.vargs.at(0);
    auto &map = static_cast<Map &>(arg);
    auto scoped_key = getMapKey(map, call.vargs.at(1));

    CallInst *lookup = b_.CreateMapLookup(map, scoped_key.value());
    Value *expr = b_.CreateICmpNE(b_.CreateIntCast(lookup, b_.getPtrTy(), true),
                                  b_.GetNull(),
                                  "has_key");
    return ScopedExpr(expr);
  } else if (call.func == "str") {
    uint64_t max_strlen = bpftrace_.config_.get(ConfigKeyInt::max_strlen);
    // Largest read we'll allow = our global string buffer size
    Value *strlen = b_.getInt64(max_strlen);
    if (call.vargs.size() > 1) {
      auto scoped_arg = visit(call.vargs.at(1));
      Value *proposed_strlen = scoped_arg.value();

      // integer comparison: unsigned less-than-or-equal-to
      CmpInst::Predicate P = CmpInst::ICMP_ULE;
      // check whether proposed_strlen is less-than-or-equal-to maximum
      Value *Cmp = b_.CreateICmp(P, proposed_strlen, strlen, "str.min.cmp");
      // select proposed_strlen if it's sufficiently low, otherwise choose
      // maximum
      strlen = b_.CreateSelect(Cmp, proposed_strlen, strlen, "str.min.select");
    }

    Value *buf = b_.CreateGetStrAllocation("str", call.loc);
    b_.CreateMemsetBPF(buf, b_.getInt8(0), max_strlen);
    auto arg0 = call.vargs.front();
    auto scoped_expr = visit(call.vargs.front());
    b_.CreateProbeReadStr(
        ctx_, buf, strlen, scoped_expr.value(), arg0->type.GetAS(), call.loc);

    if (dyn_cast<AllocaInst>(buf))
      return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
    return ScopedExpr(buf);
  } else if (call.func == "buf") {
    const uint64_t max_strlen = bpftrace_.config_.get(ConfigKeyInt::max_strlen);
    // Subtract out metadata headroom
    uint64_t fixed_buffer_length = max_strlen - sizeof(AsyncEvent::Buf);
    Value *max_length = b_.getInt64(fixed_buffer_length);
    Value *length;

    if (call.vargs.size() > 1) {
      auto &arg = *call.vargs.at(1);
      auto scoped_expr = visit(&arg);

      Value *proposed_length = scoped_expr.value();
      if (arg.type.GetSize() != 8)
        proposed_length = b_.CreateZExt(proposed_length, max_length->getType());
      Value *cmp = b_.CreateICmp(
          CmpInst::ICMP_ULE, proposed_length, max_length, "length.cmp");
      length = b_.CreateSelect(
          cmp, proposed_length, max_length, "length.select");

      auto literal_length = bpftrace_.get_int_literal(&arg);
      if (literal_length)
        fixed_buffer_length = *literal_length;
    } else {
      auto &arg = *call.vargs.at(0);
      fixed_buffer_length = arg.type.GetNumElements() *
                            arg.type.GetElementTy()->GetSize();
      length = b_.getInt32(fixed_buffer_length);
    }

    Value *buf = b_.CreateGetStrAllocation("buf", call.loc);
    auto elements = AsyncEvent::Buf().asLLVMType(b_, fixed_buffer_length);
    std::ostringstream dynamic_sized_struct_name;
    dynamic_sized_struct_name << "buffer_" << fixed_buffer_length << "_t";
    StructType *buf_struct = b_.GetStructType(dynamic_sized_struct_name.str(),
                                              elements,
                                              true);

    Value *buf_len_offset = b_.CreateGEP(buf_struct,
                                         buf,
                                         { b_.getInt32(0), b_.getInt32(0) });
    length = b_.CreateIntCast(length, buf_struct->getElementType(0), false);
    b_.CreateStore(length, buf_len_offset);

    Value *buf_data_offset = b_.CreateGEP(buf_struct,
                                          buf,
                                          { b_.getInt32(0), b_.getInt32(1) });
    b_.CreateMemsetBPF(buf_data_offset, b_.getInt8(0), fixed_buffer_length);

    auto scoped_expr = visit(call.vargs.front());
    auto arg0 = call.vargs.front();
    b_.CreateProbeRead(ctx_,
                       buf_data_offset,
                       length,
                       scoped_expr.value(),
                       find_addrspace_stack(arg0->type),
                       call.loc);

    if (dyn_cast<AllocaInst>(buf))
      return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
    return ScopedExpr(buf);
  } else if (call.func == "path") {
    Value *buf = b_.CreateGetStrAllocation("path", call.loc);
    b_.CreateMemsetBPF(buf,
                       b_.getInt8(0),
                       bpftrace_.config_.get(ConfigKeyInt::max_strlen));
    const uint64_t max_size = bpftrace_.config_.get(ConfigKeyInt::max_strlen);
    Value *sz;
    if (call.vargs.size() > 1) {
      auto scoped_arg = visit(call.vargs.at(1));
      Value *pr_sz = b_.CreateIntCast(scoped_arg.value(),
                                      b_.getInt32Ty(),
                                      false);
      Value *max_sz = b_.getInt32(max_size);
      Value *cmp = b_.CreateICmp(
          CmpInst::ICMP_ULE, pr_sz, max_sz, "path.size.cmp");
      sz = b_.CreateSelect(cmp, pr_sz, max_sz, "path.size.select");
    } else {
      sz = b_.getInt32(max_size);
    }

    auto scoped_arg = visit(*call.vargs.front());
    Value *value = scoped_arg.value();
    b_.CreatePath(ctx_,
                  buf,
                  b_.CreateCast(value->getType()->isPointerTy()
                                    ? Instruction::BitCast
                                    : Instruction::IntToPtr,
                                value,
                                b_.getPtrTy()),
                  sz,
                  call.loc);

    if (dyn_cast<AllocaInst>(buf))
      return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
    return ScopedExpr(buf);
  } else if (call.func == "kaddr") {
    uint64_t addr;
    auto name = bpftrace_.get_string_literal(call.vargs.at(0));
    addr = bpftrace_.resolve_kname(name);
    if (!addr)
      throw FatalUserException("Failed to resolve kernel symbol: " + name);
    return ScopedExpr(b_.getInt64(addr));
  } else if (call.func == "percpu_kaddr") {
    auto name = bpftrace_.get_string_literal(call.vargs.at(0));
    auto var = DeclareKernelVar(name);
    Value *percpu_ptr;
    if (call.vargs.size() == 1) {
      percpu_ptr = b_.CreateThisCpuPtr(var, call.loc);
    } else {
      auto scoped_cpu = visit(call.vargs.at(1));
      percpu_ptr = b_.CreatePerCpuPtr(var, scoped_cpu.value(), call.loc);
    }
    return ScopedExpr(b_.CreatePtrToInt(percpu_ptr, b_.getInt64Ty()));
  } else if (call.func == "uaddr") {
    auto name = bpftrace_.get_string_literal(call.vargs.at(0));
    struct symbol sym = {};
    int err = bpftrace_.resolve_uname(name,
                                      &sym,
                                      current_attach_point_->target);
    if (err < 0 || sym.address == 0)
      throw FatalUserException("Could not resolve symbol: " +
                               current_attach_point_->target + ":" + name);
    return ScopedExpr(b_.getInt64(sym.address));
  } else if (call.func == "cgroupid") {
    uint64_t cgroupid;
    auto path = bpftrace_.get_string_literal(call.vargs.at(0));
    cgroupid = bpftrace_.resolve_cgroupid(path);
    return ScopedExpr(b_.getInt64(cgroupid));
  } else if (call.func == "join") {
    auto arg0 = call.vargs.front();
    auto scoped_arg = visit(arg0);
    auto addrspace = arg0->type.GetAS();

    llvm::Function *parent = b_.GetInsertBlock()->getParent();
    BasicBlock *failure_callback = BasicBlock::Create(module_->getContext(),
                                                      "failure_callback",
                                                      parent);
    Value *perfdata = b_.CreateGetJoinMap(failure_callback, call.loc);

    // arg0
    b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::join)), perfdata);
    b_.CreateStore(b_.getInt64(async_ids_.join()),
                   b_.CreateGEP(b_.getInt8Ty(), perfdata, b_.getInt64(8)));

    SizedType elem_type = CreatePointer(CreateInt8(), addrspace);
    size_t ptr_width = b_.getPointerStorageTy(addrspace)->getIntegerBitWidth();
    assert(b_.GetType(elem_type) == b_.getInt64Ty());

    // temporary that stores the value of arg[i]
    Value *value = scoped_arg.value();
    AllocaInst *arr = b_.CreateAllocaBPF(b_.getInt64Ty(), call.func + "_r0");
    b_.CreateProbeRead(ctx_, arr, elem_type, value, call.loc);
    b_.CreateProbeReadStr(
        ctx_,
        b_.CreateGEP(b_.getInt8Ty(), perfdata, b_.getInt64(8 + 8)),
        bpftrace_.join_argsize_,
        b_.CreateLoad(b_.getInt64Ty(), arr),
        addrspace,
        call.loc);

    for (unsigned int i = 1; i < bpftrace_.join_argnum_; i++) {
      // advance to the next array element
      value = b_.CreateAdd(value, b_.getInt64(ptr_width / 8));

      b_.CreateProbeRead(ctx_, arr, elem_type, value, call.loc);
      b_.CreateProbeReadStr(
          ctx_,
          b_.CreateGEP(b_.getInt8Ty(),
                       perfdata,
                       b_.getInt64(8 + 8 + i * bpftrace_.join_argsize_)),
          bpftrace_.join_argsize_,
          b_.CreateLoad(b_.getInt64Ty(), arr),
          addrspace,
          call.loc);
    }

    // emit
    b_.CreateOutput(ctx_,
                    perfdata,
                    8 + 8 + bpftrace_.join_argnum_ * bpftrace_.join_argsize_,
                    &call.loc);

    b_.CreateBr(failure_callback);

    // if we cannot find a valid map value, we will output nothing and continue
    b_.SetInsertPoint(failure_callback);
    return ScopedExpr();
  } else if (call.func == "ksym") {
    // We want to just pass through from the child node.
    return visit(call.vargs.front());
  } else if (call.func == "usym") {
    auto scoped_arg = visit(call.vargs.front());
    return ScopedExpr(
        b_.CreateUSym(ctx_, scoped_arg.value(), get_probe_id(), call.loc),
        std::move(scoped_arg));
  } else if (call.func == "ntop") {
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
    StructType *inet_struct = b_.GetStructType("inet", elements, false);

    AllocaInst *buf = b_.CreateAllocaBPF(inet_struct, "inet");

    Value *af_offset = b_.CreateGEP(inet_struct,
                                    buf,
                                    { b_.getInt64(0), b_.getInt32(0) });
    Value *af_type;

    auto inet = call.vargs.at(0);
    if (call.vargs.size() == 1) {
      if (inet->type.IsIntegerTy() || inet->type.GetSize() == 4) {
        af_type = b_.getInt64(AF_INET);
      } else {
        af_type = b_.getInt64(AF_INET6);
      }
    } else {
      inet = call.vargs.at(1);
      auto scoped_arg = visit(call.vargs.at(0));
      af_type = b_.CreateIntCast(scoped_arg.value(), b_.getInt64Ty(), true);
    }
    b_.CreateStore(af_type, af_offset);

    Value *inet_offset = b_.CreateGEP(inet_struct,
                                      buf,
                                      { b_.getInt32(0), b_.getInt32(1) });
    b_.CreateMemsetBPF(inet_offset, b_.getInt8(0), 16);

    auto scoped_inet = visit(inet);
    if (inet->type.IsArrayTy() || inet->type.IsStringTy()) {
      b_.CreateProbeRead(ctx_,
                         static_cast<AllocaInst *>(inet_offset),
                         inet->type,
                         scoped_inet.value(),
                         call.loc);
    } else {
      b_.CreateStore(
          b_.CreateIntCast(scoped_inet.value(), b_.getInt32Ty(), false),
          inet_offset);
    }

    return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
  } else if (call.func == "pton") {
    auto af_type = AF_INET;
    int addr_size = 4;
    std::string addr = bpftrace_.get_string_literal(call.vargs.at(0));
    if (addr.find(":") != std::string::npos) {
      af_type = AF_INET6;
      addr_size = 16;
    }

    llvm::Type *array_t = ArrayType::get(b_.getInt8Ty(), addr_size);
    AllocaInst *buf;
    if (af_type == AF_INET6) {
      buf = b_.CreateAllocaBPF(array_t, "addr6");
    } else {
      buf = b_.CreateAllocaBPF(array_t, "addr4");
    }

    std::vector<char> dst(addr_size);
    Value *octet;
    auto ret = inet_pton(af_type, addr.c_str(), dst.data());
    if (ret != 1) {
      throw FatalUserException("inet_pton() call returns " +
                               std::to_string(ret));
    }
    for (int i = 0; i < addr_size; i++) {
      octet = b_.getInt8(dst[i]);
      b_.CreateStore(
          octet,
          b_.CreateGEP(array_t, buf, { b_.getInt64(0), b_.getInt64(i) }));
    }

    return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
  } else if (call.func == "reg") {
    auto reg_name = bpftrace_.get_string_literal(call.vargs.at(0));
    int offset = arch::offset(reg_name);
    if (offset == -1) {
      throw FatalUserException("negative offset on reg() call");
    }

    return ScopedExpr(
        b_.CreateRegisterRead(ctx_, offset, call.func + "_" + reg_name));
  } else if (call.func == "printf") {
    // We overload printf call for iterator probe's seq_printf helper.
    if (!inside_subprog_ &&
        probetype(current_attach_point_->provider) == ProbeType::iter) {
      auto nargs = call.vargs.size() - 1;

      int ptr_size = sizeof(unsigned long);
      int data_size = 0;

      // create buffer to store the argument expression values
      SizedType data_type = CreateArray(nargs, CreateUInt64());
      AllocaInst *data = b_.CreateAllocaBPFInit(data_type, "data");

      std::vector<ScopedExpr> scoped_args;
      scoped_args.reserve(call.vargs.size());
      for (size_t i = 1; i < call.vargs.size(); i++) {
        // process argument expression
        Expression &arg = *call.vargs.at(i);
        auto scoped_arg = visit(&arg);
        Value *value = scoped_arg.value();

        // and store it to data area
        Value *offset = b_.CreateGEP(b_.GetType(data_type),
                                     data,
                                     { b_.getInt64(0), b_.getInt32(i - 1) });
        b_.CreateStore(value, offset);

        // keep the expression alive, so it's still there
        // for following seq_printf call
        scoped_args.emplace_back(std::move(scoped_arg));
        data_size += ptr_size;
      }

      // pick the current format string
      auto print_id = async_ids_.bpf_print();
      auto fmt = createFmtString(print_id);
      auto size = bpftrace_.resources.bpf_print_fmts.at(print_id).size() + 1;

      // and finally the seq_printf call
      b_.CreateSeqPrintf(ctx_,
                         b_.CreateIntToPtr(fmt, b_.getPtrTy()),
                         b_.getInt32(size),
                         data,
                         b_.getInt32(data_size),
                         call.loc);
      return ScopedExpr();

    } else {
      createFormatStringCall(call,
                             async_ids_.printf(),
                             bpftrace_.resources.printf_args,
                             "printf",
                             AsyncAction::printf);
      return ScopedExpr();
    }
  } else if (call.func == "debugf") {
    auto print_id = async_ids_.bpf_print();
    auto fmt = createFmtString(print_id);
    auto size = bpftrace_.resources.bpf_print_fmts.at(print_id).size() + 1;

    std::vector<Value *> values;
    std::vector<ScopedExpr> exprs;
    for (size_t i = 1; i < call.vargs.size(); i++) {
      Expression &arg = *call.vargs.at(i);
      auto scoped_expr = visit(arg);
      values.push_back(scoped_expr.value());
      exprs.emplace_back(std::move(scoped_expr));
    }

    b_.CreateTracePrintk(b_.CreateIntToPtr(fmt, b_.getPtrTy()),
                         b_.getInt32(size),
                         values,
                         call.loc);
    return ScopedExpr();
  } else if (call.func == "system") {
    createFormatStringCall(call,
                           async_ids_.system(),
                           bpftrace_.resources.system_args,
                           "system",
                           AsyncAction::syscall);
    return ScopedExpr();
  } else if (call.func == "cat") {
    createFormatStringCall(call,
                           async_ids_.cat(),
                           bpftrace_.resources.cat_args,
                           "cat",
                           AsyncAction::cat);
    return ScopedExpr();
  } else if (call.func == "exit") {
    auto elements = AsyncEvent::Exit().asLLVMType(b_);
    StructType *exit_struct = b_.GetStructType("exit_t", elements, true);
    AllocaInst *buf = b_.CreateAllocaBPF(exit_struct, "exit");
    size_t struct_size = datalayout().getTypeAllocSize(exit_struct);

    // Fill in exit struct.
    b_.CreateStore(
        b_.getInt64(asyncactionint(AsyncAction::exit)),
        b_.CreateGEP(exit_struct, buf, { b_.getInt64(0), b_.getInt32(0) }));

    Value *code = b_.getInt8(0);
    if (call.vargs.size() == 1) {
      auto scoped_expr = visit(call.vargs.at(0));
      code = scoped_expr.value();
    }
    b_.CreateStore(
        code,
        b_.CreateGEP(exit_struct, buf, { b_.getInt64(0), b_.getInt32(1) }));

    b_.CreateOutput(ctx_, buf, struct_size, &call.loc);
    b_.CreateLifetimeEnd(buf);

    createRet();

    // create an unreachable basic block for all the "dead instructions" that
    // may come after exit(). If we don't, LLVM will emit the instructions
    // leading to a `unreachable insn` warning from the verifier
    BasicBlock *deadcode = BasicBlock::Create(module_->getContext(),
                                              "deadcode",
                                              b_.GetInsertBlock()->getParent());
    b_.SetInsertPoint(deadcode);
    return ScopedExpr();
  } else if (call.func == "print") {
    auto &arg = *call.vargs.at(0);
    if (arg.is_map) {
      auto &map = static_cast<Map &>(arg);
      if (map.key_expr)
        createPrintNonMapCall(call, async_ids_.non_map_print());
      else
        createPrintMapCall(call);
    } else {
      createPrintNonMapCall(call, async_ids_.non_map_print());
    }
    return ScopedExpr();
  } else if (call.func == "cgroup_path") {
    auto elements = AsyncEvent::CgroupPath().asLLVMType(b_);
    StructType *cgroup_path_struct = b_.GetStructType(call.func + "_t",
                                                      elements,
                                                      true);
    AllocaInst *buf = b_.CreateAllocaBPF(cgroup_path_struct,
                                         call.func + "_args");

    // Store cgroup path event id
    b_.CreateStore(b_.GetIntSameSize(async_ids_.cgroup_path(), elements.at(0)),
                   b_.CreateGEP(cgroup_path_struct,
                                buf,
                                { b_.getInt64(0), b_.getInt32(0) }));

    // Store cgroup id
    auto arg = call.vargs.at(0);
    auto scoped_expr = visit(arg);
    b_.CreateStore(scoped_expr.value(),
                   b_.CreateGEP(cgroup_path_struct,
                                buf,
                                { b_.getInt64(0), b_.getInt32(1) }));

    return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
  } else if (call.func == "clear" || call.func == "zero") {
    auto elements = AsyncEvent::MapEvent().asLLVMType(b_);
    StructType *event_struct = b_.GetStructType(call.func + "_t",
                                                elements,
                                                true);

    auto &arg = *call.vargs.at(0);
    auto &map = static_cast<Map &>(arg);

    AllocaInst *buf = b_.CreateAllocaBPF(event_struct,
                                         call.func + "_" + map.ident);

    auto aa_ptr = b_.CreateGEP(event_struct,
                               buf,
                               { b_.getInt64(0), b_.getInt32(0) });
    if (call.func == "clear")
      b_.CreateStore(b_.GetIntSameSize(asyncactionint(AsyncAction::clear),
                                       elements.at(0)),
                     aa_ptr);
    else
      b_.CreateStore(b_.GetIntSameSize(asyncactionint(AsyncAction::zero),
                                       elements.at(0)),
                     aa_ptr);

    int id = bpftrace_.resources.maps_info.at(map.ident).id;
    if (id == -1) {
      LOG(BUG) << "map id for map \"" << map.ident << "\" not found";
    }
    auto *ident_ptr = b_.CreateGEP(event_struct,
                                   buf,
                                   { b_.getInt64(0), b_.getInt32(1) });
    b_.CreateStore(b_.GetIntSameSize(id, elements.at(1)), ident_ptr);

    b_.CreateOutput(ctx_, buf, getStructSize(event_struct), &call.loc);
    return ScopedExpr(buf, [this, buf] { b_.CreateLifetimeEnd(buf); });
  } else if (call.func == "len") {
    if (call.vargs.at(0)->type.IsStack()) {
      auto *arg = call.vargs.at(0);
      auto scoped_arg = visit(arg);

      auto *stack_key_struct = b_.GetStackStructType(arg->type.IsUstackTy());
      Value *nr_stack_frames = b_.CreateGEP(stack_key_struct,
                                            scoped_arg.value(),
                                            { b_.getInt64(0), b_.getInt32(1) });
      return ScopedExpr(
          b_.CreateIntCast(b_.CreateLoad(b_.getInt64Ty(), nr_stack_frames),
                           b_.getInt64Ty(),
                           false));
    } else /* call.vargs.at(0)->is_map */ {
      auto &arg = *call.vargs.at(0);
      auto &map = static_cast<Map &>(arg);

      // Some map types used in bpftrace (BPF_MAP_TYPE_(PERCPU_)ARRAY) do not
      // implement per-cpu counters and bpf_map_sum_elem_count would always
      // return 0 for them. In our case, those maps typically have a single
      // element so we can return 1 straight away.
      // For the rest, use bpf_map_sum_elem_count if available and map supports
      // it, otherwise fall back to bpf_for_each_map_elem with a custom callback
      if (map_has_single_elem(map.type, map.key_type)) {
        return ScopedExpr(b_.getInt64(1));
      } else if (bpftrace_.feature_->has_kernel_func(
                     Kfunc::bpf_map_sum_elem_count) &&
                 !is_array_map(map.type, map.key_type)) {
        return ScopedExpr(CreateKernelFuncCall(Kfunc::bpf_map_sum_elem_count,
                                               { b_.GetMapVar(map.ident) },
                                               "len"));
      } else {
        if (!map_len_func_)
          map_len_func_ = createMapLenCallback();

        return ScopedExpr(b_.CreateForEachMapElem(
            ctx_, map, map_len_func_, nullptr, call.loc));
      }
    }
  } else if (call.func == "time") {
    auto elements = AsyncEvent::Time().asLLVMType(b_);
    StructType *time_struct = b_.GetStructType(call.func + "_t",
                                               elements,
                                               true);

    AllocaInst *buf = b_.CreateAllocaBPF(time_struct, call.func + "_t");

    b_.CreateStore(
        b_.GetIntSameSize(asyncactionint(AsyncAction::time), elements.at(0)),
        b_.CreateGEP(time_struct, buf, { b_.getInt64(0), b_.getInt32(0) }));

    b_.CreateStore(
        b_.GetIntSameSize(async_ids_.time(), elements.at(1)),
        b_.CreateGEP(time_struct, buf, { b_.getInt64(0), b_.getInt32(1) }));

    b_.CreateOutput(ctx_, buf, getStructSize(time_struct), &call.loc);
    return ScopedExpr(buf, [this, buf] { b_.CreateLifetimeEnd(buf); });
  } else if (call.func == "strftime") {
    auto elements = AsyncEvent::Strftime().asLLVMType(b_);
    StructType *strftime_struct = b_.GetStructType(call.func + "_t",
                                                   elements,
                                                   true);

    AllocaInst *buf = b_.CreateAllocaBPF(strftime_struct, call.func + "_args");
    b_.CreateStore(
        b_.GetIntSameSize(async_ids_.strftime(), elements.at(0)),
        b_.CreateGEP(strftime_struct, buf, { b_.getInt64(0), b_.getInt32(0) }));
    b_.CreateStore(
        b_.GetIntSameSize(
            static_cast<std::underlying_type<TimestampMode>::type>(
                call.type.ts_mode),
            elements.at(1)),
        b_.CreateGEP(strftime_struct, buf, { b_.getInt64(0), b_.getInt32(1) }));
    auto &arg = *call.vargs.at(1);
    auto scoped_expr = visit(arg);
    b_.CreateStore(
        scoped_expr.value(),
        b_.CreateGEP(strftime_struct, buf, { b_.getInt64(0), b_.getInt32(2) }));
    return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
  } else if (call.func == "kstack" || call.func == "ustack") {
    return kstack_ustack(call.func, call.type.stack_type, call.loc);
  } else if (call.func == "signal") {
    // long bpf_send_signal(u32 sig)
    auto &arg = *call.vargs.at(0);
    if (arg.type.IsStringTy()) {
      auto signame = bpftrace_.get_string_literal(&arg);
      int sigid = signal_name_to_num(signame);
      // Should be caught in semantic analyser
      if (sigid < 1) {
        LOG(BUG) << "Invalid signal ID for \"" << signame << "\"";
      }
      b_.CreateSignal(ctx_, b_.getInt32(sigid), call.loc);
      return ScopedExpr();
    }
    auto scoped_arg = visit(arg);
    Value *sig_number = b_.CreateIntCast(scoped_arg.value(),
                                         b_.getInt32Ty(),
                                         arg.type.IsSigned());
    b_.CreateSignal(ctx_, sig_number, call.loc);
    return ScopedExpr();
  } else if (call.func == "strerror") {
    return visit(call.vargs.front());
  } else if (call.func == "strncmp") {
    auto &left_arg = *call.vargs.at(0);
    auto &right_arg = *call.vargs.at(1);
    auto size_opt = bpftrace_.get_int_literal(call.vargs.at(2));
    if (!size_opt.has_value())
      LOG(BUG) << "Int literal should have been checked in semantic analysis";
    uint64_t size = std::min({ static_cast<uint64_t>(*size_opt),
                               left_arg.type.GetSize(),
                               right_arg.type.GetSize() });

    auto left_string = visit(&left_arg);
    auto right_string = visit(&right_arg);

    return ScopedExpr(b_.CreateStrncmp(
        left_string.value(), right_string.value(), size, false));
  } else if (call.func == "strcontains") {
    auto &left_arg = *call.vargs.at(0);
    auto &right_arg = *call.vargs.at(1);

    auto left_string = visit(left_arg);
    auto right_string = visit(right_arg);

    return ScopedExpr(b_.CreateStrcontains(left_string.value(),
                                           left_arg.type.GetSize(),
                                           right_string.value(),
                                           right_arg.type.GetSize()));
  } else if (call.func == "override") {
    // long bpf_override(struct pt_regs *regs, u64 rc)
    // returns: 0
    auto &arg = *call.vargs.at(0);
    auto scoped_arg = visit(arg);
    auto expr = b_.CreateIntCast(scoped_arg.value(),
                                 b_.getInt64Ty(),
                                 arg.type.IsSigned());
    b_.CreateOverrideReturn(ctx_, expr);
    return ScopedExpr();
  } else if (call.func == "kptr" || call.func == "uptr") {
    return visit(call.vargs.at(0));
  } else if (call.func == "macaddr") {
    // MAC addresses are presented as char[6]
    AllocaInst *buf = b_.CreateAllocaBPFInit(call.type, "macaddr");
    auto macaddr = call.vargs.front();
    auto scoped_arg = visit(macaddr);

    if (inBpfMemory(macaddr->type))
      b_.CreateMemcpyBPF(buf, scoped_arg.value(), macaddr->type.GetSize());
    else
      b_.CreateProbeRead(ctx_,
                         static_cast<AllocaInst *>(buf),
                         macaddr->type,
                         scoped_arg.value(),
                         call.loc);

    return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
  } else if (call.func == "unwatch") {
    auto scoped_addr = visit(call.vargs.at(0));

    auto elements = AsyncEvent::WatchpointUnwatch().asLLVMType(b_);
    StructType *unwatch_struct = b_.GetStructType("unwatch_t", elements, true);
    AllocaInst *buf = b_.CreateAllocaBPF(unwatch_struct, "unwatch");
    size_t struct_size = datalayout().getTypeAllocSize(unwatch_struct);

    b_.CreateStore(
        b_.getInt64(asyncactionint(AsyncAction::watchpoint_detach)),
        b_.CreateGEP(unwatch_struct, buf, { b_.getInt64(0), b_.getInt32(0) }));
    b_.CreateStore(
        b_.CreateIntCast(scoped_addr.value(),
                         b_.getInt64Ty(),
                         false /* unsigned */),
        b_.CreateGEP(unwatch_struct, buf, { b_.getInt64(0), b_.getInt32(1) }));
    b_.CreateOutput(ctx_, buf, struct_size, &call.loc);
    return ScopedExpr(buf, [this, buf] { b_.CreateLifetimeEnd(buf); });
  } else if (call.func == "bswap") {
    bpftrace::ast::Expression *arg = call.vargs.at(0);
    auto scoped_arg = visit(call.vargs.at(0));

    assert(arg->type.IsIntegerTy());
    if (arg->type.GetSize() > 1) {
      llvm::Type *arg_type = b_.GetType(arg->type);
#if LLVM_VERSION_MAJOR >= 20
      llvm::Function *swap_fun = Intrinsic::getOrInsertDeclaration(
          module_.get(), Intrinsic::bswap, { arg_type });
#else
      llvm::Function *swap_fun = Intrinsic::getDeclaration(module_.get(),
                                                           Intrinsic::bswap,
                                                           { arg_type });
#endif

      return ScopedExpr(b_.CreateCall(swap_fun, { scoped_arg.value() }),
                        std::move(scoped_arg));
    }
    return scoped_arg;
  } else if (call.func == "skboutput") {
    auto elements = AsyncEvent::SkbOutput().asLLVMType(b_);
    StructType *hdr_t = b_.GetStructType("hdr_t", elements, false);
    AllocaInst *data = b_.CreateAllocaBPF(hdr_t, "hdr");

    // The extra 0 here ensures the type of addr_offset will be int64
    Value *aid_addr = b_.CreateGEP(hdr_t,
                                   data,
                                   { b_.getInt64(0), b_.getInt32(0) });
    Value *id_addr = b_.CreateGEP(hdr_t,
                                  data,
                                  { b_.getInt64(0), b_.getInt32(1) });
    Value *time_addr = b_.CreateGEP(hdr_t,
                                    data,
                                    { b_.getInt64(0), b_.getInt32(2) });

    b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::skboutput)),
                   aid_addr);
    b_.CreateStore(b_.getInt64(async_ids_.skb_output()), id_addr);
    b_.CreateStore(b_.CreateGetNs(TimestampMode::boot, call.loc), time_addr);

    auto scoped_skb = visit(call.vargs.at(1));
    auto scoped_arg_len = visit(call.vargs.at(2));
    Value *len = b_.CreateIntCast(scoped_arg_len.value(),
                                  b_.getInt64Ty(),
                                  false);
    Value *ret = b_.CreateSkbOutput(
        scoped_skb.value(), len, data, getStructSize(hdr_t));
    return ScopedExpr(ret);
  } else if (call.func == "nsecs") {
    if (call.type.ts_mode == TimestampMode::sw_tai) {
      if (!bpftrace_.delta_taitime_.has_value())
        LOG(BUG) << "Should have been checked in semantic analysis";
      uint64_t delta = bpftrace_.delta_taitime_->tv_sec * 1e9 +
                       bpftrace_.delta_taitime_->tv_nsec;
      Value *ns = b_.CreateGetNs(TimestampMode::boot, call.loc);
      return ScopedExpr(b_.CreateAdd(ns, b_.getInt64(delta)));
    } else {
      return ScopedExpr(b_.CreateGetNs(call.type.ts_mode, call.loc));
    }
  } else {
    LOG(BUG) << "missing codegen for function \"" << call.func << "\"";
    __builtin_unreachable();
  }
}

ScopedExpr CodegenLLVM::visit(Sizeof &szof)
{
  return ScopedExpr(b_.getInt64(szof.argtype.GetSize()));
}

ScopedExpr CodegenLLVM::visit(Offsetof &offof)
{
  ssize_t offset = 0;
  const SizedType *record = &offof.record;
  for (const auto &field : offof.field) {
    offset += record->GetField(field).offset;
    record = &record->GetField(field).type;
  }
  return ScopedExpr(b_.getInt64(offset));
}

ScopedExpr CodegenLLVM::visit(Map &map)
{
  auto scoped_key = getMapKey(map);

  auto map_info = bpftrace_.resources.maps_info.find(map.ident);
  if (map_info == bpftrace_.resources.maps_info.end()) {
    LOG(BUG) << "map name: \"" << map.ident << "\" not found";
  }

  const auto &val_type = map_info->second.value_type;
  Value *value;
  if (canAggPerCpuMapElems(val_type, map_info->second.key_type)) {
    value = b_.CreatePerCpuMapAggElems(
        ctx_, map, scoped_key.value(), val_type, map.loc);
  } else {
    value = b_.CreateMapLookupElem(ctx_, map, scoped_key.value(), map.loc);
  }

  return ScopedExpr(value, [this, value] {
    if (dyn_cast<AllocaInst>(value))
      b_.CreateLifetimeEnd(value);
  });
}

ScopedExpr CodegenLLVM::visit(Variable &var)
{
  // Arrays and structs are not memcopied for local variables
  if (needMemcpy(var.type) &&
      !(var.type.IsArrayTy() || var.type.IsRecordTy())) {
    return ScopedExpr(getVariable(var.ident).value);
  } else {
    auto &var_llvm = getVariable(var.ident);
    return ScopedExpr(b_.CreateLoad(var_llvm.type, var_llvm.value));
  }
}

ScopedExpr CodegenLLVM::binop_string(Binop &binop)
{
  if (binop.op != Operator::EQ && binop.op != Operator::NE) {
    LOG(BUG) << "missing codegen to string operator \"" << opstr(binop) << "\"";
  }

  // strcmp returns 0 when strings are equal
  bool inverse = binop.op == Operator::EQ;

  auto left_string = visit(binop.left);
  auto right_string = visit(binop.right);

  size_t len = std::min(binop.left->type.GetSize(),
                        binop.right->type.GetSize());
  return ScopedExpr(b_.CreateStrncmp(
      left_string.value(), right_string.value(), len, inverse));
}

ScopedExpr CodegenLLVM::binop_integer_array(Binop &binop)
{
  assert(binop.op == Operator::EQ || binop.op == Operator::NE);

  // integer array compare returns 0 when arrays are equal
  bool inverse = binop.op == Operator::EQ;

  auto scoped_left = visit(binop.left);
  auto scoped_right = visit(binop.right);
  Value *left_array_val = scoped_left.value();
  Value *right_array_val = scoped_right.value();
  auto &left_array_ty = binop.left->type;
  auto &right_array_ty = binop.right->type;

  assert(left_array_ty.GetNumElements() == right_array_ty.GetNumElements());
  assert(left_array_ty.GetElementTy()->GetSize() ==
         right_array_ty.GetElementTy()->GetSize());

  return ScopedExpr(b_.CreateIntegerArrayCmp(ctx_,
                                             left_array_val,
                                             right_array_val,
                                             left_array_ty,
                                             right_array_ty,
                                             inverse,
                                             binop.loc,
                                             createLoopMetadata()));
}

ScopedExpr CodegenLLVM::binop_buf(Binop &binop)
{
  if (binop.op != Operator::EQ && binop.op != Operator::NE) {
    LOG(BUG) << "missing codegen to buffer operator \"" << opstr(binop) << "\"";
  }

  // strcmp returns 0 when strings are equal
  bool inverse = binop.op == Operator::EQ;

  auto scoped_left = visit(binop.left);
  auto scoped_right = visit(binop.right);
  Value *left_string = scoped_left.value();
  Value *right_string = scoped_right.value();

  size_t len = std::min(binop.left->type.GetSize(),
                        binop.right->type.GetSize());
  return ScopedExpr(b_.CreateStrncmp(left_string, right_string, len, inverse));
}

ScopedExpr CodegenLLVM::binop_int(Binop &binop)
{
  auto scoped_left = visit(binop.left);
  auto scoped_right = visit(binop.right);
  Value *lhs = scoped_left.value();
  Value *rhs = scoped_right.value();

  // If left or right is PositionalParameter, that means the syntax is:
  //   str($1 + num) or str(num + $1)
  // The positional params returns a pointer to a buffer, and the buffer should
  // live until str() is accepted. Extend the lifetime of the buffer by moving
  // these into the deletion scoped, where they will run once the value is
  // consumed.
  auto del = [l = std::move(scoped_left), r = std::move(scoped_right)] {};

  bool lsign = binop.left->type.IsSigned();
  bool rsign = binop.right->type.IsSigned();
  bool do_signed = lsign && rsign;

  // Promote operands if necessary
  auto size = binop.type.GetSize();
  lhs = b_.CreateIntCast(lhs, b_.getIntNTy(size * 8), lsign);
  rhs = b_.CreateIntCast(rhs, b_.getIntNTy(size * 8), rsign);

  switch (binop.op) {
    case Operator::EQ:
      return ScopedExpr(b_.CreateICmpEQ(lhs, rhs), std::move(del));
    case Operator::NE:
      return ScopedExpr(b_.CreateICmpNE(lhs, rhs), std::move(del));
    case Operator::LE:
      return ScopedExpr(do_signed ? b_.CreateICmpSLE(lhs, rhs)
                                  : b_.CreateICmpULE(lhs, rhs),
                        std::move(del));
    case Operator::GE:
      return ScopedExpr(do_signed ? b_.CreateICmpSGE(lhs, rhs)
                                  : b_.CreateICmpUGE(lhs, rhs),
                        std::move(del));
    case Operator::LT:
      return ScopedExpr(do_signed ? b_.CreateICmpSLT(lhs, rhs)
                                  : b_.CreateICmpULT(lhs, rhs),
                        std::move(del));
    case Operator::GT:
      return ScopedExpr(do_signed ? b_.CreateICmpSGT(lhs, rhs)
                                  : b_.CreateICmpUGT(lhs, rhs),
                        std::move(del));
    case Operator::LEFT:
      return ScopedExpr(b_.CreateShl(lhs, rhs), std::move(del));
    case Operator::RIGHT:
      return ScopedExpr(b_.CreateLShr(lhs, rhs), std::move(del));
    case Operator::PLUS:
      return ScopedExpr(b_.CreateAdd(lhs, rhs), std::move(del));
    case Operator::MINUS:
      return ScopedExpr(b_.CreateSub(lhs, rhs), std::move(del));
    case Operator::MUL:
      return ScopedExpr(b_.CreateMul(lhs, rhs), std::move(del));
    case Operator::DIV:
      return ScopedExpr(b_.CreateUDiv(lhs, rhs), std::move(del));
    case Operator::MOD:
      // Always do an unsigned modulo operation here even if `do_signed`
      // is true. bpf instruction set does not support signed division.
      // We already warn in the semantic analyser that signed modulo can
      // lead to undefined behavior (because we will treat it as unsigned).
      return ScopedExpr(b_.CreateURem(lhs, rhs), std::move(del));
    case Operator::BAND:
      return ScopedExpr(b_.CreateAnd(lhs, rhs), std::move(del));
    case Operator::BOR:
      return ScopedExpr(b_.CreateOr(lhs, rhs), std::move(del));
    case Operator::BXOR:
      return ScopedExpr(b_.CreateXor(lhs, rhs), std::move(del));
    default:
      LOG(BUG) << "\"" << opstr(binop) << "\" was handled earlier";
      __builtin_unreachable();
  }
}

ScopedExpr CodegenLLVM::binop_ptr(Binop &binop)
{
  auto compare = false;
  auto arith = false;

  // Do what C does
  switch (binop.op) {
    case Operator::EQ:
    case Operator::NE:
    case Operator::LE:
    case Operator::GE:
    case Operator::LT:
    case Operator::GT:
      compare = true;
      break;
    case Operator::LEFT:
    case Operator::RIGHT:
    case Operator::MOD:
    case Operator::BAND:
    case Operator::BOR:
    case Operator::BXOR:
    case Operator::MUL:
    case Operator::DIV:
      LOG(BUG) << "binop_ptr: op not implemented for type\"" << opstr(binop)
               << "\"";
      break;
    case Operator::PLUS:
    case Operator::MINUS:
      arith = true;
      break;
    default:
      LOG(BUG) << "binop_ptr invalid op \"" << opstr(binop) << "\"";
  }

  auto scoped_left = visit(binop.left);
  auto scoped_right = visit(binop.right);
  Value *lhs = scoped_left.value();
  Value *rhs = scoped_right.value();

  // note: the semantic phase blocks invalid combinations
  if (compare) {
    switch (binop.op) {
      case Operator::EQ:
        return ScopedExpr(b_.CreateICmpEQ(lhs, rhs));
      case Operator::NE:
        return ScopedExpr(b_.CreateICmpNE(lhs, rhs));
      case Operator::LE: {
        return ScopedExpr(b_.CreateICmpULE(lhs, rhs));
      }
      case Operator::GE: {
        return ScopedExpr(b_.CreateICmpUGE(lhs, rhs));
      }
      case Operator::LT: {
        return ScopedExpr(b_.CreateICmpULT(lhs, rhs));
      }
      case Operator::GT: {
        return ScopedExpr(b_.CreateICmpUGT(lhs, rhs));
      }
      default:
        LOG(BUG) << "invalid op \"" << opstr(binop) << "\"";
        __builtin_unreachable();
    }
  } else if (arith) {
    // Cannot use GEP here as LLVM doesn't know its a pointer
    bool leftptr = binop.left->type.IsPtrTy();
    auto &ptr_ty = leftptr ? binop.left->type : binop.right->type;
    auto &other_ty = leftptr ? binop.right->type : binop.left->type;
    Value *ptr_expr = leftptr ? lhs : rhs;
    Value *other_expr = leftptr ? rhs : lhs;

    if (other_ty.IsIntTy() && other_ty.GetSize() != 8)
      other_expr = b_.CreateZExt(other_expr, b_.getInt64Ty());
    Value *expr = b_.CreatePtrOffset(*ptr_ty.GetPointeeTy(),
                                     other_expr,
                                     ptr_ty.GetAS());
    if (binop.op == Operator::PLUS)
      return ScopedExpr(b_.CreateAdd(ptr_expr, expr));
    else
      return ScopedExpr(b_.CreateSub(ptr_expr, expr));
  } else {
    LOG(BUG) << "unknown op \"" << opstr(binop) << "\"";
    __builtin_unreachable();
  }
}

ScopedExpr CodegenLLVM::visit(Binop &binop)
{
  // Handle && and || separately so short circuiting works
  if (binop.op == Operator::LAND) {
    return createLogicalAnd(binop);
  } else if (binop.op == Operator::LOR) {
    return createLogicalOr(binop);
  }

  SizedType &type = binop.left->type;
  if (binop.left->type.IsPtrTy() || binop.right->type.IsPtrTy()) {
    return binop_ptr(binop);
  } else if (type.IsStringTy()) {
    return binop_string(binop);
  } else if (type.IsBufferTy()) {
    return binop_buf(binop);
  } else if (type.IsArrayTy() && type.GetElementTy()->IsIntegerTy()) {
    return binop_integer_array(binop);
  } else {
    return binop_int(binop);
  }
}

ScopedExpr CodegenLLVM::unop_int(Unop &unop)
{
  SizedType &type = unop.expr->type;
  switch (unop.op) {
    case Operator::LNOT: {
      ScopedExpr scoped_expr = visit(unop.expr);
      auto ty = scoped_expr.value()->getType();
      Value *zero_value = Constant::getNullValue(ty);
      Value *expr = b_.CreateICmpEQ(scoped_expr.value(), zero_value);
      // CreateICmpEQ() returns 1-bit integer
      // Cast it to the same type of the operand
      // Use unsigned extension, otherwise !0 becomes -1
      return ScopedExpr(b_.CreateIntCast(expr, ty, false));
    }
    case Operator::BNOT: {
      ScopedExpr scoped_expr = visit(unop.expr);
      return ScopedExpr(b_.CreateNot(scoped_expr.value()));
    }
    case Operator::MINUS: {
      ScopedExpr scoped_expr = visit(unop.expr);
      return ScopedExpr(b_.CreateNeg(scoped_expr.value()));
    }
    case Operator::INCREMENT:
    case Operator::DECREMENT: {
      return createIncDec(unop);
    }
    case Operator::MUL: {
      // When dereferencing a 32-bit integer, only read in 32-bits, etc.
      ScopedExpr scoped_expr = visit(unop.expr);
      auto dst_type = SizedType(type.GetTy(), type.GetSize());
      AllocaInst *dst = b_.CreateAllocaBPF(dst_type, "deref");
      b_.CreateProbeRead(ctx_, dst, type, scoped_expr.value(), unop.loc);
      Value *value = b_.CreateIntCast(b_.CreateLoad(b_.GetType(dst_type), dst),
                                      b_.getInt64Ty(),
                                      type.IsSigned());
      b_.CreateLifetimeEnd(dst);
      return ScopedExpr(value);
    }
    default:
      LOG(BUG) << "unop_int: invalid op \"" << opstr(unop) << "\"";
      __builtin_unreachable();
  }
}

ScopedExpr CodegenLLVM::unop_ptr(Unop &unop)
{
  SizedType &type = unop.expr->type;
  switch (unop.op) {
    case Operator::MUL: {
      ScopedExpr scoped_expr = visit(unop.expr);
      if (unop.type.IsIntegerTy() || unop.type.IsPtrTy()) {
        auto *et = type.GetPointeeTy();
        AllocaInst *dst = b_.CreateAllocaBPF(*et, "deref");
        b_.CreateProbeRead(
            ctx_, dst, *et, scoped_expr.value(), unop.loc, type.GetAS());
        Value *value = b_.CreateLoad(b_.GetType(*et), dst);
        b_.CreateLifetimeEnd(dst);
        return ScopedExpr(value);
      }
      return scoped_expr; // Pass as is.
    }
    case Operator::INCREMENT:
    case Operator::DECREMENT:
      return createIncDec(unop);
    default:
      return visit(unop.expr);
  }
}

ScopedExpr CodegenLLVM::visit(Unop &unop)
{
  SizedType &type = unop.expr->type;
  if (type.IsIntegerTy()) {
    return unop_int(unop);
  } else if (type.IsPtrTy() || type.IsCtxAccess()) // allow dereferencing args
  {
    return unop_ptr(unop);
  } else {
    LOG(BUG) << "invalid type (" << type << ") passed to unary operator \""
             << opstr(unop) << "\"";
    __builtin_unreachable();
  }
}

ScopedExpr CodegenLLVM::visit(Ternary &ternary)
{
  llvm::Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *left_block = BasicBlock::Create(module_->getContext(),
                                              "left",
                                              parent);
  BasicBlock *right_block = BasicBlock::Create(module_->getContext(),
                                               "right",
                                               parent);
  BasicBlock *done = BasicBlock::Create(module_->getContext(), "done", parent);

  // ordering of all the following statements is important
  Value *buf = nullptr;
  if (ternary.type.IsStringTy()) {
    buf = b_.CreateGetStrAllocation("buf", ternary.loc);
    uint64_t max_strlen = bpftrace_.config_.get(ConfigKeyInt::max_strlen);
    b_.CreateMemsetBPF(buf, b_.getInt8(0), max_strlen);
  } else if (!ternary.type.IsIntTy() && !ternary.type.IsNoneTy()) {
    buf = b_.CreateAllocaBPF(ternary.type);
    b_.CreateMemsetBPF(buf, b_.getInt8(0), ternary.type.GetSize());
  }

  auto scoped_expr = visit(ternary.cond);
  Value *cond = scoped_expr.value();
  Value *zero_value = Constant::getNullValue(cond->getType());
  b_.CreateCondBr(b_.CreateICmpNE(cond, zero_value, "true_cond"),
                  left_block,
                  right_block);

  if (ternary.type.IsIntTy()) {
    // fetch selected integer via CreateStore
    b_.SetInsertPoint(left_block);
    auto scoped_left = visit(ternary.left);
    auto left_expr = b_.CreateIntCast(scoped_left.value(),
                                      b_.GetType(ternary.type),
                                      ternary.type.IsSigned());
    b_.CreateBr(done);

    b_.SetInsertPoint(right_block);
    auto scoped_right = visit(ternary.right);
    auto right_expr = b_.CreateIntCast(scoped_right.value(),
                                       b_.GetType(ternary.type),
                                       ternary.type.IsSigned());
    b_.CreateBr(done);

    b_.SetInsertPoint(done);
    auto phi = b_.CreatePHI(b_.GetType(ternary.type), 2, "result");
    phi->addIncoming(left_expr, left_block);
    phi->addIncoming(right_expr, right_block);
    return ScopedExpr(phi);
  } else if (ternary.type.IsNoneTy()) {
    // Type::none
    b_.SetInsertPoint(left_block);
    visit(*ternary.left);
    b_.CreateBr(done);
    b_.SetInsertPoint(right_block);
    visit(*ternary.right);
    b_.CreateBr(done);
    b_.SetInsertPoint(done);
    return ScopedExpr();
  } else {
    b_.SetInsertPoint(left_block);
    auto scoped_left = visit(ternary.left);
    if (ternary.type.IsTupleTy()) {
      createTupleCopy(
          ternary.left->type, ternary.type, buf, scoped_left.value());
    } else if (needMemcpy(ternary.type)) {
      b_.CreateMemcpyBPF(buf, scoped_left.value(), ternary.type.GetSize());
    } else {
      b_.CreateStore(scoped_left.value(), buf);
    }
    b_.CreateBr(done);

    b_.SetInsertPoint(right_block);
    auto scoped_right = visit(ternary.right);
    if (ternary.type.IsTupleTy()) {
      createTupleCopy(
          ternary.right->type, ternary.type, buf, scoped_right.value());
    } else if (needMemcpy(ternary.type)) {
      b_.CreateMemcpyBPF(buf, scoped_right.value(), ternary.type.GetSize());
    } else {
      b_.CreateStore(scoped_right.value(), buf);
    }
    b_.CreateBr(done);

    b_.SetInsertPoint(done);
    if (dyn_cast<AllocaInst>(buf))
      return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
    return ScopedExpr(buf);
  }
}

ScopedExpr CodegenLLVM::visit(FieldAccess &acc)
{
  SizedType &type = acc.expr->type;
  AddrSpace addrspace = acc.expr->type.GetAS();
  assert(type.IsRecordTy() || type.IsTupleTy());
  auto scoped_arg = visit(*acc.expr);

  bool is_ctx = type.IsCtxAccess();
  bool is_tparg = type.is_tparg;
  bool is_internal = type.is_internal;
  bool is_funcarg = type.is_funcarg;
  bool is_btftype = type.is_btftype;
  assert(type.IsRecordTy() || type.IsTupleTy());

  if (type.is_funcarg) {
    auto probe_type = probetype(current_attach_point_->provider);
    if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit)
      return ScopedExpr(b_.CreateKFuncArg(ctx_, acc.type, acc.field),
                        std::move(scoped_arg));
    else if (probe_type == ProbeType::uprobe) {
      llvm::Type *args_type = b_.UprobeArgsType(type);
      return readDatastructElemFromStack(std::move(scoped_arg),
                                         b_.getInt32(acc.type.funcarg_idx),
                                         args_type,
                                         acc.type);
    }
  } else if (type.IsTupleTy()) {
    Value *src = b_.CreateGEP(b_.GetType(type),
                              scoped_arg.value(),
                              { b_.getInt32(0), b_.getInt32(acc.index) });
    SizedType &elem_type = type.GetFields()[acc.index].type;

    if (shouldBeInBpfMemoryAlready(elem_type)) {
      // Extend lifetime of source buffer
      return ScopedExpr(src, std::move(scoped_arg));
    } else {
      // Lifetime is not extended, it is freed after the load
      return ScopedExpr(b_.CreateLoad(b_.GetType(elem_type), src));
    }
  }

  std::string cast_type = is_tparg ? tracepoint_struct_ : type.GetName();

  // This overwrites the stored type!
  type = CreateRecord(cast_type, bpftrace_.structs.Lookup(cast_type));
  if (is_ctx)
    type.MarkCtxAccess();
  type.is_tparg = is_tparg;
  type.is_internal = is_internal;
  type.is_funcarg = is_funcarg;
  type.is_btftype = is_btftype;
  // Restore the addrspace info
  // struct MyStruct { const int* a; };  $s = (struct MyStruct *)arg0;  $s->a
  type.SetAS(addrspace);

  auto &field = type.GetField(acc.field);

  if (inBpfMemory(type)) {
    return readDatastructElemFromStack(
        std::move(scoped_arg), b_.getInt64(field.offset), type, field.type);
  } else {
    // Structs may contain two kinds of fields that must be handled separately
    // (bitfields and _data_loc)
    if (field.type.IsIntTy() &&
        (field.bitfield.has_value() || field.is_data_loc)) {
      if (field.bitfield.has_value()) {
        Value *raw;
        auto field_type = b_.GetType(field.type);
        if (type.IsCtxAccess()) {
          // The offset is specified in absolute terms here; and the load
          // will implicitly convert to the intended field_type.
          Value *src = b_.CreateSafeGEP(b_.getPtrTy(),
                                        scoped_arg.value(),
                                        b_.getInt64(field.offset));
          raw = b_.CreateLoad(field_type, src, true);
        } else {
          // Since `src` is treated as a offset for a constructed probe read,
          // we are not constrained in the same way.
          Value *src = b_.CreateAdd(scoped_arg.value(),
                                    b_.getInt64(field.offset));
          AllocaInst *dst = b_.CreateAllocaBPF(field.type,
                                               type.GetName() + "." +
                                                   acc.field);
          // memset so verifier doesn't complain about reading uninitialized
          // stack
          b_.CreateMemsetBPF(dst, b_.getInt8(0), field.type.GetSize());
          b_.CreateProbeRead(ctx_,
                             dst,
                             b_.getInt32(field.bitfield->read_bytes),
                             src,
                             type.GetAS(),
                             acc.loc);
          raw = b_.CreateLoad(field_type, dst);
          b_.CreateLifetimeEnd(dst);
        }
        size_t rshiftbits;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        rshiftbits = field.bitfield->access_rshift;
#else
        rshiftbits = (field.type.GetSize() - field.bitfield->read_bytes) * 8;
        rshiftbits += field.bitfield->access_rshift;
#endif
        Value *shifted = b_.CreateLShr(raw, rshiftbits);
        Value *masked = b_.CreateAnd(shifted, field.bitfield->mask);
        return ScopedExpr(masked);
      } else {
        // `is_data_loc` should only be set if field access is on `args` which
        // has to be a ctx access
        assert(type.IsCtxAccess());
        // Parser needs to have rewritten field to be a u64
        assert(field.type.IsIntTy());
        assert(field.type.GetIntBitWidth() == 64);

        // Top 2 bytes are length (which we'll ignore). Bottom two bytes are
        // offset which we add to the start of the tracepoint struct. We need
        // to wrap the context here in a special way to treat it as the
        // expected pointer type for all versions.
        Value *value = b_.CreateLoad(b_.getInt32Ty(),
                                     b_.CreateSafeGEP(b_.getInt32Ty(),
                                                      ctx_,
                                                      b_.getInt64(field.offset /
                                                                  4)));
        value = b_.CreateIntCast(value, b_.getInt64Ty(), false);
        value = b_.CreateAnd(value, b_.getInt64(0xFFFF));
        value = b_.CreateSafeGEP(b_.getInt32Ty(), ctx_, value);
        return ScopedExpr(value);
      }
    } else {
      return probereadDatastructElem(std::move(scoped_arg),
                                     b_.getInt64(field.offset),
                                     type,
                                     field.type,
                                     acc.loc,
                                     type.GetName() + "." + acc.field);
    }
  }
}

ScopedExpr CodegenLLVM::visit(ArrayAccess &arr)
{
  SizedType &type = arr.expr->type;
  auto elem_type = type.IsArrayTy() ? *type.GetElementTy()
                                    : *type.GetPointeeTy();

  // We can allow the lifetime of the index to expire by the time the array
  // expression is complete, but we must preserve the lifetime of the
  // expression since the `readDatstructureElemFromStack` method might end up
  // returning a pointer to live memory produced by the expression.
  auto scoped_expr = visit(*arr.expr);
  auto scoped_index = visit(*arr.indexpr);

  if (inBpfMemory(type))
    return readDatastructElemFromStack(
        std::move(scoped_expr), scoped_index.value(), type, elem_type);
  else {
    Value *array = scoped_expr.value();
    if (array->getType()->isPointerTy()) {
      scoped_expr = ScopedExpr(b_.CreatePtrToInt(array, b_.getInt64Ty()),
                               std::move(scoped_expr));
    }

    Value *index = b_.CreateIntCast(scoped_index.value(),
                                    b_.getInt64Ty(),
                                    type.IsSigned());
    Value *offset = b_.CreatePtrOffset(elem_type, index, type.GetAS());

    return probereadDatastructElem(std::move(scoped_expr),
                                   offset,
                                   type,
                                   elem_type,
                                   arr.loc,
                                   "array_access");
  }
}

ScopedExpr CodegenLLVM::visit(Cast &cast)
{
  auto scoped_expr = visit(cast.expr);
  if (cast.type.IsIntTy()) {
    auto int_ty = b_.GetType(cast.type);
    if (cast.expr->type.IsArrayTy()) {
      // we need to read the array into the integer
      Value *array = scoped_expr.value();
      if (cast.expr->type.is_internal || cast.expr->type.IsCtxAccess() ||
          cast.expr->type.is_btftype) {
        // array is on the stack - just cast the pointer
        if (array->getType()->isIntegerTy())
          array = b_.CreateIntToPtr(array, b_.getPtrTy());
      } else {
        // array is in memory - need to proberead
        auto buf = b_.CreateAllocaBPF(cast.type);
        b_.CreateProbeRead(
            ctx_, buf, cast.type, array, cast.loc, cast.expr->type.GetAS());
        array = buf;
      }
      return ScopedExpr(b_.CreateLoad(int_ty, array, true));
    } else {
      return ScopedExpr(
          b_.CreateIntCast(scoped_expr.value(),
                           b_.getIntNTy(cast.type.GetIntBitWidth()),
                           cast.type.IsSigned(),
                           "cast"));
    }
  } else if (cast.type.IsArrayTy() && cast.expr->type.IsIntTy()) {
    // We need to store the cast integer on stack and reinterpret the pointer to
    // it to an array pointer.
    auto v = b_.CreateAllocaBPF(scoped_expr.value()->getType());
    b_.CreateStore(scoped_expr.value(), v);
    return ScopedExpr(v, [this, v] { b_.CreateLifetimeEnd(v); });
  } else {
    // FIXME(amscanne): The existing behavior is to simply pass the existing
    // expression back up when it is neither an integer nor an array.
    return scoped_expr;
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

  if (llvm_size != our_size) {
    LOG(BUG) << "Struct size mismatch: expected: " << our_size
             << ", real: " << llvm_size;
  }

  auto *layout = datalayout().getStructLayout(
      reinterpret_cast<llvm::StructType *>(llvm_type));

  for (ssize_t i = 0; i < our_type.GetFieldCount(); i++) {
    ssize_t llvm_offset = layout->getElementOffset(i);
    auto &field = our_type.GetField(i);
    ssize_t our_offset = field.offset;
    if (llvm_offset != our_offset) {
      LOG(DEBUG) << "Struct offset mismatch for: " << field.type << "(" << i
                 << ")" << ": (llvm) " << llvm_offset << " != " << our_offset;

      field.offset = llvm_offset;
    }
  }
}

// createTuple
//
// Constructs a tuple on the scratch buffer or stack from the provided values.
Value *CodegenLLVM::createTuple(
    const SizedType &tuple_type,
    const std::vector<std::pair<llvm::Value *, const location *>> &vals,
    const std::string &name,
    const location &loc)
{
  auto tuple_ty = b_.GetType(tuple_type);
  size_t tuple_size = datalayout().getTypeAllocSize(tuple_ty);
  auto buf = b_.CreateTupleAllocation(tuple_type, name, loc);
  b_.CreateMemsetBPF(buf, b_.getInt8(0), tuple_size);

  for (size_t i = 0; i < vals.size(); ++i) {
    auto [val, vloc] = vals[i];
    SizedType &type = tuple_type.GetField(i).type;

    Value *dst = b_.CreateGEP(tuple_ty,
                              buf,
                              { b_.getInt32(0), b_.getInt32(i) });

    if (inBpfMemory(type))
      b_.CreateMemcpyBPF(dst, val, type.GetSize());
    else if (type.IsArrayTy() || type.IsRecordTy())
      b_.CreateProbeRead(ctx_, dst, type, val, *vloc);
    else
      b_.CreateStore(val, dst);
  }
  return buf;
}

void CodegenLLVM::createTupleCopy(const SizedType &expr_type,
                                  const SizedType &var_type,
                                  Value *dst_val,
                                  Value *src_val)
{
  assert(expr_type.IsTupleTy() && var_type.IsTupleTy());
  auto *array_ty = ArrayType::get(b_.getInt8Ty(), expr_type.GetSize());
  auto *tuple_ty = b_.GetType(var_type);
  for (size_t i = 0; i < expr_type.GetFields().size(); ++i) {
    SizedType &t_type = expr_type.GetField(i).type;
    Value *offset_val = b_.CreateGEP(
        array_ty,
        src_val,
        { b_.getInt64(0), b_.getInt64(expr_type.GetField(i).offset) });
    Value *dst = b_.CreateGEP(tuple_ty,
                              dst_val,
                              { b_.getInt32(0), b_.getInt32(i) });
    if (t_type.IsTupleTy() && !t_type.IsSameSizeRecursive(var_type)) {
      createTupleCopy(t_type, var_type.GetField(i).type, dst, offset_val);
    } else if (t_type.IsIntTy() && t_type.GetSize() < 8) {
      // Integers are always stored as 64-bit in map keys
      b_.CreateStore(b_.CreateIntCast(b_.CreateLoad(b_.GetType(t_type),
                                                    offset_val),
                                      b_.getInt64Ty(),
                                      t_type.IsSigned()),
                     dst);
    } else {
      b_.CreateMemcpyBPF(dst, offset_val, t_type.GetSize());
    }
  }
}

ScopedExpr CodegenLLVM::visit(Tuple &tuple)
{
  llvm::Type *tuple_ty = b_.GetType(tuple.type);

  compareStructure(tuple.type, tuple_ty);

  std::vector<std::pair<llvm::Value *, const location *>> vals;
  std::vector<ScopedExpr> scoped_exprs;
  vals.reserve(tuple.elems.size());

  for (Expression *elem : tuple.elems) {
    auto scoped_expr = visit(elem);
    vals.push_back({ scoped_expr.value(), &elem->loc });
    scoped_exprs.emplace_back(std::move(scoped_expr));
  }

  auto buf = createTuple(tuple.type, vals, "tuple", tuple.loc);
  if (dyn_cast<AllocaInst>(buf))
    return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
  return ScopedExpr(buf);
}

ScopedExpr CodegenLLVM::visit(ExprStatement &expr)
{
  return visit(expr.expr);
}

ScopedExpr CodegenLLVM::visit(AssignMapStatement &assignment)
{
  Map &map = *assignment.map;
  auto scoped_expr = visit(*assignment.expr);
  Value *expr = scoped_expr.value();

  if (!expr) // Some functions do the assignments themselves.
    return ScopedExpr();

  auto scoped_key = getMapKey(map);
  auto &expr_type = assignment.expr->type;
  const auto self_alloca = needAssignMapStatementAllocation(assignment);
  Value *value = self_alloca
                     ? b_.CreateWriteMapValueAllocation(map.type,
                                                        map.ident + "_val",
                                                        assignment.loc)
                     : expr;
  if (shouldBeInBpfMemoryAlready(expr_type)) {
    if (!expr_type.IsSameSizeRecursive(map.type)) {
      b_.CreateMemsetBPF(value, b_.getInt8(0), map.type.GetSize());
      if (expr_type.IsTupleTy()) {
        createTupleCopy(expr_type, map.type, value, expr);
      } else if (expr_type.IsStringTy()) {
        b_.CreateMemcpyBPF(value, expr, expr_type.GetSize());
      } else {
        LOG(BUG) << "Type size mismatch. Map Type Size: " << map.type.GetSize()
                 << " Expression Type Size: " << expr_type.GetSize();
      }
    }
  } else if (map.type.IsRecordTy() || map.type.IsArrayTy()) {
    if (!expr_type.is_internal) {
      // expr currently contains a pointer to the struct or array
      // We now want to read the entire struct/array in so we can save it
      b_.CreateProbeRead(
          ctx_, value, map.type, expr, assignment.loc, expr_type.GetAS());
    }
  } else {
    if (map.type.IsIntTy()) {
      // Integers are always stored as 64-bit in map values
      expr = b_.CreateIntCast(expr, b_.getInt64Ty(), map.type.IsSigned());
    }
    b_.CreateStore(expr, value);
  }
  b_.CreateMapUpdateElem(
      ctx_, map.ident, scoped_key.value(), value, assignment.loc);
  if (self_alloca && dyn_cast<AllocaInst>(value))
    b_.CreateLifetimeEnd(value);
  return ScopedExpr();
}

void CodegenLLVM::maybeAllocVariable(const std::string &var_ident,
                                     const SizedType &var_type,
                                     const location &loc)
{
  if (maybeGetVariable(var_ident) != nullptr) {
    // Already been allocated
    return;
  }

  SizedType alloca_type = var_type;
  // Arrays and structs need not to be copied when assigned to local variables
  // since they are treated as read-only - it is sufficient to assign
  // the pointer and do the memcpy/proberead later when necessary
  if (var_type.IsArrayTy() || var_type.IsRecordTy()) {
    auto &pointee_type = var_type.IsArrayTy() ? *var_type.GetElementTy()
                                              : var_type;
    alloca_type = CreatePointer(pointee_type, var_type.GetAS());
  }

  auto val = b_.CreateVariableAllocationInit(alloca_type, var_ident, loc);
  variables_[scope_stack_.back()][var_ident] = VariableLLVM{
    val, b_.GetType(alloca_type)
  };
}

VariableLLVM *CodegenLLVM::maybeGetVariable(const std::string &var_ident)
{
  for (auto scope : scope_stack_) {
    if (auto search_val = variables_[scope].find(var_ident);
        search_val != variables_[scope].end()) {
      return &search_val->second;
    }
  }
  return nullptr;
}

VariableLLVM &CodegenLLVM::getVariable(const std::string &var_ident)
{
  auto *variable = maybeGetVariable(var_ident);
  if (!variable) {
    LOG(BUG) << "Can't find variable: " << var_ident
             << " in this or outer scope";
  }
  return *variable;
}

ScopedExpr CodegenLLVM::visit(AssignVarStatement &assignment)
{
  Variable &var = *assignment.var;

  auto scoped_expr = visit(assignment.expr);

  // In order to assign a value to a variable, the expression has to actually
  // produce a value. Unfortunately, there are many expressions which currently
  // do not produce values (and are either valid only the context of a map
  // assignment, or are otherwise useful only in statements). Therefore, we try
  // to provide as much information as possible but generally consider this a
  // bug until it can be resolved.
  if (!scoped_expr.value()) {
    LOG(BUG) << "Expression produced no value for variable: " << var.ident;
    __builtin_unreachable();
  }

  maybeAllocVariable(var.ident, var.type, var.loc);

  if (var.type.IsArrayTy() || var.type.IsRecordTy()) {
    // For arrays and structs, only the pointer is stored. However, this means
    // that we cannot release the underlying memory for any of these types. We
    // just disarm the scoped expression, and therefore never free any of these
    // values; this is a bug that matches existing behavior.
    scoped_expr.disarm();
    b_.CreateStore(b_.CreatePtrToInt(scoped_expr.value(), b_.getInt64Ty()),
                   getVariable(var.ident).value);
  } else if (needMemcpy(var.type)) {
    auto *val = getVariable(var.ident).value;
    auto &expr_type = assignment.expr->type;
    if (!expr_type.IsSameSizeRecursive(var.type)) {
      b_.CreateMemsetBPF(val, b_.getInt8(0), var.type.GetSize());
      if (var.type.IsTupleTy()) {
        createTupleCopy(expr_type, var.type, val, scoped_expr.value());
      } else {
        b_.CreateMemcpyBPF(val, scoped_expr.value(), expr_type.GetSize());
      }
    } else {
      b_.CreateMemcpyBPF(val, scoped_expr.value(), expr_type.GetSize());
    }
  } else {
    b_.CreateStore(scoped_expr.value(), getVariable(var.ident).value);
  }
  return ScopedExpr();
}

ScopedExpr CodegenLLVM::visit(VarDeclStatement &decl)
{
  Variable &var = *decl.var;
  if (var.type.IsNoneTy()) {
    // unused and has no type
    return ScopedExpr();
  }
  maybeAllocVariable(var.ident, var.type, var.loc);
  return ScopedExpr();
}

ScopedExpr CodegenLLVM::visit(If &if_node)
{
  llvm::Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *if_true = BasicBlock::Create(module_->getContext(),
                                           "if_body",
                                           parent);
  BasicBlock *if_end = BasicBlock::Create(module_->getContext(),
                                          "if_end",
                                          parent);
  BasicBlock *if_else = nullptr;

  auto scoped_cond = visit(if_node.cond);
  auto cond_expr = scoped_cond.value();
  Value *zero_value = Constant::getNullValue(cond_expr->getType());
  Value *cond = b_.CreateICmpNE(cond_expr, zero_value, "true_cond");

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
  if (!if_node.else_block->stmts.empty()) {
    // LLVM doesn't accept empty basic block, only create when needed
    if_else = BasicBlock::Create(module_->getContext(), "else_body", parent);
    b_.CreateCondBr(cond, if_true, if_else);
  } else {
    b_.CreateCondBr(cond, if_true, if_end);
  }

  b_.SetInsertPoint(if_true);
  auto scoped_del_if_block = visit(*if_node.if_block);

  b_.CreateBr(if_end);

  b_.SetInsertPoint(if_end);

  if (!if_node.else_block->stmts.empty()) {
    b_.SetInsertPoint(if_else);
    auto scoped_del_else_block = visit(*if_node.else_block);

    b_.CreateBr(if_end);
    b_.SetInsertPoint(if_end);
  }
  return ScopedExpr();
}

ScopedExpr CodegenLLVM::visit(Unroll &unroll)
{
  for (int i = 0; i < unroll.var; i++) {
    // Make sure to save/restore async ID state b/c we could be processing
    // the same async calls multiple times.
    auto reset_ids = async_ids_.create_reset_ids();
    auto scoped_del = visit(unroll.block);

    if (i != unroll.var - 1)
      reset_ids();
  }
  return ScopedExpr();
}

ScopedExpr CodegenLLVM::visit(Jump &jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      // return can be used outside of loops
      if (jump.return_value) {
        auto scoped_return = visit(jump.return_value);
        createRet(scoped_return.value());
      } else
        createRet();
      break;
    case JumpType::BREAK:
      b_.CreateBr(std::get<1>(loops_.back()));
      break;
    case JumpType::CONTINUE:
      b_.CreateBr(std::get<0>(loops_.back()));
      break;
    default:
      LOG(BUG) << "jump: invalid op \"" << opstr(jump) << "\"";
      __builtin_unreachable();
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

  llvm::Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *unreach = BasicBlock::Create(module_->getContext(),
                                           "unreach",
                                           parent);
  b_.SetInsertPoint(unreach);
  return ScopedExpr();
}

ScopedExpr CodegenLLVM::visit(While &while_block)
{
  if (!loop_metadata_)
    loop_metadata_ = createLoopMetadata();

  llvm::Function *parent = b_.GetInsertBlock()->getParent();
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
  auto scoped_cond = visit(while_block.cond);
  auto cond_expr = scoped_cond.value();
  Value *zero_value = Constant::getNullValue(cond_expr->getType());
  auto *cond = b_.CreateICmpNE(cond_expr, zero_value, "true_cond");
  Instruction *loop_hdr = b_.CreateCondBr(cond, while_body, while_end);
  loop_hdr->setMetadata(LLVMContext::MD_loop, loop_metadata_);

  b_.SetInsertPoint(while_body);
  auto scoped_block = visit(*while_block.block);
  b_.CreateBr(while_cond);

  b_.SetInsertPoint(while_end);
  loops_.pop_back();

  return ScopedExpr();
}

ScopedExpr CodegenLLVM::visit(For &f)
{
  auto &map = static_cast<Map &>(*f.expr);

  Value *ctx = b_.getInt64(0);
  llvm::Type *ctx_t = nullptr;

  const auto &ctx_fields = f.ctx_type.GetFields();
  if (!ctx_fields.empty()) {
    // Pack pointers to variables into context struct for use in the callback

    std::vector<llvm::Type *> ctx_field_types(ctx_fields.size(), b_.getPtrTy());
    ctx_t = StructType::create(ctx_field_types, "ctx_t");
    ctx = b_.CreateAllocaBPF(ctx_t, "ctx");

    for (size_t i = 0; i < ctx_fields.size(); i++) {
      const auto &field = ctx_fields[i];
      auto *field_expr = getVariable(field.name).value;
      auto *ctx_field_ptr = b_.CreateSafeGEP(
          ctx_t, ctx, { b_.getInt64(0), b_.getInt32(i) }, "ctx." + field.name);
      b_.CreateStore(field_expr, ctx_field_ptr);
    }
  }

  scope_stack_.push_back(&f);
  b_.CreateForEachMapElem(
      ctx_, map, createForEachMapCallback(f, ctx_t), ctx, f.loc);
  scope_stack_.pop_back();

  return ScopedExpr();
}

ScopedExpr CodegenLLVM::visit(Predicate &pred)
{
  llvm::Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *pred_false_block = BasicBlock::Create(module_->getContext(),
                                                    "pred_false",
                                                    parent);
  BasicBlock *pred_true_block = BasicBlock::Create(module_->getContext(),
                                                   "pred_true",
                                                   parent);

  auto scoped_expr = visit(pred.expr);

  // allow unop casts in predicates:
  auto cast_value = b_.CreateIntCast(scoped_expr.value(),
                                     b_.getInt64Ty(),
                                     false);
  auto cmp_value = b_.CreateICmpEQ(cast_value, b_.getInt64(0), "predcond");

  b_.CreateCondBr(cmp_value, pred_false_block, pred_true_block);
  b_.SetInsertPoint(pred_false_block);

  createRet();

  b_.SetInsertPoint(pred_true_block);

  return ScopedExpr(cmp_value);
}

ScopedExpr CodegenLLVM::visit(AttachPoint &)
{
  // Empty
  return ScopedExpr();
}

ScopedExpr CodegenLLVM::visit(Block &block)
{
  scope_stack_.push_back(&block);
  for (Statement *stmt : block.stmts)
    visit(*stmt);
  scope_stack_.pop_back();

  return ScopedExpr();
}

void CodegenLLVM::generateProbe(Probe &probe,
                                const std::string &full_func_id,
                                const std::string &name,
                                FunctionType *func_type,
                                std::optional<int> usdt_location_index,
                                bool dummy)
{
  // tracepoint wildcard expansion, part 3 of 3. Set tracepoint_struct_ for use
  // by args builtin.
  auto probe_type = probetype(current_attach_point_->provider);
  if (probe_type == ProbeType::tracepoint)
    tracepoint_struct_ = TracepointFormatParser::get_struct_name(full_func_id);

  int index = current_attach_point_->index() ?: probe.index();
  auto func_name = get_function_name_for_probe(name,
                                               index,
                                               usdt_location_index);
  auto *func = llvm::Function::Create(
      func_type, llvm::Function::ExternalLinkage, func_name, module_.get());
  func->setSection(get_section_name(func_name));
  debug_.createProbeDebugInfo(*func);

  BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", func);
  b_.SetInsertPoint(entry);

  // check: do the following 8 lines need to be in the wildcard loop?
  ctx_ = func->arg_begin();

  if (bpftrace_.need_recursion_check_) {
    b_.CreateCheckSetRecursion(current_attach_point_->loc,
                               getReturnValueForProbe(probe_type));
  }

  if (probe.pred)
    visit(*probe.pred);
  variables_.clear();
  auto scoped_block = visit(*probe.block);

  createRet();

  if (dummy) {
    func->eraseFromParent();
    return;
  }

  auto pt = probetype(current_attach_point_->provider);
  if ((pt == ProbeType::watchpoint || pt == ProbeType::asyncwatchpoint) &&
      current_attach_point_->func.size())
    generateWatchpointSetupProbe(
        func_type, name, current_attach_point_->address, index);
}

void CodegenLLVM::add_probe(AttachPoint &ap,
                            Probe &probe,
                            const std::string &name,
                            FunctionType *func_type)
{
  current_attach_point_ = &ap;
  probefull_ = ap.name();
  if (ap.expansion == ExpansionType::MULTI) {
    // For non-full expansion (currently only multi), we need to avoid
    // generating the code as the BPF program would fail to load.
    if (bpftrace_.probe_matcher_->get_matches_for_ap(ap).empty())
      return;
  }
  if (probetype(ap.provider) == ProbeType::usdt) {
    auto usdt = usdt_helper_->find(bpftrace_.pid(), ap.target, ap.ns, ap.func);
    if (!usdt.has_value()) {
      throw FatalUserException("Failed to find usdt probe: " + probefull_);
    } else
      ap.usdt = *usdt;

    // A "unique" USDT probe can be present in a binary in multiple
    // locations. One case where this happens is if a function
    // containing a USDT probe is inlined into a caller. So we must
    // generate a new program for each instance. We _must_ regenerate
    // because argument locations may differ between instance locations
    // (eg arg0. may not be found in the same offset from the same
    // register in each location)
    auto reset_ids = async_ids_.create_reset_ids();
    current_usdt_location_index_ = 0;
    for (int i = 0; i < ap.usdt.num_locations; ++i) {
      reset_ids();

      std::string full_func_id = name + "_loc" + std::to_string(i);
      generateProbe(probe, full_func_id, probefull_, func_type, i);
      bpftrace_.add_probe(Visitor::ctx_, ap, probe, i);
      current_usdt_location_index_++;
    }
  } else {
    generateProbe(probe, name, probefull_, func_type);
    bpftrace_.add_probe(Visitor::ctx_, ap, probe);
  }
  current_attach_point_ = nullptr;
}

ScopedExpr CodegenLLVM::visit(Subprog &subprog)
{
  scope_stack_.push_back(&subprog);
  std::vector<llvm::Type *> arg_types;
  // First argument is for passing ctx pointer for output, rest are proper
  // arguments to the function
  arg_types.push_back(b_.getPtrTy());
  std::transform(subprog.args.begin(),
                 subprog.args.end(),
                 std::back_inserter(arg_types),
                 [this](SubprogArg *arg) { return b_.GetType(arg->type); });
  FunctionType *func_type = FunctionType::get(b_.GetType(subprog.return_type),
                                              arg_types,
                                              0);

  auto *func = llvm::Function::Create(func_type,
                                      llvm::Function::InternalLinkage,
                                      subprog.name(),
                                      module_.get());
  BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", func);
  b_.SetInsertPoint(entry);

  variables_.clear();
  ctx_ = func->arg_begin();
  inside_subprog_ = true;

  int arg_index = 0;
  for (SubprogArg *arg : subprog.args) {
    auto alloca = b_.CreateAllocaBPF(b_.GetType(arg->type), arg->name());
    b_.CreateStore(func->getArg(arg_index + 1), alloca);
    variables_[scope_stack_.back()][arg->name()] = VariableLLVM{
      alloca, alloca->getAllocatedType()
    };
    ++arg_index;
  }

  for (Statement *stmt : subprog.stmts)
    visit(*stmt);
  if (subprog.return_type.IsVoidTy())
    createRet();

  FunctionPassManager fpm;
  FunctionAnalysisManager fam;
  llvm::PassBuilder pb;
  pb.registerFunctionAnalyses(fam);
  fpm.addPass(UnreachableBlockElimPass());
  fpm.run(*func, fam);
  scope_stack_.pop_back();

  return ScopedExpr();
}

void CodegenLLVM::createRet(Value *value)
{
  if (bpftrace_.need_recursion_check_) {
    b_.CreateUnSetRecursion(current_attach_point_->loc);
  }

  // If value is explicitly provided, use it
  if (value) {
    b_.CreateRet(value);
    return;
  } else if (inside_subprog_) {
    b_.CreateRetVoid();
    return;
  }

  int ret_val = getReturnValueForProbe(
      probetype(current_attach_point_->provider));
  b_.CreateRet(b_.getInt64(ret_val));
}

int CodegenLLVM::getReturnValueForProbe(ProbeType probe_type)
{
  // Fall back to default return value
  switch (probe_type) {
    case ProbeType::invalid:
      LOG(BUG) << "Returning from invalid probetype";
      return 0;
    case ProbeType::tracepoint:
      // Classic (ie. *not* raw) tracepoints have a kernel quirk stopping perf
      // subsystem from seeing a tracepoint event if BPF program returns 0.
      // This breaks perf in some situations and generally makes such BPF
      // programs bad citizens. Return 1 instead.
      return 1;
    case ProbeType::special:
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
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::iter:
    case ProbeType::rawtracepoint:
      return 0;
  }
  LOG(BUG) << "Unknown probetype";
  return 0;
}

ScopedExpr CodegenLLVM::visit(Probe &probe)
{
  FunctionType *func_type = FunctionType::get(b_.getInt64Ty(),
                                              { b_.getPtrTy() }, // ctx
                                              false);

  // We begin by saving state that gets changed by the codegen pass, so we
  // can restore it for the next pass (printf_id_, time_id_).
  auto reset_ids = async_ids_.create_reset_ids();
  bool generated = false;
  for (auto *attach_point : probe.attach_points) {
    reset_ids();
    current_attach_point_ = attach_point;
    if (probe.need_expansion ||
        attach_point->expansion == ExpansionType::FULL) {
      // Do expansion - generate a separate LLVM function for each match
      auto matches = bpftrace_.probe_matcher_->get_matches_for_ap(
          *attach_point);

      probe_count_ += matches.size();
      uint64_t max_bpf_progs = bpftrace_.config_.get(
          ConfigKeyInt::max_bpf_progs);
      if (probe_count_ > max_bpf_progs) {
        throw FatalUserException(
            "Your program is trying to generate more than " +
            std::to_string(probe_count_) +
            " BPF programs, which exceeds the current limit of " +
            std::to_string(max_bpf_progs) +
            ".\nYou can increase the limit through the BPFTRACE_MAX_BPF_PROGS "
            "environment variable.");
      }

      for (auto &match : matches) {
        reset_ids();
        if (attach_point->index() == 0)
          attach_point->set_index(getNextIndexForProbe());

        auto &match_ap = attach_point->create_expansion_copy(Visitor::ctx_,
                                                             match);
        add_probe(match_ap, probe, match, func_type);
        generated = true;
      }
    } else {
      if (probe.index() == 0)
        probe.set_index(getNextIndexForProbe());
      add_probe(*attach_point, probe, attach_point->name(), func_type);
      generated = true;
    }
  }
  if (!generated) {
    generateProbe(probe, "dummy", "dummy", func_type, std::nullopt, true);
  }

  current_attach_point_ = nullptr;
  return ScopedExpr();
}

ScopedExpr CodegenLLVM::visit(Program &program)
{
  for (Subprog *subprog : program.functions)
    visit(subprog);
  for (Probe *probe : program.probes)
    visit(probe);
  return ScopedExpr();
}

int CodegenLLVM::getNextIndexForProbe()
{
  return next_probe_index_++;
}

ScopedExpr CodegenLLVM::getMapKey(Map &map)
{
  return getMapKey(map, map.key_expr);
}

ScopedExpr CodegenLLVM::getMapKey(Map &map, Expression *key_expr)
{
  const auto alloca_created_here = needMapKeyAllocation(map, key_expr);

  if (key_expr) {
    auto scoped_key_expr = visit(key_expr);
    const auto &key_type = map.key_type;
    // Allocation needs to be done after recursing via vist(key_expr) so that
    // we have the expression SSA value.
    Value *key = alloca_created_here
                     ? b_.CreateMapKeyAllocation(key_type,
                                                 map.ident + "_key",
                                                 key_expr->loc)
                     : scoped_key_expr.value();
    if (inBpfMemory(key_expr->type)) {
      if (!key_expr->type.IsSameSizeRecursive(key_type)) {
        b_.CreateMemsetBPF(key, b_.getInt8(0), key_type.GetSize());
        if (key_expr->type.IsTupleTy()) {
          createTupleCopy(
              key_expr->type, key_type, key, scoped_key_expr.value());
        } else if (key_expr->type.IsStringTy()) {
          b_.CreateMemcpyBPF(key,
                             scoped_key_expr.value(),
                             key_expr->type.GetSize());
        } else {
          LOG(BUG) << "Type size mismatch. Key Type Size: "
                   << key_type.GetSize()
                   << " Expression Type Size: " << key_expr->type.GetSize();
        }
      } else {
        // Call-ee freed
      }
    } else if (map.key_type.IsIntTy()) {
      // Integers are always stored as 64-bit in map keys
      b_.CreateStore(b_.CreateIntCast(scoped_key_expr.value(),
                                      b_.getInt64Ty(),
                                      key_expr->type.IsSigned()),
                     key);
    } else {
      if (key_expr->type.IsArrayTy() || key_expr->type.IsRecordTy()) {
        // We need to read the entire array/struct and save it
        b_.CreateProbeRead(
            ctx_, key, key_expr->type, scoped_key_expr.value(), key_expr->loc);
      } else {
        b_.CreateStore(b_.CreateIntCast(scoped_key_expr.value(),
                                        b_.getInt64Ty(),
                                        key_expr->type.IsSigned()),
                       key);
      }
    }
    // Either way we hold on to the original key, to ensure that its lifetime
    // lasts as long as it may be accessed.
    if (alloca_created_here && dyn_cast<AllocaInst>(key)) {
      return ScopedExpr(key, [this, key, k = std::move(scoped_key_expr)] {
        b_.CreateLifetimeEnd(key);
      });
    }
    return ScopedExpr(key, std::move(scoped_key_expr));
  } else {
    // No map key (e.g., @ = 1;). Use 0 as a key.
    assert(alloca_created_here);
    Value *key = b_.CreateMapKeyAllocation(CreateUInt64(),
                                           map.ident + "_key",
                                           map.loc);
    b_.CreateStore(b_.getInt64(0), key);
    if (dyn_cast<AllocaInst>(key)) {
      return ScopedExpr(key, [this, key] { b_.CreateLifetimeEnd(key); });
    }
    return ScopedExpr(key);
  }
}

ScopedExpr CodegenLLVM::getMultiMapKey(Map &map,
                                       const std::vector<Value *> &extra_keys,
                                       const location &loc)
{
  size_t size = map.key_type.GetSize();
  for (auto *extra_key : extra_keys) {
    size += module_->getDataLayout().getTypeAllocSize(extra_key->getType());
  }

  // If key ever changes to not be allocated here, be sure to update getMapKey()
  // as well to take the new lifetime semantics into account.
  auto key = b_.CreateMapKeyAllocation(CreateArray(size, CreateInt8()),
                                       map.ident + "_key",
                                       loc);
  auto *key_type = ArrayType::get(b_.getInt8Ty(), size);

  int offset = 0;
  bool aligned = true;
  // Construct a map key in the stack
  auto scoped_expr = visit(*map.key_expr);
  Value *offset_val = b_.CreateGEP(key_type,
                                   key,
                                   { b_.getInt64(0), b_.getInt64(offset) });
  size_t map_key_size = map.key_type.GetSize();
  size_t expr_size = map.key_expr->type.GetSize();

  if (inBpfMemory(map.key_expr->type)) {
    if (!map.key_expr->type.IsSameSizeRecursive(map.key_type)) {
      b_.CreateMemsetBPF(offset_val, b_.getInt8(0), map_key_size);
      if (map.key_expr->type.IsTupleTy()) {
        createTupleCopy(
            map.key_expr->type, map.key_type, offset_val, scoped_expr.value());
      } else if (map.key_expr->type.IsStringTy()) {
        b_.CreateMemcpyBPF(offset_val, scoped_expr.value(), expr_size);
      } else {
        LOG(BUG) << "Type size mismatch. Key Type Size: "
                 << map.key_type.GetSize()
                 << " Expression Type Size: " << expr_size;
      }
    } else {
      b_.CreateMemcpyBPF(offset_val, scoped_expr.value(), expr_size);
    }
    if ((map_key_size % 8) != 0)
      aligned = false;
  } else {
    if (map.key_expr->type.IsArrayTy() || map.key_expr->type.IsRecordTy()) {
      // Read the array/struct into the key
      b_.CreateProbeRead(ctx_,
                         offset_val,
                         map.key_expr->type,
                         scoped_expr.value(),
                         map.key_expr->loc);
      if ((map_key_size % 8) != 0)
        aligned = false;
    } else {
      // promote map key to 64-bit:
      Value *key_elem = b_.CreateIntCast(scoped_expr.value(),
                                         b_.getInt64Ty(),
                                         map.key_expr->type.IsSigned());
      if (aligned)
        b_.CreateStore(key_elem, offset_val);
      else
        b_.createAlignedStore(key_elem, offset_val, 1);
    }
  }
  offset += map_key_size;

  for (auto *extra_key : extra_keys) {
    Value *offset_val = b_.CreateGEP(key_type,
                                     key,
                                     { b_.getInt64(0), b_.getInt64(offset) });
    if (aligned)
      b_.CreateStore(extra_key, offset_val);
    else
      b_.createAlignedStore(extra_key, offset_val, 1);
    offset += module_->getDataLayout().getTypeAllocSize(extra_key->getType());
  }

  return ScopedExpr(key, [this, key] { b_.CreateLifetimeEnd(key); });
}

ScopedExpr CodegenLLVM::getHistMapKey(Map &map,
                                      Value *log2,
                                      const location &loc)
{
  if (map.key_expr)
    return getMultiMapKey(map, { log2 }, loc);

  auto key = b_.CreateMapKeyAllocation(CreateUInt64(), map.ident + "_key", loc);
  b_.CreateStore(log2, key);
  return ScopedExpr(key, [this, key] {
    if (dyn_cast<AllocaInst>(key))
      b_.CreateLifetimeEnd(key);
  });
}

ScopedExpr CodegenLLVM::createLogicalAnd(Binop &binop)
{
  assert(binop.left->type.IsIntTy() || binop.left->type.IsPtrTy());
  assert(binop.right->type.IsIntTy() || binop.right->type.IsPtrTy());

  llvm::Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *lhs_true_block = BasicBlock::Create(module_->getContext(),
                                                  "&&_lhs_true",
                                                  parent);
  BasicBlock *true_block = BasicBlock::Create(module_->getContext(),
                                              "&&_true",
                                              parent);
  BasicBlock *false_block = BasicBlock::Create(module_->getContext(),
                                               "&&_false",
                                               parent);
  BasicBlock *merge_block = BasicBlock::Create(module_->getContext(),
                                               "&&_merge",
                                               parent);

  Value *result = b_.CreateAllocaBPF(b_.getInt64Ty(), "&&_result");

  ScopedExpr scoped_lhs = visit(*binop.left);
  Value *lhs = scoped_lhs.value();
  Value *lhs_zero_value = Constant::getNullValue(lhs->getType());
  b_.CreateCondBr(b_.CreateICmpNE(lhs, lhs_zero_value, "lhs_true_cond"),
                  lhs_true_block,
                  false_block);

  b_.SetInsertPoint(lhs_true_block);

  ScopedExpr scoped_rhs = visit(*binop.right);
  Value *rhs = scoped_rhs.value();
  Value *rhs_zero_value = Constant::getNullValue(rhs->getType());
  b_.CreateCondBr(b_.CreateICmpNE(rhs, rhs_zero_value, "rhs_true_cond"),
                  true_block,
                  false_block);

  b_.SetInsertPoint(true_block);
  b_.CreateStore(b_.getInt64(1), result);
  b_.CreateBr(merge_block);

  b_.SetInsertPoint(false_block);
  b_.CreateStore(b_.getInt64(0), result);
  b_.CreateBr(merge_block);

  b_.SetInsertPoint(merge_block);
  return ScopedExpr(b_.CreateLoad(b_.getInt64Ty(), result));
}

ScopedExpr CodegenLLVM::createLogicalOr(Binop &binop)
{
  assert(binop.left->type.IsIntTy() || binop.left->type.IsPtrTy());
  assert(binop.right->type.IsIntTy() || binop.right->type.IsPtrTy());

  llvm::Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *lhs_false_block = BasicBlock::Create(module_->getContext(),
                                                   "||_lhs_false",
                                                   parent);
  BasicBlock *false_block = BasicBlock::Create(module_->getContext(),
                                               "||_false",
                                               parent);
  BasicBlock *true_block = BasicBlock::Create(module_->getContext(),
                                              "||_true",
                                              parent);
  BasicBlock *merge_block = BasicBlock::Create(module_->getContext(),
                                               "||_merge",
                                               parent);

  Value *result = b_.CreateAllocaBPF(b_.getInt64Ty(), "||_result");

  ScopedExpr scoped_lhs = visit(*binop.left);
  Value *lhs = scoped_lhs.value();
  Value *lhs_zero_value = Constant::getNullValue(lhs->getType());
  b_.CreateCondBr(b_.CreateICmpNE(lhs, lhs_zero_value, "lhs_true_cond"),
                  true_block,
                  lhs_false_block);

  b_.SetInsertPoint(lhs_false_block);

  ScopedExpr scoped_rhs = visit(*binop.right);
  Value *rhs = scoped_rhs.value();
  Value *rhs_zero_value = Constant::getNullValue(rhs->getType());
  b_.CreateCondBr(b_.CreateICmpNE(rhs, rhs_zero_value, "rhs_true_cond"),
                  true_block,
                  false_block);

  b_.SetInsertPoint(false_block);
  b_.CreateStore(b_.getInt64(0), result);
  b_.CreateBr(merge_block);

  b_.SetInsertPoint(true_block);
  b_.CreateStore(b_.getInt64(1), result);
  b_.CreateBr(merge_block);

  b_.SetInsertPoint(merge_block);
  return ScopedExpr(b_.CreateLoad(b_.getInt64Ty(), result));
}

llvm::Function *CodegenLLVM::createLog2Function()
{
  auto ip = b_.saveIP();
  // Arguments: VAL (int64), K (0..5)
  // Maps each power of 2 into N = 2^K buckets, so we can build fine-grained
  // histograms with low runtime cost.
  //
  // Returns:
  //   0               for      VAL < 0
  //   1 + VAL         for 0 <= VAL < 2^K
  //   1 + concat(A,B) for      VAL >= 2^K,
  // where
  //   A is the position of the leftmost "1" in VAL, minus K
  //   B are the K bits following the leftmost "1" in VAL
  //
  // As an example, if VAL = 225 (0b11100001) and K = 2:
  // - the leftmost "1" in VAL is at position 8, so A is 8-2=6 (0b110)
  // - the following bits are "11" so B is 0b11
  // and the returned value is 1 + concat(0b110, 0b11) = 1 + 0b11011 = 28
  //
  // log2(int n, int k)
  // {
  //   if (n < 0) return 0;
  //   mask = (1ul << k) - 1;
  //   if (n <= mask) return n + 1;
  //   n0 = n;
  //   // find leftmost 1
  //   l = 0;
  //   for (int i = 5; i >= 0; i--) {
  //     threshold = 1ul << (1<<i)
  //     shift = (n >= threshold) << i;
  //     n >>= shift;
  //     l += shift;
  //   }
  //   l -= k;
  //   // mask K bits after leftmost 1
  //   x = (n0 >> l) & mask;
  //   return ((l + 1) << k) + x + 1;
  // }

  FunctionType *log2_func_type = FunctionType::get(
      b_.getInt64Ty(), { b_.getInt64Ty(), b_.getInt64Ty() }, false);
  auto *log2_func = llvm::Function::Create(
      log2_func_type, llvm::Function::InternalLinkage, "log2", module_.get());
  log2_func->addFnAttr(Attribute::AlwaysInline);
  log2_func->setSection("helpers");
  BasicBlock *entry = BasicBlock::Create(module_->getContext(),
                                         "entry",
                                         log2_func);
  b_.SetInsertPoint(entry);

  // storage for arguments
  Value *n_alloc = b_.CreateAllocaBPF(CreateUInt64());
  b_.CreateStore(log2_func->arg_begin(), n_alloc);
  Value *k_alloc = b_.CreateAllocaBPF(CreateUInt64());
  b_.CreateStore(log2_func->arg_begin() + 1, k_alloc);

  // test for less than zero
  BasicBlock *is_less_than_zero = BasicBlock::Create(module_->getContext(),
                                                     "hist.is_less_than_zero",
                                                     log2_func);
  BasicBlock *is_not_less_than_zero = BasicBlock::Create(
      module_->getContext(), "hist.is_not_less_than_zero", log2_func);

  Value *n = b_.CreateLoad(b_.getInt64Ty(), n_alloc);
  Value *zero = b_.getInt64(0);
  b_.CreateCondBr(b_.CreateICmpSLT(n, zero),
                  is_less_than_zero,
                  is_not_less_than_zero);

  b_.SetInsertPoint(is_less_than_zero);
  createRet(zero);

  b_.SetInsertPoint(is_not_less_than_zero);

  // first set of buckets (<= mask)
  Value *one = b_.getInt64(1);
  Value *k = b_.CreateLoad(b_.getInt64Ty(), k_alloc);
  Value *mask = b_.CreateSub(b_.CreateShl(one, k), one);

  BasicBlock *is_zero = BasicBlock::Create(module_->getContext(),
                                           "hist.is_zero",
                                           log2_func);
  BasicBlock *is_not_zero = BasicBlock::Create(module_->getContext(),
                                               "hist.is_not_zero",
                                               log2_func);
  b_.CreateCondBr(b_.CreateICmpULE(n, mask), is_zero, is_not_zero);

  b_.SetInsertPoint(is_zero);
  createRet(b_.CreateAdd(n, one));

  b_.SetInsertPoint(is_not_zero);

  // index of first bit set in n, 1 means bit 0, guaranteed to be >= k
  Value *l = zero;
  for (int i = 5; i >= 0; i--) {
    Value *threshold = b_.getInt64(1ul << (1ul << i));
    Value *is_ge = b_.CreateICmpSGE(n, threshold);
    // cast is important.
    is_ge = b_.CreateIntCast(is_ge, b_.getInt64Ty(), false);
    Value *shift = b_.CreateShl(is_ge, i);
    n = b_.CreateLShr(n, shift);
    l = b_.CreateAdd(l, shift);
  }

  // see algorithm for next steps:
  // subtract k, so we can move the next k bits of N to position 0
  l = b_.CreateSub(l, k);
  // now find the k bits in n after the first '1'
  Value *x = b_.CreateAnd(
      b_.CreateLShr(b_.CreateLoad(b_.getInt64Ty(), n_alloc), l), mask);

  Value *ret = b_.CreateAdd(l, one);
  ret = b_.CreateShl(ret, k); // make room for the extra slots
  ret = b_.CreateAdd(ret, x);
  ret = b_.CreateAdd(ret, one);
  createRet(ret);

  b_.restoreIP(ip);
  return module_->getFunction("log2");
}

llvm::Function *CodegenLLVM::createLinearFunction()
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
  FunctionType *linear_func_type = FunctionType::get(
      b_.getInt64Ty(),
      { b_.getInt64Ty(), b_.getInt64Ty(), b_.getInt64Ty(), b_.getInt64Ty() },
      false);
  auto *linear_func = llvm::Function::Create(linear_func_type,
                                             llvm::Function::InternalLinkage,
                                             "linear",
                                             module_.get());
  linear_func->addFnAttr(Attribute::AlwaysInline);
  linear_func->setSection("helpers");
  BasicBlock *entry = BasicBlock::Create(module_->getContext(),
                                         "entry",
                                         linear_func);
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
    Value *min = b_.CreateLoad(b_.getInt64Ty(), min_alloc);
    Value *val = b_.CreateLoad(b_.getInt64Ty(), value_alloc);
    cmp = b_.CreateICmpSLT(val, min);
  }
  BasicBlock *lt_min = BasicBlock::Create(module_->getContext(),
                                          "lhist.lt_min",
                                          linear_func);
  BasicBlock *ge_min = BasicBlock::Create(module_->getContext(),
                                          "lhist.ge_min",
                                          linear_func);
  b_.CreateCondBr(cmp, lt_min, ge_min);

  b_.SetInsertPoint(lt_min);
  createRet(b_.getInt64(0));

  b_.SetInsertPoint(ge_min);
  {
    Value *max = b_.CreateLoad(b_.getInt64Ty(), max_alloc);
    Value *val = b_.CreateLoad(b_.getInt64Ty(), value_alloc);
    cmp = b_.CreateICmpSGT(val, max);
  }
  BasicBlock *le_max = BasicBlock::Create(module_->getContext(),
                                          "lhist.le_max",
                                          linear_func);
  BasicBlock *gt_max = BasicBlock::Create(module_->getContext(),
                                          "lhist.gt_max",
                                          linear_func);
  b_.CreateCondBr(cmp, gt_max, le_max);

  b_.SetInsertPoint(gt_max);
  {
    Value *step = b_.CreateLoad(b_.getInt64Ty(), step_alloc);
    Value *min = b_.CreateLoad(b_.getInt64Ty(), min_alloc);
    Value *max = b_.CreateLoad(b_.getInt64Ty(), max_alloc);
    Value *div = b_.CreateUDiv(b_.CreateSub(max, min), step);
    b_.CreateStore(b_.CreateAdd(div, b_.getInt64(1)), result_alloc);
    createRet(b_.CreateLoad(b_.getInt64Ty(), result_alloc));
  }

  b_.SetInsertPoint(le_max);
  {
    Value *step = b_.CreateLoad(b_.getInt64Ty(), step_alloc);
    Value *min = b_.CreateLoad(b_.getInt64Ty(), min_alloc);
    Value *val = b_.CreateLoad(b_.getInt64Ty(), value_alloc);
    Value *div3 = b_.CreateUDiv(b_.CreateSub(val, min), step);
    b_.CreateStore(b_.CreateAdd(div3, b_.getInt64(1)), result_alloc);
    createRet(b_.CreateLoad(b_.getInt64Ty(), result_alloc));
  }

  b_.restoreIP(ip);
  return module_->getFunction("linear");
}

MDNode *CodegenLLVM::createLoopMetadata()
{
  // Create metadata to disable loop unrolling
  //
  // For legacy reasons, the first item of a loop metadata node must be
  // a self-reference. See https://llvm.org/docs/LangRef.html#llvm-loop
  LLVMContext &context = *context_;
  MDNode *unroll_disable = MDNode::get(
      context, MDString::get(context, "llvm.loop.unroll.disable"));
  MDNode *loopid = MDNode::getDistinct(context,
                                       { unroll_disable, unroll_disable });
  loopid->replaceOperandWith(0, loopid);

  return loopid;
}

void CodegenLLVM::createFormatStringCall(Call &call,
                                         int id,
                                         const CallArgs &call_args,
                                         const std::string &call_name,
                                         AsyncAction async_action)
{
  // perf event output has: uint64_t id, vargs
  // The id maps to bpftrace_.*_args_, and is a way to define the
  // types and offsets of each of the arguments, and share that between BPF and
  // user-space for printing.
  std::vector<llvm::Type *> elements = { b_.getInt64Ty() }; // ID

  const auto &args = std::get<1>(call_args.at(id));
  for (const Field &arg : args) {
    llvm::Type *ty = b_.GetType(arg.type);
    elements.push_back(ty);
  }
  StructType *fmt_struct = StructType::create(elements,
                                              call_name + "_t",
                                              false);
  int struct_size = datalayout().getTypeAllocSize(fmt_struct);

  // Check that offsets created during resource analysis match what LLVM
  // expects. This is just a guard rail against bad padding analysis logic.
  auto *struct_layout = datalayout().getStructLayout(fmt_struct);
  for (size_t i = 0; i < args.size(); i++) {
    size_t offset = static_cast<size_t>(args[i].offset);
    // +1 for the id field
    size_t expected_offset = struct_layout->getElementOffset(i + 1);
    if (offset != expected_offset)
      LOG(BUG) << "Calculated offset=" << offset
               << " does not match LLVM offset=" << expected_offset;
  }

  Value *fmt_args = b_.CreateGetFmtStringArgsAllocation(fmt_struct,
                                                        call_name + "_args",
                                                        call.loc);
  // The struct is not packed so we need to memset it
  b_.CreateMemsetBPF(fmt_args, b_.getInt8(0), struct_size);

  Value *id_offset = b_.CreateGEP(fmt_struct,
                                  fmt_args,
                                  { b_.getInt32(0), b_.getInt32(0) });
  b_.CreateStore(b_.getInt64(id + asyncactionint(async_action)), id_offset);

  for (size_t i = 1; i < call.vargs.size(); i++) {
    Expression &arg = *call.vargs.at(i);
    auto scoped_arg = visit(arg);
    Value *offset = b_.CreateGEP(fmt_struct,
                                 fmt_args,
                                 { b_.getInt32(0), b_.getInt32(i) });
    if (needMemcpy(arg.type))
      b_.CreateMemcpyBPF(offset, scoped_arg.value(), arg.type.GetSize());
    else if (arg.type.IsIntegerTy() && arg.type.GetSize() < 8)
      b_.CreateStore(b_.CreateIntCast(scoped_arg.value(),
                                      b_.getInt64Ty(),
                                      arg.type.IsSigned()),
                     offset);
    else
      b_.CreateStore(scoped_arg.value(), offset);
  }

  b_.CreateOutput(ctx_, fmt_args, struct_size, &call.loc);
  if (dyn_cast<AllocaInst>(fmt_args))
    b_.CreateLifetimeEnd(fmt_args);
}

void CodegenLLVM::generateWatchpointSetupProbe(
    FunctionType *func_type,
    const std::string &expanded_probe_name,
    int arg_num,
    int index)
{
  auto func_name = get_function_name_for_watchpoint_setup(expanded_probe_name,
                                                          index);
  auto *func = llvm::Function::Create(
      func_type, llvm::Function::ExternalLinkage, func_name, module_.get());
  func->setSection(get_section_name(func_name));
  debug_.createProbeDebugInfo(*func);

  BasicBlock *entry = BasicBlock::Create(module_->getContext(), "entry", func);
  b_.SetInsertPoint(entry);

  // Send SIGSTOP to curtask
  if (!current_attach_point_->async)
    b_.CreateSignal(ctx_, b_.getInt32(SIGSTOP), current_attach_point_->loc);

  // Pull out function argument
  Value *ctx = func->arg_begin();
  int offset = arch::arg_offset(arg_num);
  Value *addr = b_.CreateRegisterRead(ctx,
                                      offset,
                                      "arg" + std::to_string(arg_num));

  // Tell userspace to setup the real watchpoint
  auto elements = AsyncEvent::Watchpoint().asLLVMType(b_);
  StructType *watchpoint_struct = b_.GetStructType("watchpoint_t",
                                                   elements,
                                                   true);
  AllocaInst *buf = b_.CreateAllocaBPF(watchpoint_struct, "watchpoint");
  size_t struct_size = datalayout().getTypeAllocSize(watchpoint_struct);

  // Fill in perf event struct
  b_.CreateStore(
      b_.getInt64(asyncactionint(AsyncAction::watchpoint_attach)),
      b_.CreateGEP(watchpoint_struct, buf, { b_.getInt64(0), b_.getInt32(0) }));
  b_.CreateStore(
      b_.getInt64(async_ids_.watchpoint()),
      b_.CreateGEP(watchpoint_struct, buf, { b_.getInt64(0), b_.getInt32(1) }));
  b_.CreateStore(
      addr,
      b_.CreateGEP(watchpoint_struct, buf, { b_.getInt64(0), b_.getInt32(2) }));
  b_.CreateOutput(ctx, buf, struct_size);
  b_.CreateLifetimeEnd(buf);

  createRet();
}

void CodegenLLVM::createPrintMapCall(Call &call)
{
  auto elements = AsyncEvent::Print().asLLVMType(b_);
  StructType *print_struct = b_.GetStructType(call.func + "_t", elements, true);

  auto &arg = *call.vargs.at(0);
  auto &map = static_cast<Map &>(arg);

  AllocaInst *buf = b_.CreateAllocaBPF(print_struct,
                                       call.func + "_" + map.ident);

  // store asyncactionid:
  b_.CreateStore(
      b_.getInt64(asyncactionint(AsyncAction::print)),
      b_.CreateGEP(print_struct, buf, { b_.getInt64(0), b_.getInt32(0) }));

  int id = bpftrace_.resources.maps_info.at(map.ident).id;
  if (id == -1) {
    LOG(BUG) << "map id for map \"" << map.ident << "\" not found";
  }
  auto *ident_ptr = b_.CreateGEP(print_struct,
                                 buf,
                                 { b_.getInt64(0), b_.getInt32(1) });
  b_.CreateStore(b_.GetIntSameSize(id, elements.at(1)), ident_ptr);

  // top, div
  // first loops sets the arguments as passed by user. The second one zeros
  // the rest
  size_t arg_idx = 1;
  for (; arg_idx < call.vargs.size(); arg_idx++) {
    auto scoped_arg = visit(call.vargs.at(arg_idx));

    b_.CreateStore(
        b_.CreateIntCast(scoped_arg.value(), elements.at(arg_idx), false),
        b_.CreateGEP(print_struct,
                     buf,
                     { b_.getInt64(0), b_.getInt32(arg_idx + 1) }));
  }

  for (; arg_idx < 3; arg_idx++) {
    b_.CreateStore(b_.GetIntSameSize(0, elements.at(arg_idx)),
                   b_.CreateGEP(print_struct,
                                buf,
                                { b_.getInt64(0), b_.getInt32(arg_idx + 1) }));
  }

  b_.CreateOutput(ctx_, buf, getStructSize(print_struct), &call.loc);
  b_.CreateLifetimeEnd(buf);
}

void CodegenLLVM::createPrintNonMapCall(Call &call, int id)
{
  auto &arg = *call.vargs.at(0);
  auto scoped_arg = visit(arg);
  Value *value = scoped_arg.value();

  auto elements = AsyncEvent::PrintNonMap().asLLVMType(b_, arg.type.GetSize());
  std::ostringstream struct_name;
  struct_name << call.func << "_" << arg.type.GetTy() << "_"
              << arg.type.GetSize() << "_t";
  StructType *print_struct = b_.GetStructType(struct_name.str(),
                                              elements,
                                              true);
  Value *buf = b_.CreateGetFmtStringArgsAllocation(print_struct,
                                                   struct_name.str(),
                                                   call.loc);
  size_t struct_size = datalayout().getTypeAllocSize(print_struct);

  // Store asyncactionid:
  b_.CreateStore(
      b_.getInt64(asyncactionint(AsyncAction::print_non_map)),
      b_.CreateGEP(print_struct, buf, { b_.getInt64(0), b_.getInt32(0) }));

  // Store print id
  b_.CreateStore(
      b_.getInt64(id),
      b_.CreateGEP(print_struct, buf, { b_.getInt64(0), b_.getInt32(1) }));

  // Store content
  Value *content_offset = b_.CreateGEP(print_struct,
                                       buf,
                                       { b_.getInt32(0), b_.getInt32(2) });
  b_.CreateMemsetBPF(content_offset, b_.getInt8(0), arg.type.GetSize());
  if (needMemcpy(arg.type)) {
    if (inBpfMemory(arg.type))
      b_.CreateMemcpyBPF(content_offset, value, arg.type.GetSize());
    else
      b_.CreateProbeRead(ctx_, content_offset, arg.type, value, arg.loc);
  } else {
    b_.CreateStore(value, content_offset);
  }

  b_.CreateOutput(ctx_, buf, struct_size, &call.loc);
  if (dyn_cast<AllocaInst>(buf))
    b_.CreateLifetimeEnd(buf);
}

void CodegenLLVM::generate_ir()
{
  assert(state_ == State::INIT);

  auto analyser = CodegenResourceAnalyser(Visitor::ctx_, bpftrace_.config_);
  auto codegen_resources = analyser.analyse();

  generate_maps(bpftrace_.resources, codegen_resources);
  generate_global_vars(bpftrace_.resources, bpftrace_.config_);

  auto scoped_del = visit(Visitor::ctx_.root);
  debug_.finalize();
  state_ = State::IR;
}

void CodegenLLVM::createMapDefinition(const std::string &name,
                                      libbpf::bpf_map_type map_type,
                                      uint64_t max_entries,
                                      const SizedType &key_type,
                                      const SizedType &value_type)
{
  DIType *di_key_type = debug_.GetMapKeyType(key_type, value_type, map_type);
  map_types_.emplace(name, map_type);
  auto var_name = bpf_map_name(name);
  auto debuginfo = debug_.createMapEntry(
      var_name, map_type, max_entries, di_key_type, value_type);

  // It's sufficient that the global variable has the correct size (struct with
  // one pointer per field). The actual inner types are defined in debug info.
  SmallVector<llvm::Type *, 4> elems = { b_.getPtrTy(), b_.getPtrTy() };
  if (!value_type.IsNoneTy()) {
    elems.push_back(b_.getPtrTy());
    elems.push_back(b_.getPtrTy());
  }
  auto type = StructType::create(elems, "struct map_t", false);

  auto var = llvm::dyn_cast<GlobalVariable>(
      module_->getOrInsertGlobal(var_name, type));
  var->setInitializer(ConstantAggregateZero::get(type));
  var->setSection(".maps");
  var->setDSOLocal(true);
  var->addDebugInfo(debuginfo);
}

libbpf::bpf_map_type CodegenLLVM::get_map_type(const SizedType &val_type,
                                               const SizedType &key_type)
{
  if (val_type.IsCountTy() && key_type.IsNoneTy()) {
    return libbpf::BPF_MAP_TYPE_PERCPU_ARRAY;
  } else if (val_type.NeedsPercpuMap()) {
    return libbpf::BPF_MAP_TYPE_PERCPU_HASH;
  } else {
    return libbpf::BPF_MAP_TYPE_HASH;
  }
}

bool CodegenLLVM::is_array_map(const SizedType &val_type,
                               const SizedType &key_type)
{
  auto map_type = get_map_type(val_type, key_type);
  return map_type == libbpf::BPF_MAP_TYPE_ARRAY ||
         map_type == libbpf::BPF_MAP_TYPE_PERCPU_ARRAY;
}

// Check if we can special-case the map to have a single element. This is done
// for keyless maps BPF_MAP_TYPE_(PERCPU_)ARRAY type.
bool CodegenLLVM::map_has_single_elem(const SizedType &val_type,
                                      const SizedType &key_type)
{
  return is_array_map(val_type, key_type) && key_type.IsNoneTy();
}

// Emit maps in libbpf format so that Clang can create BTF info for them which
// can be read and used by libbpf.
//
// Each map should be defined by a global variable of a struct type with the
// following fields:
// - "type"        map type (e.g. BPF_MAP_TYPE_HASH)
// - "max_entries" maximum number of entries
// - "key"         key type
// - "value"       value type
//
// "type" and "max_entries" are integers but they must be represented as
// pointers to an array of ints whose dimension defines the specified value.
//
// "key" and "value" are pointers to the corresponding types. Note that these
// are not used for the BPF_MAP_TYPE_RINGBUF map type.
//
// The most important part is to generate BTF with the above information. This
// is done by emitting DWARF which LLVM will convert into BTF. The LLVM type of
// the global variable itself is not important, it can simply be a struct with 4
// pointers.
//
// Note that LLVM will generate BTF which misses some information. This is
// normally set by libbpf's linker but since we load BTF directly, we must do
// the fixing ourselves, until we start loading BPF programs via bpf_object.
// See BpfBytecode::fixupBTF for details.
void CodegenLLVM::generate_maps(const RequiredResources &required_resources,
                                const CodegenResources &codegen_resources)
{
  // User-defined maps
  for (const auto &[name, info] : required_resources.maps_info) {
    const auto &val_type = info.value_type;
    const auto &key_type = info.key_type;

    auto max_entries = bpftrace_.config_.get(ConfigKeyInt::max_map_keys);
    auto map_type = get_map_type(val_type, key_type);

    // hist() and lhist() transparently create additional elements in whatever
    // map they are assigned to. So even if the map looks like it has no keys,
    // multiple keys are necessary.
    if (key_type.IsNoneTy() && !val_type.IsHistTy() && !val_type.IsLhistTy()) {
      max_entries = 1;
    }

    createMapDefinition(name, map_type, max_entries, key_type, val_type);
  }

  // bpftrace internal maps

  uint16_t max_stack_limit = 0;
  for (const StackType &stack_type : codegen_resources.stackid_maps) {
    createMapDefinition(stack_type.name(),
                        libbpf::BPF_MAP_TYPE_LRU_HASH,
                        128 << 10,
                        CreateArray(12, CreateInt8()),
                        CreateArray(stack_type.limit, CreateUInt64()));
    max_stack_limit = std::max(stack_type.limit, max_stack_limit);
  }

  if (max_stack_limit > 0) {
    createMapDefinition(StackType::scratch_name(),
                        libbpf::BPF_MAP_TYPE_PERCPU_ARRAY,
                        1,
                        CreateInt32(),
                        CreateArray(max_stack_limit, CreateUInt64()));
  }

  if (codegen_resources.needs_join_map) {
    auto value_size = 8 + 8 + bpftrace_.join_argnum_ * bpftrace_.join_argsize_;
    SizedType value_type = CreateArray(value_size, CreateInt8());
    createMapDefinition(to_string(MapType::Join),
                        libbpf::BPF_MAP_TYPE_PERCPU_ARRAY,
                        1,
                        CreateInt32(),
                        value_type);
  }

  if (codegen_resources.needs_elapsed_map) {
    createMapDefinition(to_string(MapType::Elapsed),
                        libbpf::BPF_MAP_TYPE_HASH,
                        1,
                        CreateNone(),
                        CreateUInt64());
  }

  if (bpftrace_.need_recursion_check_) {
    createMapDefinition(to_string(MapType::RecursionPrevention),
                        libbpf::BPF_MAP_TYPE_PERCPU_ARRAY,
                        1,
                        CreateInt32(),
                        CreateUInt64());
  }

  if (!bpftrace_.feature_->has_map_ringbuf() ||
      required_resources.needs_perf_event_map) {
    createMapDefinition(to_string(MapType::PerfEvent),
                        libbpf::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                        get_online_cpus().size(),
                        CreateInt32(),
                        CreateInt32());
  }

  if (bpftrace_.feature_->has_map_ringbuf()) {
    auto entries = bpftrace_.config_.get(ConfigKeyInt::perf_rb_pages) * 4096;
    createMapDefinition(to_string(MapType::Ringbuf),
                        libbpf::BPF_MAP_TYPE_RINGBUF,
                        entries,
                        CreateNone(),
                        CreateNone());
  }

  int loss_cnt_key_size = sizeof(bpftrace_.event_loss_cnt_key_) * 8;
  int loss_cnt_val_size = sizeof(bpftrace_.event_loss_cnt_val_) * 8;
  createMapDefinition(to_string(MapType::EventLossCounter),
                      libbpf::BPF_MAP_TYPE_ARRAY,
                      1,
                      CreateInt(loss_cnt_key_size),
                      CreateInt(loss_cnt_val_size));
}

void CodegenLLVM::generate_global_vars(
    const RequiredResources &resources,
    const ::bpftrace::Config &bpftrace_config)
{
  for (const auto global_var : resources.needed_global_vars) {
    auto config = bpftrace::globalvars::get_config(global_var);
    auto type = bpftrace::globalvars::get_type(global_var,
                                               resources,
                                               bpftrace_config);
    auto var = llvm::dyn_cast<GlobalVariable>(
        module_->getOrInsertGlobal(config.name, b_.GetType(type)));
    var->setInitializer(ConstantAggregateZero::get(b_.GetType(type)));
    var->setConstant(config.read_only);
    var->setSection(config.section);
    var->setExternallyInitialized(true);
    var->setDSOLocal(true);
    var->addDebugInfo(debug_.createGlobalVariable(config.name, type));
  }
}

void CodegenLLVM::emit_elf(const std::string &filename)
{
  assert(state_ == State::OPT);

  std::error_code err;
  raw_fd_ostream out(filename, err);
  if (err)
    throw std::system_error(err.value(),
                            std::generic_category(),
                            "Failed to open: " + filename);

  emit(out);
  out.flush();

  return;
}

void CodegenLLVM::optimize()
{
  assert(state_ == State::IR);

  PipelineTuningOptions pto;
  pto.LoopUnrolling = false;
  pto.LoopInterleaving = false;
  pto.LoopVectorization = false;
  pto.SLPVectorization = false;

  llvm::PassBuilder pb(target_machine_.get(), pto);

  // ModuleAnalysisManager must be destroyed first.
  llvm::LoopAnalysisManager lam;
  llvm::FunctionAnalysisManager fam;
  llvm::CGSCCAnalysisManager cgam;
  llvm::ModuleAnalysisManager mam;

  // Register all the basic analyses with the managers.
  pb.registerModuleAnalyses(mam);
  pb.registerCGSCCAnalyses(cgam);
  pb.registerFunctionAnalyses(fam);
  pb.registerLoopAnalyses(lam);
  pb.crossRegisterProxies(lam, fam, cgam, mam);

  ModulePassManager mpm = pb.buildPerModuleDefaultPipeline(
      llvm::OptimizationLevel::O3);
  mpm.run(*module_, mam);

  state_ = State::OPT;
}

bool CodegenLLVM::verify()
{
  bool ret = llvm::verifyModule(*module_, &errs());
  if (ret) {
    /* verifyModule doesn't end output with end of line of line, print it now */
    std::cerr << std::endl;
  }
  return !ret;
}

// Technically we could use LLVM APIs to do a proper disassemble on
// the in-memory ELF file. But that is quite complex, as LLVM only
// provides fairly low level APIs to do this.
//
// Since disassembly is a debugging tool, just shell out to llvm-objdump
// to keep things simple.
static void disassemble(const SmallVector<char, 0> &elf)
{
  std::cout << "\nDisassembled bytecode\n";
  std::cout << "---------------------------\n";

  FILE *objdump = ::popen("llvm-objdump -d -", "w");
  if (!objdump) {
    LOG(ERROR) << "Failed to spawn llvm-objdump: " << strerror(errno);
    return;
  }

  if (::fwrite(elf.data(), sizeof(char), elf.size(), objdump) != elf.size()) {
    LOG(ERROR) << "Failed to write ELF to llvm-objdump";
    return;
  }

  if (auto rc = ::pclose(objdump))
    LOG(WARNING) << "llvm-objdump did not exit cleanly: status " << rc;
}

void CodegenLLVM::emit(raw_pwrite_stream &stream)
{
  legacy::PassManager PM;

#if LLVM_VERSION_MAJOR >= 18
  auto type = CodeGenFileType::ObjectFile;
#else
  auto type = llvm::CGFT_ObjectFile;
#endif

  if (target_machine_->addPassesToEmitFile(PM, stream, nullptr, type))
    LOG(BUG) << "Cannot emit a file of this type";
  PM.run(*module_.get());
}

BpfBytecode CodegenLLVM::emit(bool dis)
{
  assert(state_ == State::OPT);
  SmallVector<char, 0> output;
  raw_svector_ostream os(output);

  emit(os);
  assert(!output.empty());

  if (dis)
    disassemble(output);

  state_ = State::DONE;
  return BpfBytecode{ output };
}

BpfBytecode CodegenLLVM::compile()
{
  generate_ir();
  optimize();
  return emit(false);
}

void CodegenLLVM::DumpIR()
{
  DumpIR(std::cout);
}

void CodegenLLVM::DumpIR(std::ostream &out)
{
  assert(module_.get() != nullptr);
  raw_os_ostream os(out);
  module_->print(os, nullptr, false, true);
}

void CodegenLLVM::DumpIR(const std::string filename)
{
  assert(module_.get() != nullptr);
  std::ofstream file;
  file.open(filename);
  raw_os_ostream os(file);
  module_->print(os, nullptr, false, true);
}

// Read a single element from a compound data structure (i.e. an array or
// a struct) that has been pulled onto BPF stack.
// Params:
//   src_data   pointer to the entire data structure
//   index      index of the field to read
//   data_type  type of the structure
//   elem_type  type of the element
//   scoped_del scope deleter for the data structure
ScopedExpr CodegenLLVM::readDatastructElemFromStack(ScopedExpr &&scoped_src,
                                                    Value *index,
                                                    llvm::Type *data_type,
                                                    const SizedType &elem_type)
{
  // src_data should contain a pointer to the data structure, but it may be
  // internally represented as an integer and then we need to cast it
  Value *src_data = scoped_src.value();
  if (src_data->getType()->isIntegerTy())
    src_data = b_.CreateIntToPtr(src_data, b_.getPtrTy());

  Value *src = b_.CreateGEP(data_type, src_data, { b_.getInt32(0), index });

  if (elem_type.IsIntegerTy() || elem_type.IsPtrTy()) {
    // Load the correct type from src
    return ScopedExpr(
        b_.CreateDatastructElemLoad(elem_type, src, true, elem_type.GetAS()));
  } else {
    // The inner type is an aggregate - instead of copying it, just pass
    // the pointer and extend lifetime of the source data.
    return ScopedExpr(src, std::move(scoped_src));
  }
}

ScopedExpr CodegenLLVM::readDatastructElemFromStack(ScopedExpr &&scoped_src,
                                                    Value *index,
                                                    const SizedType &data_type,
                                                    const SizedType &elem_type)
{
  return readDatastructElemFromStack(
      std::move(scoped_src), index, b_.GetType(data_type), elem_type);
}

// Read a single element from a compound data structure (i.e. an array or
// a struct) that has not been yet pulled into BPF memory.
// Params:
//   scoped_src scoped expression pointing to the data structure
//   offset     offset of the requested element from the structure beginning
//   data_type  type of the data structure
//   elem_type  type of the requested element
//   loc        location of the element access (for proberead)
//   temp_name  name of a temporary variable, if the function creates any
ScopedExpr CodegenLLVM::probereadDatastructElem(ScopedExpr &&scoped_src,
                                                Value *offset,
                                                const SizedType &data_type,
                                                const SizedType &elem_type,
                                                location loc,
                                                const std::string &temp_name)
{
  // We treat this access as a raw byte offset, but may then subsequently need
  // to cast the pointer to the expected value.
  Value *src = b_.CreateSafeGEP(b_.getInt8Ty(), scoped_src.value(), offset);

  if (elem_type.IsRecordTy() || elem_type.IsArrayTy()) {
    // For nested arrays and structs, just pass the pointer along and
    // dereference it later when necessary. We just need to extend lifetime
    // of the source pointer.
    return ScopedExpr(src, std::move(scoped_src));
  } else if (elem_type.IsStringTy() || elem_type.IsBufferTy()) {
    AllocaInst *dst = b_.CreateAllocaBPF(elem_type, temp_name);
    if (elem_type.IsStringTy() && data_type.is_btftype) {
      if (src->getType()->isIntegerTy())
        src = b_.CreateIntToPtr(src, dst->getType());
      b_.CreateMemcpyBPF(dst, src, elem_type.GetSize());
    } else {
      b_.CreateProbeRead(ctx_, dst, elem_type, src, loc, data_type.GetAS());
    }
    // dst is left as is, so we need to return and bound its lifetime to the
    // underlying expression. Since we've finished copying, we can end the
    // lifetime of the `scoped_src` argument.
    return ScopedExpr(dst, [this, dst]() { b_.CreateLifetimeEnd(dst); });
  } else {
    // Read data onto stack
    if (data_type.IsCtxAccess() || data_type.is_btftype) {
      // Types have already been suitably casted; just do the access.
      Value *expr = b_.CreateDatastructElemLoad(
          elem_type, src, true, data_type.GetAS());
      // check context access for iter probes (required by kernel)
      if (data_type.IsCtxAccess() &&
          probetype(current_attach_point_->provider) == ProbeType::iter) {
        llvm::Function *parent = b_.GetInsertBlock()->getParent();
        BasicBlock *pred_false_block = BasicBlock::Create(module_->getContext(),
                                                          "pred_false",
                                                          parent);
        BasicBlock *pred_true_block = BasicBlock::Create(module_->getContext(),
                                                         "pred_true",
                                                         parent);
        Value *cast = b_.CreateIntCast(expr, b_.getInt64Ty(), false);
        Value *cmp = b_.CreateICmpEQ(cast, b_.getInt64(0), "predcond");

        b_.CreateCondBr(cmp, pred_false_block, pred_true_block);
        b_.SetInsertPoint(pred_false_block);
        createRet();

        b_.SetInsertPoint(pred_true_block);
      }
      // Everything should be loaded by this point, so we can drop the lifetime
      // of `scoped_src`.
      return ScopedExpr(expr);

    } else {
      AllocaInst *dst = b_.CreateAllocaBPF(elem_type, temp_name);
      b_.CreateProbeRead(ctx_, dst, elem_type, src, loc, data_type.GetAS());
      Value *expr = b_.CreateLoad(b_.GetType(elem_type), dst);
      // We have completely loaded from dst, and therefore can insert an end to
      // its lifetime directly.
      b_.CreateLifetimeEnd(dst);
      return ScopedExpr(expr);
    }
  }
}

ScopedExpr CodegenLLVM::createIncDec(Unop &unop)
{
  bool is_increment = unop.op == Operator::INCREMENT;
  SizedType &type = unop.expr->type;
  uint64_t step = type.IsPtrTy() ? type.GetPointeeTy()->GetSize() : 1;

  if (unop.expr->is_map) {
    auto &map = static_cast<Map &>(*unop.expr);
    auto scoped_key = getMapKey(map);
    Value *oldval = b_.CreateMapLookupElem(
        ctx_, map, scoped_key.value(), unop.loc);
    AllocaInst *newval = b_.CreateAllocaBPF(map.type, map.ident + "_newval");
    if (is_increment)
      b_.CreateStore(b_.CreateAdd(oldval, b_.GetIntSameSize(step, oldval)),
                     newval);
    else
      b_.CreateStore(b_.CreateSub(oldval, b_.GetIntSameSize(step, oldval)),
                     newval);
    b_.CreateMapUpdateElem(
        ctx_, map.ident, scoped_key.value(), newval, unop.loc);

    Value *value;
    if (unop.is_post_op)
      value = oldval;
    else
      value = b_.CreateLoad(b_.GetType(map.type), newval);
    b_.CreateLifetimeEnd(newval);
    return ScopedExpr(value);
  } else if (unop.expr->is_variable) {
    Variable &var = static_cast<Variable &>(*unop.expr);
    const auto &variable = getVariable(var.ident);
    Value *oldval = b_.CreateLoad(variable.type, variable.value);
    Value *newval;
    if (is_increment)
      newval = b_.CreateAdd(oldval, b_.GetIntSameSize(step, oldval));
    else
      newval = b_.CreateSub(oldval, b_.GetIntSameSize(step, oldval));
    b_.CreateStore(newval, variable.value);

    if (unop.is_post_op)
      return ScopedExpr(oldval);
    else
      return ScopedExpr(newval);
  } else {
    LOG(BUG) << "invalid expression passed to " << opstr(unop);
    __builtin_unreachable();
  }
}

llvm::Function *CodegenLLVM::createMurmurHash2Func()
{
  // The goal is to produce the following code:
  //
  // uint64_t murmur_hash_2(void *stack, uint8_t nr_stack_frames, uint64_t seed)
  // {
  //   const uint64_t m = 0xc6a4a7935bd1e995LLU;
  //   const int r = 47;
  //   uint64_t id = seed ^ (nr_stack_frames * m);
  //   int i = 0;

  //   while(i < nr_stack_frames) {
  //     uint64_t k = stack[i];
  //     k *= m;
  //     k ^= k >> r;
  //     k *= m;
  //     id ^= k;
  //     id *= m;
  //     ++i;
  //   }
  //   return id;
  // }
  //
  // https://github.com/aappleby/smhasher/blob/92cf3702fcfaadc84eb7bef59825a23e0cd84f56/src/MurmurHash2.cpp
  auto saved_ip = b_.saveIP();

  std::array<llvm::Type *, 3> args = { b_.getPtrTy(),
                                       b_.getInt8Ty(),
                                       b_.getInt64Ty() };
  FunctionType *callback_type = FunctionType::get(b_.getInt64Ty(), args, false);

  auto *callback = llvm::Function::Create(
      callback_type,
      llvm::Function::LinkageTypes::InternalLinkage,
      "murmur_hash_2",
      module_.get());
  callback->addFnAttr(Attribute::AlwaysInline);
  callback->setSection("helpers");

  auto *bb = BasicBlock::Create(module_->getContext(), "entry", callback);
  b_.SetInsertPoint(bb);

  AllocaInst *nr_stack_frames = b_.CreateAllocaBPF(b_.getInt8Ty(),
                                                   "nr_stack_frames_addr");
  AllocaInst *seed_addr = b_.CreateAllocaBPF(b_.getInt64Ty(), "seed_addr");

  AllocaInst *id = b_.CreateAllocaBPF(b_.getInt64Ty(), "id");
  AllocaInst *i = b_.CreateAllocaBPF(b_.getInt8Ty(), "i");
  AllocaInst *k = b_.CreateAllocaBPF(b_.getInt64Ty(), "k");

  Value *m = b_.getInt64(0xc6a4a7935bd1e995LLU);
  Value *r = b_.getInt64(47);

  Value *stack_addr = callback->getArg(0);

  b_.CreateStore(callback->getArg(1), nr_stack_frames);
  b_.CreateStore(callback->getArg(2), seed_addr);

  // uint64_t id = seed ^ (len * m);
  b_.CreateStore(
      b_.CreateXor(b_.CreateLoad(b_.getInt64Ty(), seed_addr),
                   b_.CreateMul(b_.CreateIntCast(b_.CreateLoad(b_.getInt8Ty(),
                                                               nr_stack_frames),
                                                 b_.getInt64Ty(),
                                                 false),
                                m)),
      id);

  // int i = 0;
  b_.CreateStore(b_.getInt8(0), i);

  llvm::Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *while_cond = BasicBlock::Create(module_->getContext(),
                                              "while_cond",
                                              parent);
  BasicBlock *while_body = BasicBlock::Create(module_->getContext(),
                                              "while_body",
                                              parent);
  BasicBlock *while_end = BasicBlock::Create(module_->getContext(),
                                             "while_end",
                                             parent);
  b_.CreateBr(while_cond);
  b_.SetInsertPoint(while_cond);
  auto *cond = b_.CreateICmp(CmpInst::ICMP_ULT,
                             b_.CreateLoad(b_.getInt8Ty(), i),
                             b_.CreateLoad(b_.getInt8Ty(), nr_stack_frames),
                             "length.cmp");
  b_.CreateCondBr(cond, while_body, while_end);

  b_.SetInsertPoint(while_body);

  // uint64_t k = stack[i];
  Value *stack_ptr = b_.CreateGEP(b_.getInt64Ty(),
                                  stack_addr,
                                  b_.CreateLoad(b_.getInt8Ty(), i));
  b_.CreateStore(b_.CreateLoad(b_.getInt64Ty(), stack_ptr), k);

  // k *= m;
  b_.CreateStore(b_.CreateMul(b_.CreateLoad(b_.getInt64Ty(), k), m), k);

  // // k ^= k >> r
  b_.CreateStore(b_.CreateXor(b_.CreateLoad(b_.getInt64Ty(), k),
                              b_.CreateLShr(b_.CreateLoad(b_.getInt64Ty(), k),
                                            r)),
                 k);

  // // k *= m
  b_.CreateStore(b_.CreateMul(b_.CreateLoad(b_.getInt64Ty(), k), m), k);

  // id ^= k
  b_.CreateStore(b_.CreateXor(b_.CreateLoad(b_.getInt64Ty(), id),
                              b_.CreateLoad(b_.getInt64Ty(), k)),
                 id);

  // id *= m
  b_.CreateStore(b_.CreateMul(b_.CreateLoad(b_.getInt64Ty(), id), m), id);

  // ++i
  b_.CreateStore(b_.CreateAdd(b_.CreateLoad(b_.getInt8Ty(), i), b_.getInt8(1)),
                 i);

  b_.CreateBr(while_cond);
  b_.SetInsertPoint(while_end);

  b_.CreateLifetimeEnd(nr_stack_frames);
  b_.CreateLifetimeEnd(seed_addr);
  b_.CreateLifetimeEnd(i);
  b_.CreateLifetimeEnd(k);

  // We reserve 0 for errors so if we happen to hash to 0 just set to 1.
  // This should reduce hash collisions as we now have to come across two stacks
  // that naturally hash to 1 AND 0.
  BasicBlock *if_zero = BasicBlock::Create(module_->getContext(),
                                           "if_zero",
                                           parent);
  BasicBlock *if_end = BasicBlock::Create(module_->getContext(),
                                          "if_end",
                                          parent);

  Value *zero_cond = b_.CreateICmpEQ(b_.CreateLoad(b_.getInt64Ty(), id),
                                     b_.getInt64(0),
                                     "zero_cond");

  b_.CreateCondBr(zero_cond, if_zero, if_end);
  b_.SetInsertPoint(if_zero);
  b_.CreateStore(b_.getInt64(1), id);

  b_.CreateBr(if_end);
  b_.SetInsertPoint(if_end);

  Value *ret = b_.CreateLoad(b_.getInt64Ty(), id);

  b_.CreateLifetimeEnd(id);

  b_.CreateRet(ret);

  b_.restoreIP(saved_ip);

  return callback;
}

llvm::Function *CodegenLLVM::createMapLenCallback()
{
  // The goal is to produce the following code:
  //
  // static int cb(struct map *map, void *key, void *value, void *ctx)
  // {
  //   return 0;
  // }
  auto saved_ip = b_.saveIP();

  std::array<llvm::Type *, 4> args = {
    b_.getPtrTy(), b_.getPtrTy(), b_.getPtrTy(), b_.getPtrTy()
  };

  FunctionType *callback_type = FunctionType::get(b_.getInt64Ty(), args, false);

  auto *callback = llvm::Function::Create(
      callback_type,
      llvm::Function::LinkageTypes::InternalLinkage,
      "map_len_cb",
      module_.get());

  callback->setDSOLocal(true);
  callback->setVisibility(llvm::GlobalValue::DefaultVisibility);
  callback->setSection(".text");

  Struct debug_args;
  debug_args.AddField("map", CreatePointer(CreateInt8()));
  debug_args.AddField("key", CreatePointer(CreateInt8()));
  debug_args.AddField("value", CreatePointer(CreateInt8()));
  debug_args.AddField("ctx", CreatePointer(CreateInt8()));
  debug_.createFunctionDebugInfo(*callback, CreateInt64(), debug_args);

  auto *bb = BasicBlock::Create(module_->getContext(), "", callback);
  b_.SetInsertPoint(bb);

  b_.CreateRet(b_.getInt64(0));

  b_.restoreIP(saved_ip);

  return callback;
}

llvm::Function *CodegenLLVM::createForEachMapCallback(For &f, llvm::Type *ctx_t)
{
  // Create a callback function suitable for passing to bpf_for_each_map_elem,
  // of the form:
  //
  //   static int cb(struct map *map, void *key, void *value, void *ctx)
  //   {
  //     $decl = (key, value);
  //     [stmts...]
  //   }

  auto saved_ip = b_.saveIP();

  std::array<llvm::Type *, 4> args = {
    b_.getPtrTy(), b_.getPtrTy(), b_.getPtrTy(), b_.getPtrTy()
  };

  FunctionType *callback_type = FunctionType::get(b_.getInt64Ty(), args, false);
  auto *callback = llvm::Function::Create(
      callback_type,
      llvm::Function::LinkageTypes::InternalLinkage,
      "map_for_each_cb",
      module_.get());
  callback->setDSOLocal(true);
  callback->setVisibility(llvm::GlobalValue::DefaultVisibility);
  callback->setSection(".text");

  Struct debug_args;
  debug_args.AddField("map", CreatePointer(CreateInt8()));
  debug_args.AddField("key", CreatePointer(CreateInt8()));
  debug_args.AddField("value", CreatePointer(CreateInt8()));
  debug_args.AddField("ctx", CreatePointer(CreateInt8()));
  debug_.createFunctionDebugInfo(*callback, CreateInt64(), debug_args);

  auto *bb = BasicBlock::Create(module_->getContext(), "", callback);
  b_.SetInsertPoint(bb);

  auto &key_type = f.decl->type.GetField(0).type;
  Value *key = callback->getArg(1);
  if (!inBpfMemory(key_type)) {
    key = b_.CreateLoad(b_.GetType(key_type), key, "key");
  }

  auto &map = static_cast<Map &>(*f.expr);
  auto map_info = bpftrace_.resources.maps_info.find(map.ident);
  if (map_info == bpftrace_.resources.maps_info.end()) {
    LOG(BUG) << "map name: \"" << map.ident << "\" not found";
  }

  auto &val_type = f.decl->type.GetField(1).type;
  Value *val = callback->getArg(2);

  const auto &map_val_type = map_info->second.value_type;
  if (canAggPerCpuMapElems(map_val_type, map_info->second.key_type)) {
    val = b_.CreatePerCpuMapAggElems(
        ctx_, map, callback->getArg(1), map_val_type, map.loc);
  } else if (!inBpfMemory(val_type)) {
    val = b_.CreateLoad(b_.GetType(val_type), val, "val");
  }

  // Create decl variable for use in this iteration of the loop
  auto tuple = createTuple(f.decl->type,
                           { { key, &f.decl->loc }, { val, &f.decl->loc } },
                           f.decl->ident,
                           f.decl->loc);
  variables_[scope_stack_.back()][f.decl->ident] = VariableLLVM{
    tuple, b_.GetType(f.decl->type)
  };

  // 1. Save original locations of variables which will form part of the
  //    callback context
  // 2. Replace variable expressions with those from the context
  Value *ctx = callback->getArg(3);
  const auto &ctx_fields = f.ctx_type.GetFields();
  std::unordered_map<std::string, Value *> orig_ctx_vars;
  for (size_t i = 0; i < ctx_fields.size(); i++) {
    const auto &field = ctx_fields[i];
    orig_ctx_vars[field.name] = getVariable(field.name).value;

    auto *ctx_field_ptr = b_.CreateGEP(
        ctx_t, ctx, { b_.getInt64(0), b_.getInt32(i) }, "ctx." + field.name);
    getVariable(field.name).value = b_.CreateLoad(b_.getPtrTy(),
                                                  ctx_field_ptr,
                                                  field.name);
  }

  // Generate code for the loop body
  visit(f.stmts);
  b_.CreateRet(b_.getInt64(0));

  // Restore original non-context variables
  for (const auto &[ident, expr] : orig_ctx_vars) {
    getVariable(ident).value = expr;
  }

  // Decl variable is not valid beyond this for loop
  variables_[scope_stack_.back()].erase(f.decl->ident);

  b_.restoreIP(saved_ip);
  return callback;
}

bool CodegenLLVM::canAggPerCpuMapElems(const SizedType &val_type,
                                       const SizedType &key_type)
{
  auto map_type = get_map_type(val_type, key_type);
  return val_type.IsCastableMapTy() &&
         (map_type == libbpf::BPF_MAP_TYPE_PERCPU_ARRAY ||
          map_type == libbpf::BPF_MAP_TYPE_PERCPU_HASH);
}

// BPF helpers that use fmt strings (bpf_trace_printk, bpf_seq_printf) expect
// the string passed in a data map. libbpf is able to create the map internally
// if an internal global constant string is used. This function creates the
// constant. Uses bpf_print_id_ to pick the correct format string from
// RequiredResources.
Value *CodegenLLVM::createFmtString(int print_id)
{
  auto fmt_str = bpftrace_.resources.bpf_print_fmts.at(print_id);
  auto res = llvm::dyn_cast<GlobalVariable>(module_->getOrInsertGlobal(
      "__fmt_" + std::to_string(print_id),
      ArrayType::get(b_.getInt8Ty(), fmt_str.length() + 1)));
  res->setConstant(true);
  res->setInitializer(
      ConstantDataArray::getString(module_->getContext(), fmt_str.c_str()));
  res->setAlignment(MaybeAlign(1));
  res->setLinkage(llvm::GlobalValue::InternalLinkage);
  return res;
}

/// This should emit
///
///    declare !dbg !... extern_weak ... @func_name(...) section ".ksyms"
///
/// with proper debug info entry.
///
/// The function type is retrieved from kernel BTF.
///
/// If the function declaration is already in the module, just return it.
///
llvm::Function *CodegenLLVM::DeclareKernelFunc(Kfunc kfunc)
{
  const std::string &func_name = kfunc_name(kfunc);
  if (auto *fun = module_->getFunction(func_name))
    return fun;

  std::string err;
  auto maybe_func_type = bpftrace_.btf_->resolve_args(func_name, true, err);
  if (!maybe_func_type.has_value()) {
    throw FatalUserException(err);
  }

  std::vector<llvm::Type *> args;
  for (auto &field : maybe_func_type->fields) {
    if (field.name != RETVAL_FIELD_NAME)
      args.push_back(b_.GetType(field.type, false));
  }

  FunctionType *func_type = FunctionType::get(
      b_.GetType(maybe_func_type->GetField(RETVAL_FIELD_NAME).type, false),
      args,
      false);

  auto *fun = llvm::Function::Create(func_type,
                                     llvm::GlobalValue::ExternalWeakLinkage,
                                     func_name,
                                     module_.get());
  fun->setSection(".ksyms");
  fun->setUnnamedAddr(GlobalValue::UnnamedAddr::Local);

  // Copy args and remove the last field (retval) as we pass it to
  // createFunctionDebugInfo separately
  Struct debug_args = *maybe_func_type; // copy here
  debug_args.fields.pop_back();
  debug_.createFunctionDebugInfo(
      *fun,
      maybe_func_type->GetField(RETVAL_FIELD_NAME).type,
      debug_args,
      true);

  return fun;
}

CallInst *CodegenLLVM::CreateKernelFuncCall(Kfunc kfunc,
                                            ArrayRef<Value *> args,
                                            const Twine &name)
{
  auto func = DeclareKernelFunc(kfunc);
  return b_.createCall(func->getFunctionType(), func, args, name);
}

/// This should emit
///
///    declare !dbg !... extern ... @var_name(...) section ".ksyms"
///
/// with proper debug info entry.
///
/// The function type is retrieved from kernel BTF.
///
/// If the function declaration is already in the module, just return it.
///
GlobalVariable *CodegenLLVM::DeclareKernelVar(const std::string &var_name)
{
  if (auto *sym = module_->getGlobalVariable(var_name))
    return sym;

  std::string err;
  auto type = bpftrace_.btf_->get_var_type(var_name);
  assert(!type.IsNoneTy()); // already checked in semantic analyser

  auto var = llvm::dyn_cast<GlobalVariable>(
      module_->getOrInsertGlobal(var_name, b_.GetType(type)));
  var->setSection(".ksyms");
  var->setLinkage(llvm::GlobalValue::ExternalLinkage);

  auto var_debug = debug_.createGlobalVariable(var_name, type);
  var->addDebugInfo(var_debug);

  return var;
}

} // namespace bpftrace::ast
