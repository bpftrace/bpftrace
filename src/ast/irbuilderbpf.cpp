#include <filesystem>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Module.h>

#include "arch/arch.h"
#include "ast/async_event_types.h"
#include "ast/codegen_helper.h"
#include "ast/irbuilderbpf.h"
#include "async_action.h"
#include "bpfmap.h"
#include "bpftrace.h"
#include "globalvars.h"
#include "log.h"
#include "types.h"
#include "util/exceptions.h"

namespace bpftrace::ast {

namespace {
std::string probeReadHelperName(bpf_func_id id)
{
  switch (id) {
    case BPF_FUNC_probe_read:
      return "probe_read";
    case BPF_FUNC_probe_read_user:
      return "probe_read_user";
    case BPF_FUNC_probe_read_kernel:
      return "probe_read_kernel";
    case BPF_FUNC_probe_read_str:
      return "probe_read_str";
    case BPF_FUNC_probe_read_user_str:
      return "probe_read_user_str";
    case BPF_FUNC_probe_read_kernel_str:
      return "probe_read_kernel_str";
    default:
      LOG(BUG) << "unknown probe_read id: " << std::to_string(id);
  }
  __builtin_unreachable();
}
} // namespace

bpf_func_id IRBuilderBPF::selectProbeReadHelper(AddrSpace as, bool str)
{
  bpf_func_id fn;
  if (as == AddrSpace::kernel) {
    fn = str ? BPF_FUNC_probe_read_kernel_str : BPF_FUNC_probe_read_kernel;
  } else if (as == AddrSpace::user) {
    fn = str ? BPF_FUNC_probe_read_user_str : BPF_FUNC_probe_read_user;
  } else {
    // if the kernel has the new helpers but AS is still none it is a bug
    // in bpftrace, assert catches it for debug builds.
    // assert(as != AddrSpace::none);
    static bool warnonce = false;
    if (!warnonce) {
      warnonce = true;
      LOG(WARNING) << "Addrspace is not set";
    }
    fn = str ? BPF_FUNC_probe_read_str : BPF_FUNC_probe_read;
  }

  return fn;
}

// This constant is defined in the Linux kernel's proc_ns.h
// It represents the inode of the initial (global) PID namespace
constexpr uint32_t PROC_PID_INIT_INO = 0xeffffffc;

Value *IRBuilderBPF::CreateGetPid(const Location &loc, bool force_init)
{
  const auto &pidns = bpftrace_.get_pidns_self_stat();
  if (!force_init && pidns && pidns->st_ino != PROC_PID_INIT_INO) {
    // Get namespaced target PID when we're running in a namespace
    AllocaInst *res = CreateAllocaBPF(BpfPidnsInfoType(), "bpf_pidns_info");
    CreateGetNsPidTgid(
        getInt64(pidns->st_dev), getInt64(pidns->st_ino), res, loc);
    Value *pid = CreateLoad(
        getInt32Ty(),
        CreateGEP(BpfPidnsInfoType(), res, { getInt32(0), getInt32(1) }));
    CreateLifetimeEnd(res);
    return pid;
  }

  // Get global target PID otherwise
  Value *pidtgid = CreateGetPidTgid(loc);
  Value *pid = CreateTrunc(CreateLShr(pidtgid, 32), getInt32Ty(), "pid");
  return pid;
}

Value *IRBuilderBPF::CreateGetTid(const Location &loc, bool force_init)
{
  const auto &pidns = bpftrace_.get_pidns_self_stat();
  if (!force_init && pidns && pidns->st_ino != PROC_PID_INIT_INO) {
    // Get namespaced target TID when we're running in a namespace
    AllocaInst *res = CreateAllocaBPF(BpfPidnsInfoType(), "bpf_pidns_info");
    CreateGetNsPidTgid(
        getInt64(pidns->st_dev), getInt64(pidns->st_ino), res, loc);
    Value *tid = CreateLoad(
        getInt32Ty(),
        CreateGEP(BpfPidnsInfoType(), res, { getInt32(0), getInt32(0) }));
    CreateLifetimeEnd(res);
    return tid;
  }

  // Get global target TID otherwise
  Value *pidtgid = CreateGetPidTgid(loc);
  Value *tid = CreateTrunc(pidtgid, getInt32Ty(), "tid");
  return tid;
}

AllocaInst *IRBuilderBPF::CreateUSym(Value *val,
                                     int probe_id,
                                     const Location &loc)
{
  std::vector<llvm::Type *> elements = {
    getInt64Ty(), // addr
    getInt32Ty(), // pid
    getInt32Ty(), // probe id
  };
  StructType *usym_t = GetStructType("usym_t", elements, false);
  AllocaInst *buf = CreateAllocaBPF(usym_t, "usym");

  Value *pid = CreateGetPid(loc, false);
  Value *probe_id_val = Constant::getIntegerValue(getInt32Ty(),
                                                  APInt(32, probe_id));

  // The extra 0 here ensures the type of addr_offset will be int64
  Value *addr_offset = CreateGEP(usym_t, buf, { getInt64(0), getInt32(0) });
  Value *pid_offset = CreateGEP(usym_t, buf, { getInt64(0), getInt32(1) });
  Value *probeid_offset = CreateGEP(usym_t, buf, { getInt64(0), getInt32(2) });

  CreateStore(val, addr_offset);
  CreateStore(pid, pid_offset);
  CreateStore(probe_id_val, probeid_offset);
  return buf;
}

StructType *IRBuilderBPF::GetStackStructType(const StackType &stack_type)
{
  std::vector<llvm::Type *> elements;
  // Kernel stacks should not be differentiated by pid, since the kernel
  // address space is the same between pids (and when aggregating you *want*
  // to be able to correlate between pids in most cases). User-space stacks
  // are special because of ASLR, hence we also store the pid; probe id is
  // stored for cases when only ELF resolution works (e.g. ASLR disabled and
  // process exited).
  if (!stack_type.kernel) {
    elements.emplace_back(getInt32Ty()); // pid
    elements.emplace_back(getInt32Ty()); // probe id
  }
  // If the offset changes, make sure to also change the codegen for "stack_len"
  elements.emplace_back(getInt64Ty()); // nr_stack_frames

  if (stack_type.mode == StackMode::build_id) {
    // struct bpf_stack_build_id {
    //   __s32		status;
    //   unsigned char	build_id[BPF_BUILD_ID_SIZE];
    //   union {
    //     __u64	offset;
    //     __u64	ip;
    //   };
    // };
    std::vector<llvm::Type *> union_elem = {
      getInt64Ty(),
    };
    StructType *union_type = GetStructType("offset_ip_union",
                                           union_elem,
                                           false);

    std::vector<llvm::Type *> build_id_elements = {
      getInt32Ty(), // status
      ArrayType::get(getInt8Ty(),
                     BPF_BUILD_ID_SIZE), // build_id[BPF_BUILD_ID_SIZE]
      union_type,
    };
    StructType *stack_build_id = GetStructType("stack_build_id",
                                               build_id_elements,
                                               false);
    elements.emplace_back(ArrayType::get(stack_build_id, stack_type.limit));
  } else {
    elements.emplace_back(ArrayType::get(getInt64Ty(), stack_type.limit));
  }

  return GetStructType(stack_type.name(), elements, false);
}

StructType *IRBuilderBPF::GetStructType(
    const std::string &name,
    const std::vector<llvm::Type *> &elements,
    bool packed)
{
  auto search = structs_.find(name);
  if (search != structs_.end())
    return search->second;

  StructType *s = nullptr;
  if (!elements.empty()) {
    s = StructType::create(module_.getContext(), elements, name, packed);
  } else {
    s = StructType::create(module_.getContext(), name);
  }
  structs_.insert({ name, s });
  return s;
}

IRBuilderBPF::IRBuilderBPF(LLVMContext &context,
                           Module &module,
                           BPFtrace &bpftrace,
                           AsyncIds &async_ids)
    : IRBuilder<>(context),
      module_(module),
      bpftrace_(bpftrace),
      async_ids_(async_ids)
{
  // Declare external LLVM function
  FunctionType *pseudo_func_type = FunctionType::get(
      getInt64Ty(), { getInt64Ty(), getInt64Ty() }, false);
  llvm::Function::Create(pseudo_func_type,
                         GlobalValue::ExternalLinkage,
                         "llvm.bpf.pseudo",
                         &module_);
}

void IRBuilderBPF::hoist(const std::function<void()> &functor)
{
  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock &entry_block = parent->getEntryBlock();

  auto ip = saveIP();
  if (entry_block.empty())
    SetInsertPoint(&entry_block);
  else
    SetInsertPoint(&entry_block.front());

  functor();
  restoreIP(ip);
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(llvm::Type *ty,
                                          const std::string &name)
{
  // Anything this large should be allocated in a scratch map instead
  assert(module_.getDataLayout().getTypeAllocSize(ty) <= 256);

  AllocaInst *alloca;
  hoist([this, ty, &name, &alloca]() {
    alloca = CreateAlloca(ty, nullptr, name);
  });

  CreateLifetimeStart(alloca);
  return alloca;
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(const SizedType &stype,
                                          const std::string &name)
{
  llvm::Type *ty = GetType(stype);
  return CreateAllocaBPF(ty, name);
}

void IRBuilderBPF::CreateAllocationInit(const SizedType &stype, Value *alloc)
{
  if (needMemcpy(stype)) {
    CreateMemsetBPF(alloc, getInt8(0), stype.GetSize());
  } else {
    CreateStore(Constant::getNullValue(GetType(stype)), alloc);
  }
}

AllocaInst *IRBuilderBPF::CreateAllocaBPFInit(const SizedType &stype,
                                              const std::string &name)
{
  // Anything this large should be allocated in a scratch map instead
  assert(stype.GetSize() <= 256);

  AllocaInst *alloca;
  hoist([this, &stype, &name, &alloca]() {
    llvm::Type *ty = GetType(stype);
    alloca = CreateAlloca(ty, nullptr, name);
    CreateLifetimeStart(alloca);
    CreateAllocationInit(stype, alloca);
  });
  return alloca;
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(int bytes, const std::string &name)
{
  llvm::Type *ty = ArrayType::get(getInt8Ty(), bytes);
  return CreateAllocaBPF(ty, name);
}

void IRBuilderBPF::CreateMemsetBPF(Value *ptr, Value *val, uint32_t size)
{
  if (size > 512) {
    // Note we are "abusing" bpf_probe_read_kernel() by reading from NULL
    // which triggers a call into the kernel-optimized memset().
    //
    // Upstream blesses this trick so we should be able to count on them
    // to maintain these semantics.
    //
    // Also note we are avoiding a call to CreateProbeRead(), as it wraps
    // calls to probe read helpers with the -k error reporting feature.
    // The call here will always fail and we want it that way. So avoid
    // reporting errors to the user.
    auto probe_read_id = BPF_FUNC_probe_read_kernel;
    FunctionType *proberead_func_type = FunctionType::get(
        getInt64Ty(),
        { ptr->getType(), getInt32Ty(), GetNull()->getType() },
        false);
    PointerType *proberead_func_ptr_type = PointerType::get(getContext(), 0);
    Constant *proberead_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                     getInt64(probe_read_id),
                                                     proberead_func_ptr_type);
    createCall(proberead_func_type,
               proberead_func,
               { ptr, getInt32(size), GetNull() },
               probeReadHelperName(probe_read_id));
  } else {
    // Use unrolled memset for memsets less than 512 bytes mostly for
    // correctness.
    //
    // It appears that helper based memsets obscure LLVM stack optimizer view
    // into memory usage such that programs that were below stack limit with
    // builtin memsets will bloat with helper based memsets enough to where
    // LLVM BPF backend will barf.
    //
    // So only use helper based memset when we really need it. And that's when
    // we're memset()ing off-stack. We know it's off stack b/c 512 is program
    // stack limit.
    CreateMemSet(ptr, val, getInt64(size), MaybeAlign(1));
  }
}

void IRBuilderBPF::CreateMemcpyBPF(Value *dst, Value *src, uint32_t size)
{
  if (size > 512) {
    // Note we are avoiding a call to CreateProbeRead(), as it wraps
    // calls to probe read helpers with the -k error reporting feature.
    //
    // Errors are not ever expected, as memcpy should only be used when
    // you're sure src and dst are both in BPF memory.
    auto probe_read_id = BPF_FUNC_probe_read_kernel;
    FunctionType *probe_read_func_type = FunctionType::get(
        getInt64Ty(), { dst->getType(), getInt32Ty(), src->getType() }, false);
    PointerType *probe_read_func_ptr_type = PointerType::get(getContext(), 0);
    Constant *probe_read_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                      getInt64(probe_read_id),
                                                      probe_read_func_ptr_type);
    createCall(probe_read_func_type,
               probe_read_func,
               { dst, getInt32(size), src },
               probeReadHelperName(probe_read_id));
  } else {
    CreateMemCpy(dst, MaybeAlign(1), src, MaybeAlign(1), size);
  }
}

llvm::ConstantInt *IRBuilderBPF::GetIntSameSize(uint64_t C, llvm::Type *ty)
{
  assert(ty->isIntegerTy());
  unsigned size = ty->getIntegerBitWidth();
  return getIntN(size, C);
}

llvm::ConstantInt *IRBuilderBPF::GetIntSameSize(uint64_t C, llvm::Value *expr)
{
  unsigned size = expr->getType()->getIntegerBitWidth();
  return getIntN(size, C);
}

/// Convert internal SizedType to a corresponding LLVM type.
///
/// Only one type is not converted directly into an LLVM type:
/// - C structs (c_struct) are represented as byte arrays
llvm::Type *IRBuilderBPF::GetType(const SizedType &stype)
{
  llvm::Type *ty;
  if (stype.IsByteArray() || stype.IsCStructTy()) {
    ty = ArrayType::get(getInt8Ty(), stype.GetSize());
  } else if (stype.IsArrayTy()) {
    ty = ArrayType::get(GetType(stype.GetElementTy()), stype.GetNumElements());
  } else if (stype.IsTupleTy() || stype.IsRecordTy()) {
    std::vector<llvm::Type *> llvm_elems;
    std::string ty_name;

    for (const auto &elem : stype.GetFields()) {
      const auto &elemtype = elem.type;
      llvm_elems.emplace_back(GetType(elemtype));
      ty_name += typestr(elemtype) + "_";
    }
    ty_name += (stype.IsTupleTy() ? "_tuple_t" : "_record_t");

    ty = GetStructType(ty_name, llvm_elems, false);
  } else if (stype.IsStack()) {
    ty = GetStackStructType(stype.stack_type);
  } else if (stype.IsPtrTy()) {
    ty = getPtrTy();
  } else if (stype.IsVoidTy()) {
    ty = getVoidTy();
  } else if (stype.IsBoolTy()) {
    ty = getInt1Ty();
  } else {
    switch (stype.GetSize()) {
      case 16:
        ty = getInt128Ty();
        break;
      case 8:
        ty = getInt64Ty();
        break;
      case 4:
        ty = getInt32Ty();
        break;
      case 2:
        ty = getInt16Ty();
        break;
      case 1:
        ty = getInt8Ty();
        break;
      default:
        LOG(BUG) << stype.GetSize() << " is not a valid type size for GetType";
    }
  }
  return ty;
}

llvm::Type *IRBuilderBPF::GetMapValueType(const SizedType &stype)
{
  llvm::Type *ty;
  if (stype.IsMinTy() || stype.IsMaxTy()) {
    // The first field is the value
    // The second field is the "value is set" flag
    std::vector<llvm::Type *> llvm_elems = { getInt64Ty(), getInt64Ty() };
    ty = GetStructType("min_max_val", llvm_elems, false);
  } else if (stype.IsAvgTy() || stype.IsStatsTy()) {
    // The first field is the total value
    // The second is the count value
    std::vector<llvm::Type *> llvm_elems = { getInt64Ty(), getInt64Ty() };
    ty = GetStructType("avg_stas_val", llvm_elems, false);
  } else if (stype.IsTSeriesTy()) {
    std::vector<llvm::Type *> llvm_elems = { getInt64Ty(),
                                             getInt64Ty(),
                                             getInt64Ty() };
    ty = GetStructType("t_series_val", llvm_elems, false);
  } else {
    ty = GetType(stype);
  }

  return ty;
}

/// Creates a call to a BPF helper function
///
/// A call to a helper function can be marked as "pure" to allow LLVM to
/// optimise around it.
///
/// ** BE VERY CAREFUL when marking a helper function as pure - marking an
/// impure helper as pure can result in undefined behaviour. **
///
/// Guidelines for deciding if a helper can be considered pure:
/// - It must always return the same value when called repeatedly with the same
///   arguments within a single probe's context
/// - It must not read or write any memory in the BPF address space (e.g. it
///   mustn't take any pointers to BPF memory as parameters)
/// - It must not have any intentional side effects outside of the BPF address
///   space, otherwise these may be optimised out, e.g. pushing to the ring
///   buffer, signalling a process
CallInst *IRBuilderBPF::CreateHelperCall(bpf_func_id func_id,
                                         FunctionType *helper_type,
                                         ArrayRef<Value *> args,
                                         bool is_pure,
                                         const Twine &Name,
                                         const Location &loc)
{
  bpftrace_.helper_use_loc_[func_id].emplace_back(RuntimeErrorId::HELPER_ERROR,
                                                  func_id,
                                                  loc);
  PointerType *helper_ptr_type = PointerType::get(getContext(), 0);
  Constant *helper_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                getInt64(func_id),
                                                helper_ptr_type);
  CallInst *call = createCall(helper_type, helper_func, args, Name);

  // When we tell LLVM that this function call "does not access memory", this
  // only refers to BPF memory. Accessing kernel or user memory is fine within
  // a "pure helper", as we can consider kernel/user memory as constant.
  if (is_pure)
    call->setDoesNotAccessMemory();
  return call;
}

CallInst *IRBuilderBPF::createCall(FunctionType *callee_type,
                                   Value *callee,
                                   ArrayRef<Value *> args,
                                   const Twine &Name)
{
  return CreateCall(callee_type, callee, args, Name);
}

Value *IRBuilderBPF::GetMapVar(const std::string &map_name)
{
  return module_.getGlobalVariable(bpf_map_name(map_name));
}

Value *IRBuilderBPF::GetNull()
{
  return ConstantExpr::getCast(Instruction::IntToPtr, getInt64(0), getPtrTy());
}

CallInst *IRBuilderBPF::CreateMapLookup(Map &map,
                                        Value *key,
                                        const std::string &name)
{
  return createMapLookup(map.ident, key, name);
}

CallInst *IRBuilderBPF::createMapLookup(const std::string &map_name,
                                        Value *key,
                                        const std::string &name)
{
  Value *map_ptr = GetMapVar(map_name);
  // void *map_lookup_elem(struct bpf_map * map, void * key)
  // Return: Map value or NULL

  assert(key->getType()->isPointerTy());
  FunctionType *lookup_func_type = FunctionType::get(
      getPtrTy(), { map_ptr->getType(), key->getType() }, false);
  PointerType *lookup_func_ptr_type = PointerType::get(getContext(), 0);
  Constant *lookup_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                getInt64(
                                                    BPF_FUNC_map_lookup_elem),
                                                lookup_func_ptr_type);
  return createCall(lookup_func_type, lookup_func, { map_ptr, key }, name);
}

CallInst *IRBuilderBPF::createPerCpuMapLookup(const std::string &map_name,
                                              Value *key,
                                              Value *cpu,
                                              const std::string &name)
{
  Value *map_ptr = GetMapVar(map_name);
  // void *map_lookup_percpu_elem(struct bpf_map * map, void * key, u32 cpu)
  // Return: Map value or NULL

  assert(key->getType()->isPointerTy());
  FunctionType *lookup_func_type = FunctionType::get(
      getPtrTy(), { map_ptr->getType(), key->getType(), getInt32Ty() }, false);
  PointerType *lookup_func_ptr_type = PointerType::get(getContext(), 0);
  Constant *lookup_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(BPF_FUNC_map_lookup_percpu_elem),
      lookup_func_ptr_type);
  return createCall(lookup_func_type, lookup_func, { map_ptr, key, cpu }, name);
}

Value *IRBuilderBPF::CreateGetStrAllocation(const std::string &name,
                                            const Location &loc,
                                            uint64_t pad)
{
  const auto max_strlen = bpftrace_.config_->max_strlen + pad;
  const auto str_type = CreateArray(max_strlen, CreateInt8());
  return createAllocation(bpftrace::globalvars::GET_STR_BUFFER,
                          GetType(str_type),
                          name,
                          loc,
                          [](AsyncIds &async_ids) { return async_ids.str(); });
}

Value *IRBuilderBPF::CreateGetFmtStringArgsAllocation(StructType *struct_type,
                                                      const std::string &name,
                                                      const Location &loc)
{
  return createAllocation(
      bpftrace::globalvars::FMT_STRINGS_BUFFER, struct_type, name, loc);
}

Value *IRBuilderBPF::CreateAnonStructAllocation(const SizedType &tuple_type,
                                                const std::string &name,
                                                const Location &loc)
{
  return createAllocation(bpftrace::globalvars::ANON_STRUCT_BUFFER,
                          GetType(tuple_type),
                          name,
                          loc,
                          [](AsyncIds &async_ids) {
                            return async_ids.anon_struct();
                          });
}

Value *IRBuilderBPF::CreateCallStackAllocation(const SizedType &stack_type,
                                               const std::string &name,
                                               const Location &loc)
{
  return createAllocation(bpftrace::globalvars::CALL_STACK_BUFFER,
                          GetType(stack_type),
                          name,
                          loc,
                          [](AsyncIds &async_ids) {
                            return async_ids.call_stack();
                          });
}

Value *IRBuilderBPF::CreateJoinAllocation(const Location &loc)
{
  return createScratchBuffer(bpftrace::globalvars::JOIN_BUFFER, loc, 0);
}

Value *IRBuilderBPF::CreateReadMapValueAllocation(const SizedType &value_type,
                                                  const std::string &name,
                                                  const Location &loc)
{
  return createAllocation(bpftrace::globalvars::READ_MAP_VALUE_BUFFER,
                          GetType(value_type),
                          name,
                          loc,
                          [](AsyncIds &async_ids) {
                            return async_ids.read_map_value();
                          });
}

Value *IRBuilderBPF::CreateWriteMapValueAllocation(const SizedType &value_type,
                                                   const std::string &name,
                                                   const Location &loc)
{
  return createAllocation(bpftrace::globalvars::WRITE_MAP_VALUE_BUFFER,
                          GetType(value_type),
                          name,
                          loc);
}

Value *IRBuilderBPF::CreateVariableAllocationInit(const SizedType &value_type,
                                                  const std::string &name,
                                                  const Location &loc)
{
  // Hoist variable declaration and initialization to entry point of
  // probe/subprogram. While we technically do not need this as variables
  // are properly scoped, it eases debugging and is consistent with previous
  // stack-only variable implementation.
  Value *alloc;
  hoist([this, &value_type, &name, &loc, &alloc] {
    alloc = createAllocation(bpftrace::globalvars::VARIABLE_BUFFER,
                             GetType(value_type),
                             name,
                             loc,
                             [](AsyncIds &async_ids) {
                               return async_ids.variable();
                             });
    CreateAllocationInit(value_type, alloc);
  });
  return alloc;
}

Value *IRBuilderBPF::CreateMapKeyAllocation(const SizedType &value_type,
                                            const std::string &name,
                                            const Location &loc)
{
  return createAllocation(bpftrace::globalvars::MAP_KEY_BUFFER,
                          GetType(value_type),
                          name,
                          loc,
                          [](AsyncIds &async_ids) {
                            return async_ids.map_key();
                          });
}

Value *IRBuilderBPF::createAllocation(
    std::string_view global_var_name,
    llvm::Type *obj_type,
    const std::string &name,
    const Location &loc,
    std::optional<std::function<size_t(AsyncIds &)>> gen_async_id_cb)
{
  const auto obj_size = module_.getDataLayout().getTypeAllocSize(obj_type);
  const auto on_stack_limit = bpftrace_.config_->on_stack_limit;
  if (obj_size > on_stack_limit) {
    return createScratchBuffer(global_var_name,
                               loc,
                               gen_async_id_cb ? (*gen_async_id_cb)(async_ids_)
                                               : 0);
  }
  return CreateAllocaBPF(obj_type, name);
}

Value *IRBuilderBPF::createScratchBuffer(std::string_view global_var_name,
                                         const Location &loc,
                                         size_t key)
{
  // These specific global variables are nested arrays
  // (see get_sized_type in globalvars.cpp).
  // The top level array is for each CPU where the length is
  // MAX_CPU_ID + 1. This is so there is no contention between CPUs
  // when accessing this global value.

  // The second level array is for each key where the length is
  // the number of elements for this specific global, e.g. if
  // there are multiple strings that can't fit on the BPF stack
  // then there will be one element per string.

  // The last level is either an array of bytes (e.g. for strings)
  // or a single value (e.g. for ints like the EVENT_LOSS_COUNTER)
  const auto global_name = std::string(global_var_name);
  bpftrace_.resources.global_vars.check_index(global_name,
                                              bpftrace_.resources,
                                              key);
  auto sized_type = bpftrace_.resources.global_vars.get_sized_type(
      global_name, bpftrace_.resources, *bpftrace_.config_);
  auto *cpu_id = CreateGetCpuId(loc);
  auto *max = CreateLoad(getInt64Ty(),
                         module_.getGlobalVariable(
                             std::string(bpftrace::globalvars::MAX_CPU_ID)));
  // Mask CPU ID by MAX_CPU_ID to ensure BPF verifier knows CPU ID is bounded
  // on older kernels. Note this means MAX_CPU_ID must be 2^N - 1 for some N.
  // See get_max_cpu_id() for more details.
  auto *bounded_cpu_id = CreateAnd(cpu_id, max, "cpu.id.bounded");

  // Note the 1st index is 0 because we're pointing to
  // ValueType var[MAX_CPU_ID + 1][num_elements]
  // More details on using GEP: https://llvm.org/docs/LangRef.html#id236
  if (sized_type.GetElementTy().GetElementTy().IsArrayTy()) {
    return CreateGEP(
        GetType(sized_type),
        module_.getGlobalVariable(global_name),
        { getInt64(0), bounded_cpu_id, getInt64(key), getInt64(0) });
  }

  return CreateGEP(GetType(sized_type),
                   module_.getGlobalVariable(global_name),
                   { getInt64(0), bounded_cpu_id, getInt64(key) });
}

Value *IRBuilderBPF::CreateMapLookupElem(Map &map,
                                         Value *key,
                                         const Location &loc)
{
  return CreateMapLookupElem(map.ident, key, map.value_type, loc);
}

Value *IRBuilderBPF::CreateMapLookupElem(const std::string &map_name,
                                         Value *key,
                                         SizedType &type,
                                         const Location &loc)
{
  CallInst *call = createMapLookup(map_name, key);

  // Check if result == 0
  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_success",
                                                        parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_failure",
                                                        parent);
  BasicBlock *lookup_merge_block = BasicBlock::Create(module_.getContext(),
                                                      "lookup_merge",
                                                      parent);

  Value *value = CreateReadMapValueAllocation(type, "lookup_elem_val", loc);
  Value *condition = CreateICmpNE(CreateIntCast(call, getPtrTy(), true),
                                  GetNull(),
                                  "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);
  if (needMemcpy(type))
    CreateMemcpyBPF(value, call, type.GetSize());
  else {
    CreateStore(CreateLoad(GetType(type), call), value);
  }
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_failure_block);
  if (needMemcpy(type))
    CreateMemsetBPF(value, getInt8(0), type.GetSize());
  else
    CreateStore(Constant::getNullValue(GetType(type)), value);
  CreateRuntimeError(
      RuntimeErrorId::HELPER_ERROR, getInt32(0), BPF_FUNC_map_lookup_elem, loc);
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_merge_block);
  if (needMemcpy(type))
    return value;

  // value is a pointer to i64
  Value *ret = CreateLoad(GetType(type), value);
  if (dyn_cast<AllocaInst>(value))
    CreateLifetimeEnd(value);
  return ret;
}

Value *IRBuilderBPF::CreatePerCpuMapAggElems(Map &map,
                                             Value *key,
                                             const SizedType &type,
                                             const Location &loc)
{
  // int ret = 0;
  // int i = 0;
  // while (i < nr_cpus) {
  //   int * cpu_value = map_lookup_percpu_elem(map, key, i);
  //   if (cpu_value == NULL) {
  //     if (i == 0)
  //        log_error("Key not found")
  //     else
  //        debug("No cpu found for cpu id: %lu", i) // Mostly for AOT
  //     break;
  //   }
  //   // update ret for sum, count, avg, min, max
  //   i++;
  // }
  // return ret;

  const std::string &map_name = map.ident;

  AllocaInst *i = CreateAllocaBPF(getInt32Ty(), "i");
  AllocaInst *val_1 = CreateAllocaBPF(getInt64Ty(), "val_1");
  // used for min/max/avg
  AllocaInst *val_2 = CreateAllocaBPF(getInt64Ty(), "val_2");

  CreateStore(getInt32(0), i);
  CreateStore(getInt64(0), val_1);
  CreateStore(getInt64(0), val_2);

  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock *while_cond = BasicBlock::Create(module_.getContext(),
                                              "while_cond",
                                              parent);
  BasicBlock *while_body = BasicBlock::Create(module_.getContext(),
                                              "while_body",
                                              parent);
  BasicBlock *while_end = BasicBlock::Create(module_.getContext(),
                                             "while_end",
                                             parent);
  CreateBr(while_cond);
  SetInsertPoint(while_cond);

  auto *cond = CreateICmp(CmpInst::ICMP_ULT,
                          CreateLoad(getInt32Ty(), i),
                          CreateLoad(getInt32Ty(),
                                     module_.getGlobalVariable(std::string(
                                         bpftrace::globalvars::NUM_CPUS))),
                          "num_cpu.cmp");
  CreateCondBr(cond, while_body, while_end);

  SetInsertPoint(while_body);

  CallInst *call = createPerCpuMapLookup(map_name,
                                         key,
                                         CreateLoad(getInt32Ty(), i));

  llvm::Function *lookup_parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_success",
                                                        lookup_parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_failure",
                                                        lookup_parent);
  Value *condition = CreateICmpNE(CreateIntCast(call, getPtrTy(), true),
                                  GetNull(),
                                  "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);

  if (type.IsMinTy() || type.IsMaxTy()) {
    createPerCpuMinMax(val_1, val_2, call, type);
  } else if (type.IsAvgTy()) {
    createPerCpuAvg(val_1, val_2, call, type);
  } else if (type.IsSumTy() || type.IsCountTy()) {
    createPerCpuSum(val_1, call, type);
  } else {
    LOG(BUG) << "Unsupported map aggregation type: " << type;
  }

  // ++i;
  CreateStore(CreateAdd(CreateLoad(getInt32Ty(), i), getInt32(1)), i);

  CreateBr(while_cond);
  SetInsertPoint(lookup_failure_block);

  llvm::Function *error_parent = GetInsertBlock()->getParent();
  BasicBlock *error_success_block = BasicBlock::Create(module_.getContext(),
                                                       "error_success",
                                                       error_parent);
  BasicBlock *error_failure_block = BasicBlock::Create(module_.getContext(),
                                                       "error_failure",
                                                       error_parent);

  // If the CPU is 0 and the map lookup fails it means the key doesn't exist.
  Value *error_condition = CreateICmpEQ(CreateLoad(getInt32Ty(), i),
                                        getInt32(0),
                                        "error_lookup_cond");
  CreateCondBr(error_condition, error_success_block, error_failure_block);

  SetInsertPoint(error_success_block);

  CreateRuntimeError(RuntimeErrorId::HELPER_ERROR,
                     getInt32(0),
                     BPF_FUNC_map_lookup_percpu_elem,
                     loc);
  CreateBr(while_end);

  SetInsertPoint(error_failure_block);

  CreateRuntimeError(RuntimeErrorId::CPU_COUNT_MISMATCH, loc);
  CreateBr(while_end);

  SetInsertPoint(while_end);

  CreateLifetimeEnd(i);

  Value *ret_reg;

  if (type.IsAvgTy()) {
    AllocaInst *ret = CreateAllocaBPF(getInt64Ty(), "ret");
    // BPF doesn't yet support a signed division so we have to check if
    // the value is negative, flip it, do an unsigned division, and then
    // flip it back
    if (type.IsSigned()) {
      llvm::Function *avg_parent = GetInsertBlock()->getParent();
      BasicBlock *is_negative_block = BasicBlock::Create(module_.getContext(),
                                                         "is_negative",
                                                         avg_parent);
      BasicBlock *is_positive_block = BasicBlock::Create(module_.getContext(),
                                                         "is_positive",
                                                         avg_parent);
      BasicBlock *merge_block = BasicBlock::Create(module_.getContext(),
                                                   "is_negative_merge_block",
                                                   avg_parent);

      Value *is_negative_condition = CreateICmpSLT(
          CreateLoad(getInt64Ty(), val_1), getInt64(0), "is_negative_cond");
      CreateCondBr(is_negative_condition, is_negative_block, is_positive_block);

      SetInsertPoint(is_negative_block);

      Value *pos_total = CreateAdd(CreateNot(CreateLoad(getInt64Ty(), val_1)),
                                   getInt64(1));
      Value *pos_avg = CreateUDiv(pos_total, CreateLoad(getInt64Ty(), val_2));
      CreateStore(CreateNeg(pos_avg), ret);

      CreateBr(merge_block);

      SetInsertPoint(is_positive_block);

      CreateStore(CreateUDiv(CreateLoad(getInt64Ty(), val_1),
                             CreateLoad(getInt64Ty(), val_2)),
                  ret);

      CreateBr(merge_block);

      SetInsertPoint(merge_block);
      ret_reg = CreateLoad(getInt64Ty(), ret);
      CreateLifetimeEnd(ret);
    } else {
      ret_reg = CreateUDiv(CreateLoad(getInt64Ty(), val_1),
                           CreateLoad(getInt64Ty(), val_2));
    }
  } else {
    ret_reg = CreateLoad(getInt64Ty(), val_1);
  }

  CreateLifetimeEnd(val_1);
  CreateLifetimeEnd(val_2);
  return ret_reg;
}

void IRBuilderBPF::createPerCpuSum(AllocaInst *ret,
                                   CallInst *call,
                                   const SizedType &type)
{
  CreateStore(CreateAdd(CreateLoad(GetType(type), call),
                        CreateLoad(getInt64Ty(), ret)),
              ret);
}

void IRBuilderBPF::createPerCpuMinMax(AllocaInst *ret,
                                      AllocaInst *is_ret_set,
                                      CallInst *call,
                                      const SizedType &type)
{
  auto *value_type = GetMapValueType(type);
  bool is_max = type.IsMaxTy();

  Value *mm_val = CreateLoad(
      getInt64Ty(), CreateGEP(value_type, call, { getInt64(0), getInt32(0) }));

  Value *is_val_set = CreateLoad(
      getInt64Ty(), CreateGEP(value_type, call, { getInt64(0), getInt32(1) }));

  // (ret, is_ret_set, min_max_val, is_val_set) {
  // // if the min_max_val is 0, which is the initial map value,
  // // we need to know if it was explicitly set by user
  // if (!is_val_set == 1) {
  //   return;
  // }
  // if (!is_ret_set == 1) {
  //   ret = min_max_val;
  //   is_ret_set = 1;
  // } else if (min_max_val > ret) { // or min_max_val < ret if min operation
  //   ret = min_max_val;
  //   is_ret_set = 1;
  // }

  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock *val_set_success = BasicBlock::Create(module_.getContext(),
                                                   "val_set_success",
                                                   parent);
  BasicBlock *min_max_success = BasicBlock::Create(module_.getContext(),
                                                   "min_max_success",
                                                   parent);
  BasicBlock *ret_set_success = BasicBlock::Create(module_.getContext(),
                                                   "ret_set_success",
                                                   parent);
  BasicBlock *merge_block = BasicBlock::Create(module_.getContext(),
                                               "min_max_merge",
                                               parent);

  Value *val_set_condition = CreateICmpEQ(is_val_set,
                                          getInt64(1),
                                          "val_set_cond");

  Value *ret_set_condition = CreateICmpEQ(CreateLoad(getInt64Ty(), is_ret_set),
                                          getInt64(1),
                                          "ret_set_cond");

  Value *min_max_condition;

  if (is_max) {
    min_max_condition =
        type.IsSigned()
            ? CreateICmpSGT(mm_val, CreateLoad(getInt64Ty(), ret), "max_cond")
            : CreateICmpUGT(mm_val, CreateLoad(getInt64Ty(), ret), "max_cond");
  } else {
    min_max_condition =
        type.IsSigned()
            ? CreateICmpSLT(mm_val, CreateLoad(getInt64Ty(), ret), "min_cond")
            : CreateICmpULT(mm_val, CreateLoad(getInt64Ty(), ret), "max_cond");
  }

  // if (is_val_set == 1)
  CreateCondBr(val_set_condition, val_set_success, merge_block);

  SetInsertPoint(val_set_success);

  // if (is_ret_set == 1)
  CreateCondBr(ret_set_condition, ret_set_success, min_max_success);

  SetInsertPoint(ret_set_success);

  // if (min_max_val > ret) or if (min_max_val < ret)
  CreateCondBr(min_max_condition, min_max_success, merge_block);

  SetInsertPoint(min_max_success);

  // ret = cpu_value;
  CreateStore(mm_val, ret);
  // is_ret_set = 1;
  CreateStore(getInt64(1), is_ret_set);

  CreateBr(merge_block);

  SetInsertPoint(merge_block);
}

void IRBuilderBPF::createPerCpuAvg(AllocaInst *total,
                                   AllocaInst *count,
                                   CallInst *call,
                                   const SizedType &type)
{
  auto *value_type = GetMapValueType(type);

  Value *total_val = CreateLoad(
      getInt64Ty(), CreateGEP(value_type, call, { getInt64(0), getInt32(0) }));

  Value *count_val = CreateLoad(
      getInt64Ty(), CreateGEP(value_type, call, { getInt64(0), getInt32(1) }));

  CreateStore(CreateAdd(total_val, CreateLoad(getInt64Ty(), total)), total);
  CreateStore(CreateAdd(count_val, CreateLoad(getInt64Ty(), count)), count);
}

void IRBuilderBPF::CreateMapUpdateElem(const std::string &map_ident,
                                       Value *key,
                                       Value *val,
                                       const Location &loc,
                                       int64_t flags)
{
  Value *map_ptr = GetMapVar(map_ident);

  assert(key->getType()->isPointerTy());
  assert(val->getType()->isPointerTy());

  Value *flags_val = getInt64(flags);

  // long map_update_elem(struct bpf_map * map, void *key, void * value, u64
  // flags) Return: 0 on success or negative error
  FunctionType *update_func_type = FunctionType::get(
      getInt64Ty(),
      { map_ptr->getType(), key->getType(), val->getType(), getInt64Ty() },
      false);
  PointerType *update_func_ptr_type = PointerType::get(getContext(), 0);
  Constant *update_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                getInt64(
                                                    BPF_FUNC_map_update_elem),
                                                update_func_ptr_type);
  CallInst *call = createCall(update_func_type,
                              update_func,
                              { map_ptr, key, val, flags_val },
                              "update_elem");
  CreateHelperErrorCond(call, BPF_FUNC_map_update_elem, loc);
}

Value *IRBuilderBPF::CreateForRange(Value *iters,
                                    Value *callback,
                                    Value *callback_ctx,
                                    const Location &loc)
{
  // long bpf_loop(__u32 nr_loops, void *callback_fn, void *callback_ctx, u64
  // flags)
  //
  // Return: 0 on success or negative error
  //
  // callback is long (*callback_fn)(u64 index, void *ctx);
  iters = CreateIntCast(iters, getInt32Ty(), true);
  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock *is_positive_block = BasicBlock::Create(module_.getContext(),
                                                     "is_positive",
                                                     parent);
  BasicBlock *merge_block = BasicBlock::Create(module_.getContext(),
                                               "merge",
                                               parent);
  Value *is_positive = CreateICmpSGT(iters, getInt32(0), "is_positive_cond");
  CreateCondBr(is_positive, is_positive_block, merge_block);
  SetInsertPoint(is_positive_block);

  FunctionType *bpf_loop_type = FunctionType::get(
      getInt64Ty(),
      { getInt32Ty(), callback->getType(), getPtrTy(), getInt64Ty() },
      false);
  PointerType *bpf_loop_ptr_type = PointerType::get(getContext(), 0);

  Constant *bpf_loop_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                  getInt64(BPF_FUNC_loop),
                                                  bpf_loop_ptr_type);
  CallInst *call = createCall(
      bpf_loop_type,
      bpf_loop_func,
      { iters,
        callback,
        callback_ctx ? CreateIntToPtr(callback_ctx, getPtrTy()) : GetNull(),
        /*flags=*/getInt64(0) },
      "bpf_loop");
  CreateHelperErrorCond(call, BPF_FUNC_loop, loc);
  CreateBr(merge_block);

  SetInsertPoint(merge_block);
  return call;
}

Value *IRBuilderBPF::CreateForEachMapElem(Map &map,
                                          Value *callback,
                                          Value *callback_ctx,
                                          const Location &loc)
{
  Value *map_ptr = GetMapVar(map.ident);

  // long bpf_for_each_map_elem(struct bpf_map *map, void *callback_fn, void
  // *callback_ctx, u64 flags)
  //
  // Return: 0 on success or negative error
  //
  // callback is long (*callback_fn)(struct bpf_map *map, const void *key, void
  // *value, void *ctx);

  FunctionType *for_each_map_type = FunctionType::get(
      getInt64Ty(),
      { map_ptr->getType(), callback->getType(), getPtrTy(), getInt64Ty() },
      false);
  PointerType *for_each_map_ptr_type = PointerType::get(getContext(), 0);

  Constant *for_each_map_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(BPF_FUNC_for_each_map_elem),
      for_each_map_ptr_type);
  CallInst *call = createCall(
      for_each_map_type,
      for_each_map_func,
      { map_ptr,
        callback,
        callback_ctx ? CreateIntToPtr(callback_ctx, getPtrTy()) : GetNull(),
        /*flags=*/getInt64(0) },
      "for_each_map_elem");
  CreateHelperErrorCond(call, BPF_FUNC_for_each_map_elem, loc);
  return call;
}

void IRBuilderBPF::CreateCheckSetRecursion(const Location &loc,
                                           int early_exit_ret)
{
  const std::string map_ident = to_string(MapType::RecursionPrevention);

  AllocaInst *key = CreateAllocaBPF(getInt32Ty(), "lookup_key");
  CreateStore(getInt32(0), key);

  CallInst *call = createMapLookup(map_ident, key);

  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_success",
                                                        parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_failure",
                                                        parent);
  BasicBlock *merge_block = BasicBlock::Create(module_.getContext(),
                                               "lookup_merge",
                                               parent);

  // Make the verifier happy with a null check even though the value should
  // never be null for key 0.
  Value *condition = CreateICmpNE(
      CreateIntCast(call, getPtrTy(), true),
      ConstantExpr::getCast(Instruction::IntToPtr, getInt64(0), getPtrTy()),
      "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);

  CreateLifetimeEnd(key);

  // createMapLookup  returns an u8*
  auto *cast = CreatePtrToInt(call, getInt64Ty(), "cast");

  Value *prev_value = CREATE_ATOMIC_RMW(AtomicRMWInst::BinOp::Xchg,
                                        cast,
                                        getInt64(1),
                                        8,
                                        AtomicOrdering::SequentiallyConsistent);

  llvm::Function *set_parent = GetInsertBlock()->getParent();
  BasicBlock *value_is_set_block = BasicBlock::Create(module_.getContext(),
                                                      "value_is_set",
                                                      set_parent);
  Value *set_condition = CreateICmpEQ(prev_value,
                                      getInt64(0),
                                      "value_set_condition");
  CreateCondBr(set_condition, merge_block, value_is_set_block);

  SetInsertPoint(value_is_set_block);
  // The counter is set, we need to exit early from the probe.
  // Most of the time this will happen for the functions that can lead
  // to a crash e.g. "queued_spin_lock_slowpath" but it can also happen
  // for nested probes e.g. "page_fault_user" -> "print".
  CreateIncEventLossCounter(loc);
  CreateRet(getInt64(early_exit_ret));

  SetInsertPoint(lookup_failure_block);

  CreateRuntimeError(RuntimeErrorId::CPU_COUNT_MISMATCH, loc);
  CreateRet(getInt64(0));

  SetInsertPoint(merge_block);
}

void IRBuilderBPF::CreateUnSetRecursion(const Location &loc)
{
  const std::string map_ident = to_string(MapType::RecursionPrevention);

  AllocaInst *key = CreateAllocaBPF(getInt32Ty(), "lookup_key");
  CreateStore(getInt32(0), key);

  CallInst *call = createMapLookup(map_ident, key);

  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_success",
                                                        parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_failure",
                                                        parent);
  BasicBlock *merge_block = BasicBlock::Create(module_.getContext(),
                                               "lookup_merge",
                                               parent);

  // Make the verifier happy with a null check even though the value should
  // never be null for key 0.
  Value *condition = CreateICmpNE(
      CreateIntCast(call, getPtrTy(), true),
      ConstantExpr::getCast(Instruction::IntToPtr, getInt64(0), getPtrTy()),
      "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);

  CreateLifetimeEnd(key);

  // createMapLookup  returns an u8*
  auto *cast = CreatePtrToInt(call, getInt64Ty(), "cast");
  CreateStore(getInt64(0), cast);

  CreateBr(merge_block);

  SetInsertPoint(lookup_failure_block);

  CreateRuntimeError(RuntimeErrorId::CPU_COUNT_MISMATCH, loc);
  CreateBr(merge_block);

  SetInsertPoint(merge_block);
}

void IRBuilderBPF::CreateProbeRead(Value *dst,
                                   llvm::Value *size,
                                   Value *src,
                                   AddrSpace as,
                                   const Location &loc)
{
  assert(size && size->getType()->getIntegerBitWidth() <= 32);
  size = CreateIntCast(size, getInt32Ty(), false);

  // int bpf_probe_read(void *dst, int size, void *src)
  // Return: 0 on success or negative error

  auto read_fn = selectProbeReadHelper(as, false);

  FunctionType *proberead_func_type = FunctionType::get(
      getInt64Ty(), { dst->getType(), getInt32Ty(), src->getType() }, false);
  PointerType *proberead_func_ptr_type = PointerType::get(getContext(), 0);
  Constant *proberead_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                   getInt64(read_fn),
                                                   proberead_func_ptr_type);
  CallInst *call = createCall(proberead_func_type,
                              proberead_func,
                              { dst, size, src },
                              probeReadHelperName(read_fn));
  CreateHelperErrorCond(call, read_fn, loc);
}

CallInst *IRBuilderBPF::CreateProbeReadStr(Value *dst,
                                           size_t size,
                                           Value *src,
                                           AddrSpace as,
                                           const Location &loc)
{
  return CreateProbeReadStr(dst, getInt32(size), src, as, loc);
}

CallInst *IRBuilderBPF::CreateProbeReadStr(Value *dst,
                                           llvm::Value *size,
                                           Value *src,
                                           AddrSpace as,
                                           const Location &loc)
{
  assert(size && size->getType()->isIntegerTy());
  if ([[maybe_unused]] auto *dst_alloca = dyn_cast<AllocaInst>(dst)) {
    assert(dst_alloca->getAllocatedType()->isArrayTy() &&
           dst_alloca->getAllocatedType()->getArrayElementType() ==
               getInt8Ty());
  }

  auto *size_i32 = size;
  if (size_i32->getType()->getScalarSizeInBits() != 32)
    size_i32 = CreateIntCast(size_i32, getInt32Ty(), false);

  auto read_fn = selectProbeReadHelper(as, true);
  // int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
  FunctionType *probereadstr_func_type = FunctionType::get(
      getInt64Ty(), { dst->getType(), getInt32Ty(), src->getType() }, false);
  PointerType *probereadstr_func_ptr_type = PointerType::get(getContext(), 0);
  Constant *probereadstr_callee = ConstantExpr::getCast(
      Instruction::IntToPtr, getInt64(read_fn), probereadstr_func_ptr_type);
  CallInst *call = createCall(probereadstr_func_type,
                              probereadstr_callee,
                              { dst, size_i32, src },
                              probeReadHelperName(read_fn));
  CreateHelperErrorCond(call, read_fn, loc);
  return call;
}

Value *IRBuilderBPF::CreateStrncmp(Value *str1,
                                   Value *str2,
                                   uint64_t n,
                                   bool inverse)
{
  // This function compares each character of the two strings. It returns 0
  // if all are equal and 1 if any are different.
  //
  //  strcmp(String val1, String val2)
  //  {
  //     for (size_t i = 0; i < n; i++)
  //     {
  //
  //       if (val1[i] != val2[i])
  //       {
  //         return 1;
  //       }
  //       if (val1[i] == NULL)
  //       {
  //         break;
  //       }
  //     }
  //
  //     return 0;
  //  }

  llvm::Function *parent = GetInsertBlock()->getParent();
  AllocaInst *store = CreateAllocaBPF(getInt64Ty(), "strcmp.result");
  BasicBlock *str_ne = BasicBlock::Create(module_.getContext(),
                                          "strcmp.false",
                                          parent);
  BasicBlock *done = BasicBlock::Create(module_.getContext(),
                                        "strcmp.done",
                                        parent);

  CreateStore(getInt64(inverse ? 0 : 1), store);

  Value *null_byte = getInt8(0);
  for (size_t i = 0; i < n; i++) {
    BasicBlock *char_eq = BasicBlock::Create(module_.getContext(),
                                             "strcmp.loop",
                                             parent);
    BasicBlock *loop_null_check = BasicBlock::Create(module_.getContext(),
                                                     "strcmp.loop_null_cmp",
                                                     parent);

    Value *l;
    auto *ptr_l = CreateGEP(getInt8Ty(), str1, { getInt32(i) });
    l = CreateLoad(getInt8Ty(), ptr_l);

    Value *r;
    auto *ptr_r = CreateGEP(getInt8Ty(), str2, { getInt32(i) });
    r = CreateLoad(getInt8Ty(), ptr_r);

    Value *cmp = CreateICmpNE(l, r, "strcmp.cmp");
    CreateCondBr(cmp, str_ne, loop_null_check);

    SetInsertPoint(loop_null_check);

    Value *cmp_null = CreateICmpEQ(l, null_byte, "strcmp.cmp_null");
    CreateCondBr(cmp_null, done, char_eq);

    SetInsertPoint(char_eq);
  }

  CreateBr(done);
  SetInsertPoint(done);
  CreateStore(getInt64(inverse ? 1 : 0), store);

  CreateBr(str_ne);
  SetInsertPoint(str_ne);

  Value *result = CreateLoad(getInt64Ty(), store);
  CreateLifetimeEnd(store);

  return result;
}

Value *IRBuilderBPF::CreateGetNs(TimestampMode ts, const Location &loc)
{
  // If the BPFTRACE_DUMMY_TS_MAP environment variable is set, generate code
  // that simply reads an unsigned integer from a map instead of generating a
  // call to a BPF time helper. Currently, this is only used by tseries runtime
  // tests. Example:
  //
  // my_script.bt:
  //
  // BEGIN {
  //   @ts = nsecs;
  // }
  //
  // interval:1:ms {
  //   @ = tseries(5, "1ms", 5);
  //   @ts += 1000000; // +1ms
  //   @ = tseries(5, "1ms", 5);
  //   @ts += 1000000; // +1ms
  //   @ = tseries(5, "1ms", 5);
  // }
  //
  // $ BPFTRACE_DUMMY_TS_MAP=@ts bpftrace my_script.bt
  const char *dummy_ts_map_env = std::getenv("BPFTRACE_DUMMY_TS_MAP");

  if (dummy_ts_map_env) {
    std::string dummy_ts_map = dummy_ts_map_env;
    auto map_info = bpftrace_.resources.maps_info.find(dummy_ts_map);
    if (map_info == bpftrace_.resources.maps_info.end()) {
      LOG(BUG) << "dummy_ts_map: \"" << dummy_ts_map << "\" not found";
    } else if (!map_info->second.is_scalar) {
      LOG(BUG) << "dummy_ts_map: \"" << dummy_ts_map << "\" must be scalar";
    } else if (!map_info->second.value_type.IsIntegerTy() ||
               map_info->second.value_type.IsSigned()) {
      LOG(BUG) << "dummy_ts_map: \"" << dummy_ts_map
               << "\" value must must be an unsigned integer";
    } else {
      AllocaInst *key = CreateAllocaBPF(getInt64Ty(), "dummy_ts_map_key");
      CreateStore(getInt64(0), key);

      Value *val = CreateMapLookupElem(
          dummy_ts_map, key, map_info->second.value_type, loc);
      CreateLifetimeEnd(key);
      return val;
    }
  }

  // Random default value to silence compiler warning
  bpf_func_id fn = BPF_FUNC_ktime_get_ns;
  switch (ts) {
    case TimestampMode::monotonic:
      fn = BPF_FUNC_ktime_get_ns;
      break;
    case TimestampMode::boot:
      fn = BPF_FUNC_ktime_get_boot_ns;
      break;
    case TimestampMode::tai:
      fn = BPF_FUNC_ktime_get_tai_ns;
      break;
    case TimestampMode::sw_tai:
      if (!bpftrace_.delta_taitime_.has_value())
        LOG(BUG)
            << "delta_taitime_ should have been checked in an earlier pass";
      uint64_t delta = (bpftrace_.delta_taitime_->tv_sec * 1e9) +
                       bpftrace_.delta_taitime_->tv_nsec;
      Value *ns = CreateGetNs(TimestampMode::boot, loc);
      return CreateAdd(ns, getInt64(delta));
  }

  // u64 ktime_get_*ns()
  // Return: current ktime
  FunctionType *gettime_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(fn, gettime_func_type, {}, false, "get_ns", loc);
}

CallInst *IRBuilderBPF::CreateJiffies64(const Location &loc)
{
  // u64 bpf_jiffies64()
  // Return: jiffies (BITS_PER_LONG == 64) or jiffies_64 (otherwise)
  FunctionType *jiffies64_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(
      BPF_FUNC_jiffies64, jiffies64_func_type, {}, false, "jiffies64", loc);
}

Value *IRBuilderBPF::CreateIntegerArrayCmp(Value *val1,
                                           Value *val2,
                                           const SizedType &val1_type,
                                           const SizedType &val2_type,
                                           const bool inverse,
                                           const Location &loc,
                                           MDNode *metadata)
{
  // This function compares each character of the two arrays.  It returns true
  // if all are equal and false if any are different.
  //
  //  cmp([]char val1, []char val2)
  //  {
  //    for (size_t i = 0; i < n; i++)
  //    {
  //      if (val1[i] != val2[i])
  //      {
  //        return false;
  //      }
  //    }
  //    return true;
  //  }

  auto elem_type = val1_type.GetElementTy();
  const size_t num = val1_type.GetNumElements();

  Value *val1_elem_i, *val2_elem_i, *cmp;
  AllocaInst *v1 = CreateAllocaBPF(elem_type, "v1");
  AllocaInst *v2 = CreateAllocaBPF(elem_type, "v2");
  AllocaInst *store = CreateAllocaBPF(getInt1Ty(), "arraycmp.result");
  CreateStore(getInt1(inverse), store);

  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock *while_cond = BasicBlock::Create(module_.getContext(),
                                              "while_cond",
                                              parent);
  BasicBlock *while_body = BasicBlock::Create(module_.getContext(),
                                              "while_body",
                                              parent);
  BasicBlock *arr_ne = BasicBlock::Create(module_.getContext(),
                                          "arraycmp.false",
                                          parent);
  BasicBlock *done = BasicBlock::Create(module_.getContext(),
                                        "arraycmp.done",
                                        parent);

  Value *ptr_val1 = CreateIntToPtr(val1, getPtrTy());
  Value *ptr_val2 = CreateIntToPtr(val2, getPtrTy());
  AllocaInst *i = CreateAllocaBPF(getInt32Ty(), "i");
  AllocaInst *n = CreateAllocaBPF(getInt32Ty(), "n");
  CreateStore(getInt32(0), i);
  CreateStore(getInt32(num), n);
  CreateBr(while_cond);

  SetInsertPoint(while_cond);
  auto *cond = CreateICmpSLT(CreateLoad(getInt32Ty(), i),
                             CreateLoad(getInt32Ty(), n),
                             "size_check");
  Instruction *loop_hdr = CreateCondBr(cond, while_body, done);
  loop_hdr->setMetadata(LLVMContext::MD_loop, metadata);

  SetInsertPoint(while_body);
  BasicBlock *arr_eq = BasicBlock::Create(module_.getContext(),
                                          "arraycmp.loop",
                                          parent);
  auto *ptr_val1_elem_i = CreateGEP(GetType(val1_type),
                                    ptr_val1,
                                    { getInt32(0),
                                      CreateLoad(getInt32Ty(), i) });
  if (inBpfMemory(val1_type)) {
    val1_elem_i = CreateLoad(GetType(elem_type), ptr_val1_elem_i);
  } else {
    CreateProbeRead(v1,
                    getInt32(elem_type.GetSize()),
                    ptr_val1_elem_i,
                    val1_type.GetAS(),
                    loc);
    val1_elem_i = CreateLoad(GetType(elem_type), v1);
  }

  auto *ptr_val2_elem_i = CreateGEP(GetType(val2_type),
                                    ptr_val2,
                                    { getInt32(0),
                                      CreateLoad(getInt32Ty(), i) });
  if (inBpfMemory(val2_type)) {
    val2_elem_i = CreateLoad(GetType(elem_type), ptr_val2_elem_i);
  } else {
    CreateProbeRead(v2,
                    getInt32(elem_type.GetSize()),
                    ptr_val2_elem_i,
                    val2_type.GetAS(),
                    loc);
    val2_elem_i = CreateLoad(GetType(elem_type), v2);
  }

  cmp = CreateICmpNE(val1_elem_i, val2_elem_i, "arraycmp.cmp");
  CreateCondBr(cmp, arr_ne, arr_eq);

  SetInsertPoint(arr_eq);
  CreateStore(CreateAdd(CreateLoad(getInt32Ty(), i), getInt32(1)), i);
  CreateBr(while_cond);

  SetInsertPoint(arr_ne);
  CreateStore(getInt1(!inverse), store);
  CreateBr(done);

  SetInsertPoint(done);
  Value *result = CreateLoad(getInt1Ty(), store);
  CreateLifetimeEnd(store);
  CreateLifetimeEnd(v1);
  CreateLifetimeEnd(v2);
  result = CreateIntCast(result, getInt64Ty(), false);
  return result;
}

CallInst *IRBuilderBPF::CreateGetPidTgid(const Location &loc)
{
  // u64 bpf_get_current_pid_tgid(void)
  // Return: current->tgid << 32 | current->pid
  FunctionType *getpidtgid_func_type = FunctionType::get(getInt64Ty(), false);
  auto *res = CreateHelperCall(BPF_FUNC_get_current_pid_tgid,
                               getpidtgid_func_type,
                               {},
                               true,
                               "get_pid_tgid",
                               loc);
  return res;
}

void IRBuilderBPF::CreateGetNsPidTgid(Value *dev,
                                      Value *ino,
                                      AllocaInst *ret,
                                      const Location &loc)
{
  // long bpf_get_ns_current_pid_tgid(
  //   u64 dev, u64 ino, struct bpf_pidns_info *nsdata, u32 size)
  // Return: 0 on success
  const auto &layout = module_.getDataLayout();
  auto struct_size = layout.getTypeAllocSize(BpfPidnsInfoType());

  FunctionType *getnspidtgid_func_type = FunctionType::get(getInt64Ty(),
                                                           {
                                                               getInt64Ty(),
                                                               getInt64Ty(),
                                                               getPtrTy(),
                                                               getInt32Ty(),
                                                           },
                                                           false);
  CallInst *call = CreateHelperCall(BPF_FUNC_get_ns_current_pid_tgid,
                                    getnspidtgid_func_type,
                                    { dev, ino, ret, getInt32(struct_size) },
                                    false,
                                    "get_ns_pid_tgid",
                                    loc);
  CreateHelperErrorCond(call, BPF_FUNC_get_ns_current_pid_tgid, loc);
}

llvm::Type *IRBuilderBPF::BpfPidnsInfoType()
{
  return GetStructType("bpf_pidns_info",
                       {
                           getInt32Ty(), // pid   (TID in userspace)
                           getInt32Ty(), // tgid  (PID in userspace)
                       },
                       false);
}

CallInst *IRBuilderBPF::CreateGetCurrentCgroupId(const Location &loc)
{
  // u64 bpf_get_current_cgroup_id(void)
  // Return: 64-bit cgroup-v2 id
  FunctionType *getcgroupid_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(BPF_FUNC_get_current_cgroup_id,
                          getcgroupid_func_type,
                          {},
                          true,
                          "get_cgroup_id",
                          loc);
}

CallInst *IRBuilderBPF::CreateGetUidGid(const Location &loc)
{
  // u64 bpf_get_current_uid_gid(void)
  // Return: current_gid << 32 | current_uid
  FunctionType *getuidgid_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(BPF_FUNC_get_current_uid_gid,
                          getuidgid_func_type,
                          {},
                          true,
                          "get_uid_gid",
                          loc);
}

CallInst *IRBuilderBPF::CreateGetCpuId(const Location &loc)
{
  // u32 bpf_get_smp_processor_id(void)
  // Return: SMP processor ID
  FunctionType *getcpuid_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(BPF_FUNC_get_smp_processor_id,
                          getcpuid_func_type,
                          {},
                          true,
                          "get_cpu_id",
                          loc);
}

CallInst *IRBuilderBPF::CreateGetCurrentTask(const Location &loc)
{
  // u64 bpf_get_current_task(void)
  // Return: current task_struct
  FunctionType *getcurtask_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(BPF_FUNC_get_current_task,
                          getcurtask_func_type,
                          {},
                          true,
                          "get_cur_task",
                          loc);
}

CallInst *IRBuilderBPF::CreateGetRandom(const Location &loc)
{
  // u32 bpf_get_prandom_u32(void)
  // Return: random
  FunctionType *getrandom_func_type = FunctionType::get(getInt32Ty(), false);
  return CreateHelperCall(BPF_FUNC_get_prandom_u32,
                          getrandom_func_type,
                          {},
                          false,
                          "get_random",
                          loc);
}

CallInst *IRBuilderBPF::CreateGetStack(Value *ctx,
                                       Value *buf,
                                       const StackType &stack_type,
                                       const Location &loc)
{
  int flags = 0;
  if (!stack_type.kernel) {
    flags |= (1 << 8);
    if (stack_type.mode == StackMode::build_id) {
      flags |= (1 << 11);
    }
  }
  Value *flags_val = getInt64(flags);
  Value *stack_size = getInt32(stack_type.limit * stack_type.elem_size());

  // long bpf_get_stack(void *ctx, void *buf, u32 size, u64 flags)
  // Return: The non-negative copied *buf* length equal to or less than
  // *size* on success, or a negative error in case of failure.
  FunctionType *getstack_func_type = FunctionType::get(
      getInt64Ty(),
      { getPtrTy(), getPtrTy(), getInt32Ty(), getInt64Ty() },
      false);
  CallInst *call = CreateHelperCall(BPF_FUNC_get_stack,
                                    getstack_func_type,
                                    { ctx, buf, stack_size, flags_val },
                                    false,
                                    "get_stack",
                                    loc);
  CreateHelperErrorCond(call, BPF_FUNC_get_stack, loc);
  return call;
}

CallInst *IRBuilderBPF::CreateGetFuncIp(Value *ctx, const Location &loc)
{
  // u64 bpf_get_func_ip(void *ctx)
  // Return:
  // 		Address of the traced function for kprobe.
  //		0 for kprobes placed within the function (not at the entry).
  //		Address of the probe for uprobe and return uprobe.
  FunctionType *getfuncip_func_type = FunctionType::get(getInt64Ty(),
                                                        { getPtrTy() },
                                                        false);
  return CreateHelperCall(BPF_FUNC_get_func_ip,
                          getfuncip_func_type,
                          { ctx },
                          true,
                          "get_func_ip",
                          loc);
}

CallInst *IRBuilderBPF::CreatePerCpuPtr(Value *var,
                                        Value *cpu,
                                        const Location &loc)
{
  // void *bpf_per_cpu_ptr(const void *percpu_ptr, u32 cpu)
  // Return:
  //    A pointer pointing to the kernel percpu variable on
  //    cpu, or NULL, if cpu is invalid.
  FunctionType *percpuptr_func_type = FunctionType::get(
      getPtrTy(), { getPtrTy(), getInt32Ty() }, false);
  return CreateHelperCall(BPF_FUNC_per_cpu_ptr,
                          percpuptr_func_type,
                          { var, cpu },
                          true,
                          "per_cpu_ptr",
                          loc);
}

CallInst *IRBuilderBPF::CreateThisCpuPtr(Value *var, const Location &loc)
{
  // void *bpf_this_cpu_ptr(const void *percpu_ptr)
  // Return:
  //    A pointer pointing to the kernel percpu variable on
  //    this cpu. May never be NULL.
  FunctionType *percpuptr_func_type = FunctionType::get(getPtrTy(),
                                                        { getPtrTy() },
                                                        false);
  return CreateHelperCall(BPF_FUNC_this_cpu_ptr,
                          percpuptr_func_type,
                          { var },
                          true,
                          "this_cpu_ptr",
                          loc);
}

void IRBuilderBPF::CreateGetCurrentComm(AllocaInst *buf,
                                        size_t size,
                                        const Location &loc)
{
  assert(buf->getAllocatedType()->isArrayTy() &&
         buf->getAllocatedType()->getArrayNumElements() >= size &&
         buf->getAllocatedType()->getArrayElementType() == getInt8Ty());

  // long bpf_get_current_comm(char *buf, int size_of_buf)
  // Return: 0 on success or negative error
  FunctionType *getcomm_func_type = FunctionType::get(
      getInt64Ty(), { buf->getType(), getInt64Ty() }, false);
  CallInst *call = CreateHelperCall(BPF_FUNC_get_current_comm,
                                    getcomm_func_type,
                                    { buf, getInt64(size) },
                                    false,
                                    "get_comm",
                                    loc);
  CreateHelperErrorCond(call, BPF_FUNC_get_current_comm, loc);
}

CallInst *IRBuilderBPF::CreateGetSocketCookie(Value *var, const Location &loc)
{
  // u64 bpf_get_socket_cookie(struct sock *sk)
  // Return:
  //    A 8-byte long unique number or 0 if *sk* is NULL.
  FunctionType *get_socket_cookie_func_type = FunctionType::get(
      getInt64Ty(), { var->getType() }, false);
  return CreateHelperCall(BPF_FUNC_get_socket_cookie,
                          get_socket_cookie_func_type,
                          { var },
                          true,
                          "get_socket_cookie",
                          loc);
}

void IRBuilderBPF::CreateOutput(Value *data, size_t size, const Location &loc)
{
  assert(data && data->getType()->isPointerTy());
  CreateRingbufOutput(data, size, loc);
}

void IRBuilderBPF::CreateRingbufOutput(Value *data,
                                       size_t size,
                                       const Location &loc)
{
  Value *map_ptr = GetMapVar(to_string(MapType::Ringbuf));

  // long bpf_ringbuf_output(void *ringbuf, void *data, u64 size, u64 flags)
  FunctionType *ringbuf_output_func_type = FunctionType::get(
      getInt64Ty(),
      { map_ptr->getType(), data->getType(), getInt64Ty(), getInt64Ty() },
      false);

  Value *ret = CreateHelperCall(BPF_FUNC_ringbuf_output,
                                ringbuf_output_func_type,
                                { map_ptr, data, getInt64(size), getInt64(0) },
                                false,
                                "ringbuf_output",
                                loc);

  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock *loss_block = BasicBlock::Create(module_.getContext(),
                                              "event_loss_counter",
                                              parent);
  BasicBlock *merge_block = BasicBlock::Create(module_.getContext(),
                                               "counter_merge",
                                               parent);
  Value *condition = CreateICmpSLT(ret, getInt64(0), "ringbuf_loss");
  CreateCondBr(condition, loss_block, merge_block);

  SetInsertPoint(loss_block);
  CreateIncEventLossCounter(loc);
  CreateBr(merge_block);

  SetInsertPoint(merge_block);
}

void IRBuilderBPF::CreateIncEventLossCounter(const Location &loc)
{
  auto *value = createScratchBuffer(bpftrace::globalvars::EVENT_LOSS_COUNTER,
                                    loc,
                                    0);
  CreateStore(CreateAdd(CreateLoad(getInt64Ty(), value), getInt64(1)), value);
}

void IRBuilderBPF::CreatePerCpuMapElemInit(Map &map,
                                           Value *key,
                                           Value *val,
                                           const Location &loc)
{
  AllocaInst *initValue = CreateAllocaBPF(val->getType(), "initial_value");
  CreateStore(val, initValue);
  CreateMapUpdateElem(map.ident, key, initValue, loc, BPF_ANY);
  CreateLifetimeEnd(initValue);
}

void IRBuilderBPF::CreatePerCpuMapElemAdd(Map &map,
                                          Value *key,
                                          Value *val,
                                          const Location &loc)
{
  CallInst *call = CreateMapLookup(map, key);

  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_success",
                                                        parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_failure",
                                                        parent);
  BasicBlock *lookup_merge_block = BasicBlock::Create(module_.getContext(),
                                                      "lookup_merge",
                                                      parent);

  AllocaInst *value = CreateAllocaBPF(map.value_type, "lookup_elem_val");
  Value *condition = CreateICmpNE(CreateIntCast(call, getPtrTy(), true),
                                  GetNull(),
                                  "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);

  // createMapLookup  returns an u8*
  auto *cast = CreatePtrToInt(call, value->getType(), "cast");
  CreateStore(CreateAdd(CreateLoad(value->getAllocatedType(), cast), val),
              cast);

  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_failure_block);

  CreatePerCpuMapElemInit(map, key, val, loc);

  CreateBr(lookup_merge_block);
  SetInsertPoint(lookup_merge_block);
  CreateLifetimeEnd(value);
}

void IRBuilderBPF::CreateTracePrintk(Value *fmt_ptr,
                                     Value *fmt_size,
                                     const std::vector<Value *> &values,
                                     const Location &loc)
{
  std::vector<Value *> args = { fmt_ptr, fmt_size };
  for (auto *val : values) {
    args.push_back(val);
  }

  // long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)
  FunctionType *traceprintk_func_type = FunctionType::get(
      getInt64Ty(), { getPtrTy(), getInt32Ty() }, true);

  CreateHelperCall(BPF_FUNC_trace_printk,
                   traceprintk_func_type,
                   args,
                   false,
                   "trace_printk",
                   loc);
}

void IRBuilderBPF::CreateSignal(Value *sig,
                                const Location &loc,
                                bool target_thread)
{
  // target_thread = false: long bpf_send_signal(u32 sig)
  // target_thread = true:  long bpf_send_signal_thread(u32 sig)
  // Return: 0 or error
  FunctionType *signal_func_type = FunctionType::get(getInt64Ty(),
                                                     { getInt32Ty() },
                                                     false);
  PointerType *signal_func_ptr_type = PointerType::get(getContext(), 0);

  auto helper_func_id = BPF_FUNC_send_signal;
  std::string name = "signal";
  if (target_thread) {
    helper_func_id = BPF_FUNC_send_signal_thread;
    name = "signal_thread";
  }

  Constant *signal_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                getInt64(helper_func_id),
                                                signal_func_ptr_type);
  CallInst *call = createCall(signal_func_type, signal_func, { sig }, name);
  CreateHelperErrorCond(call, helper_func_id, loc);
}

CallInst *IRBuilderBPF::CreateSkbOutput(Value *skb,
                                        Value *len,
                                        AllocaInst *data,
                                        size_t size)
{
  Value *flags, *map_ptr, *size_val;

  map_ptr = GetMapVar(to_string(MapType::PerfEvent));

  flags = len;
  flags = CreateShl(flags, 32);
  flags = CreateOr(flags, getInt64(BPF_F_CURRENT_CPU));

  size_val = getInt64(size);

  // long bpf_skb_output(void *skb, struct bpf_map *map, u64 flags,
  //                     void *data, u64 size)
  FunctionType *skb_output_func_type = FunctionType::get(getInt64Ty(),
                                                         { skb->getType(),
                                                           map_ptr->getType(),
                                                           getInt64Ty(),
                                                           data->getType(),
                                                           getInt64Ty() },
                                                         false);

  PointerType *skb_output_func_ptr_type = PointerType::get(getContext(), 0);
  Constant *skb_output_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                    getInt64(
                                                        BPF_FUNC_skb_output),
                                                    skb_output_func_ptr_type);
  CallInst *call = createCall(skb_output_func_type,
                              skb_output_func,
                              { skb, map_ptr, flags, data, size_val },
                              "skb_output");
  return call;
}

Value *IRBuilderBPF::CreateKFuncArg(Value *ctx,
                                    SizedType &type,
                                    std::string &name)
{
  assert(type.IsIntTy() || type.IsPtrTy() || type.IsBoolTy());
  Value *expr = CreateLoad(
      GetType(type),
      CreateSafeGEP(getInt64Ty(), ctx, getInt64(type.funcarg_idx)),
      true, /*volatile*/
      name);
  return expr;
}

Value *IRBuilderBPF::CreateRawTracepointArg(Value *ctx,
                                            const std::string &builtin)
{
  // argX
  int offset = atoi(builtin.substr(3).c_str());
  llvm::Type *type = getInt64Ty();

  // All arguments are coerced into Int64.
  Value *expr = CreateLoad(type,
                           CreateSafeGEP(type, ctx, getInt64(offset)),
                           builtin);

  return expr;
}

Value *IRBuilderBPF::CreateUprobeArgsRecord(Value *ctx,
                                            const SizedType &args_type)
{
  assert(args_type.IsCStructTy());

  auto *args_t = UprobeArgsType(args_type);
  AllocaInst *result = CreateAllocaBPF(args_t, "args");

  for (auto &arg : args_type.GetFields()) {
    assert(arg.type.is_funcarg);
    Value *arg_read = CreateRegisterRead(
        ctx, "arg" + std::to_string(arg.type.funcarg_idx));
    if (arg.type.GetSize() != 8)
      arg_read = CreateTrunc(arg_read, GetType(arg.type));
    CreateStore(arg_read,
                CreateGEP(args_t,
                          result,
                          { getInt64(0), getInt32(arg.type.funcarg_idx) }));
  }
  return result;
}

llvm::Type *IRBuilderBPF::UprobeArgsType(const SizedType &args_type)
{
  auto type_name = args_type.GetName();
  type_name.erase(0, strlen("struct "));

  std::vector<llvm::Type *> arg_types;
  for (auto &arg : args_type.GetFields())
    arg_types.push_back(GetType(arg.type));
  return GetStructType(type_name, arg_types, false);
}

Value *IRBuilderBPF::CreateRegisterRead(Value *ctx, const std::string &builtin)
{
  std::optional<std::string> reg;
  if (builtin == "__builtin_retval") {
    reg = arch::Host::return_value();
  } else if (builtin == "__builtin_func") {
    reg = arch::Host::pc_value();
  } else if (builtin.starts_with("arg")) {
    size_t n = static_cast<size_t>(atoi(builtin.substr(3).c_str()));
    const auto &arguments = arch::Host::arguments();
    if (n < arguments.size()) {
      reg = arguments[n];
    }
  }
  if (!reg.has_value()) {
    LOG(BUG) << "unknown builtin: " << builtin;
    __builtin_unreachable();
  }

  auto offset = arch::Host::register_to_pt_regs_offset(reg.value());
  if (!offset.has_value()) {
    LOG(BUG) << "invalid register `" << reg.value()
             << " for builtin: " << builtin;
    __builtin_unreachable();
  }

  return CreateRegisterRead(ctx, offset.value(), builtin);
}

Value *IRBuilderBPF::CreateRegisterRead(Value *ctx,
                                        size_t offset,
                                        const std::string &name)
{
  // Bitwidth of register values in struct pt_regs is the same as the kernel
  // pointer width on all supported architectures.
  //
  // FIXME(#3873): Not clear if this applies as a general rule, best to allow
  // these to be resolved via field names and BTF directly in the future.
  llvm::Type *registerTy = getPointerStorageTy();

  Value *result = CreateLoad(registerTy,
                             CreateSafeGEP(getInt8Ty(), ctx, getInt64(offset)),
                             true, /*volatile*/
                             name);
  return result;
}

static bool return_zero_if_err(bpf_func_id func_id)
{
  switch (func_id) {
    // When these function fails, bpftrace stores zero as a result.
    // A user script can check an error by seeing the value.
    // Therefore error checks of these functions are omitted if
    // warning_level == 1.
    case BPF_FUNC_probe_read:
    case BPF_FUNC_probe_read_str:
    case BPF_FUNC_probe_read_kernel:
    case BPF_FUNC_probe_read_kernel_str:
    case BPF_FUNC_probe_read_user:
    case BPF_FUNC_probe_read_user_str:
    case BPF_FUNC_map_lookup_elem:
      return true;
    default:
      return false;
  }
  return false;
}

void IRBuilderBPF::CreateRuntimeError(RuntimeErrorId rte_id,
                                      const Location &loc)
{
  CreateRuntimeError(rte_id, getInt64(0), __BPF_FUNC_MAX_ID, loc);
}

void IRBuilderBPF::CreateRuntimeError(RuntimeErrorId rte_id,
                                      Value *return_value,
                                      bpf_func_id func_id,
                                      const Location &loc)
{
  if (rte_id == RuntimeErrorId::HELPER_ERROR) {
    assert(return_value && return_value->getType() == getInt32Ty());

    if (bpftrace_.warning_level_ == 0 ||
        (bpftrace_.warning_level_ == 1 && return_zero_if_err(func_id)))
      return;
  }

  int error_id = async_ids_.runtime_error();
  bpftrace_.resources.runtime_error_info.try_emplace(
      error_id, RuntimeErrorInfo(rte_id, func_id, loc));
  auto elements = AsyncEvent::RuntimeError().asLLVMType(*this);
  StructType *runtime_error_struct = GetStructType("runtime_error_t",
                                                   elements,
                                                   true);
  AllocaInst *buf = CreateAllocaBPF(runtime_error_struct, "runtime_error_t");
  CreateStore(
      GetIntSameSize(static_cast<int64_t>(
                         async_action::AsyncAction::runtime_error),
                     elements.at(0)),
      CreateGEP(runtime_error_struct, buf, { getInt64(0), getInt32(0) }));
  CreateStore(
      GetIntSameSize(error_id, elements.at(1)),
      CreateGEP(runtime_error_struct, buf, { getInt64(0), getInt32(1) }));
  CreateStore(
      return_value,
      CreateGEP(runtime_error_struct, buf, { getInt64(0), getInt32(2) }));

  const auto &layout = module_.getDataLayout();
  auto struct_size = layout.getTypeAllocSize(runtime_error_struct);
  CreateOutput(buf, struct_size, loc);
  CreateLifetimeEnd(buf);
}

void IRBuilderBPF::CreateHelperErrorCond(Value *return_value,
                                         bpf_func_id func_id,
                                         const Location &loc)
{
  if (bpftrace_.warning_level_ == 0 ||
      (bpftrace_.warning_level_ == 1 && return_zero_if_err(func_id)))
    return;

  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock *helper_failure_block = BasicBlock::Create(module_.getContext(),
                                                        "helper_failure",
                                                        parent);
  BasicBlock *helper_merge_block = BasicBlock::Create(module_.getContext(),
                                                      "helper_merge",
                                                      parent);
  // A return type of most helper functions are Int64Ty but they actually
  // return int and we need to use Int32Ty value to check if a return
  // value is negative. TODO: use Int32Ty as a return type
  auto *ret = CreateIntCast(return_value, getInt32Ty(), true);
  Value *condition = CreateICmpSGE(ret, Constant::getNullValue(ret->getType()));
  CreateCondBr(condition, helper_merge_block, helper_failure_block);
  SetInsertPoint(helper_failure_block);
  CreateRuntimeError(RuntimeErrorId::HELPER_ERROR, ret, func_id, loc);
  CreateBr(helper_merge_block);
  SetInsertPoint(helper_merge_block);
}

void IRBuilderBPF::CreatePath(Value *buf,
                              Value *path,
                              Value *sz,
                              const Location &loc)
{
  // int bpf_d_path(struct path *path, char *buf, u32 sz)
  // Return: 0 or error
  FunctionType *d_path_func_type = FunctionType::get(
      getInt64Ty(), { getPtrTy(), buf->getType(), getInt32Ty() }, false);
  CallInst *call = CreateHelperCall(bpf_func_id::BPF_FUNC_d_path,
                                    d_path_func_type,
                                    { path, buf, sz },
                                    false,
                                    "d_path",
                                    loc);
  CreateHelperErrorCond(call, BPF_FUNC_d_path, loc);
}

void IRBuilderBPF::CreateSeqPrintf(Value *ctx,
                                   Value *fmt,
                                   Value *fmt_size,
                                   Value *data,
                                   Value *data_len,
                                   const Location &loc)
{
  // long bpf_seq_printf(struct seq_file *m, const char *fmt, __u32 fmt_size,
  //                     const void *data, __u32 data_len)
  // Return: 0 or error
  FunctionType *seq_printf_func_type = FunctionType::get(
      getInt64Ty(),
      { getInt64Ty(), getPtrTy(), getInt32Ty(), getPtrTy(), getInt32Ty() },
      false);
  PointerType *seq_printf_func_ptr_type = PointerType::get(getContext(), 0);
  Constant *seq_printf_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                    getInt64(
                                                        BPF_FUNC_seq_printf),
                                                    seq_printf_func_ptr_type);

  LoadInst *meta = CreateLoad(getPtrTy(),
                              CreateSafeGEP(getInt64Ty(), ctx, getInt64(0)),
                              "meta");
  meta->setVolatile(true);

  Value *seq = CreateLoad(getInt64Ty(),
                          CreateGEP(getInt64Ty(), meta, getInt64(0)),
                          "seq");

  CallInst *call = createCall(seq_printf_func_type,
                              seq_printf_func,
                              { seq, fmt, fmt_size, data, data_len },
                              "seq_printf");
  CreateHelperErrorCond(call, BPF_FUNC_seq_printf, loc);
}

StoreInst *IRBuilderBPF::createAlignedStore(Value *val,
                                            Value *ptr,
                                            unsigned int align)
{
  return CreateAlignedStore(val, ptr, MaybeAlign(align));
}

void IRBuilderBPF::CreateProbeRead(Value *dst,
                                   const SizedType &type,
                                   Value *src,
                                   const Location &loc,
                                   std::optional<AddrSpace> addrSpace)
{
  AddrSpace as = addrSpace ? addrSpace.value() : type.GetAS();

  if (!type.IsPtrTy()) {
    CreateProbeRead(dst, getInt32(type.GetSize()), src, as, loc);
    return;
  }

  // Pointers are internally always represented as 64-bit integers, matching the
  // BPF register size (BPF is a 64-bit ISA). This helps to avoid BPF codegen
  // issues such as truncating PTR_TO_STACK registers using shift operations,
  // which is disallowed (see https://github.com/bpftrace/bpftrace/pull/2361).
  // However, when reading pointers from kernel or user memory, we need to use
  // the appropriate size for the target system.
  const size_t ptr_size = getPointerStorageTy()->getIntegerBitWidth() / 8;

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  // TODO: support 32-bit big-endian systems
  assert(ptr_size == type.GetSize());
#endif

  if (ptr_size != type.GetSize())
    CreateMemsetBPF(dst, getInt8(0), type.GetSize());

  CreateProbeRead(dst, getInt32(ptr_size), src, as, loc);
}

llvm::Value *IRBuilderBPF::CreateDatastructElemLoad(const SizedType &type,
                                                    llvm::Value *ptr)
{
  llvm::Type *ptr_storage_ty = getPointerStorageTy();

  if (!type.IsPtrTy() || ptr_storage_ty == getInt64Ty())
    return CreateLoad(GetType(type), ptr, true /*volatile*/);

  assert(GetType(type) == getInt64Ty());

  // Pointer size for the given address space doesn't match the BPF-side
  // representation. Use ptr_storage_ty as the load type and cast the result
  // back to int64.
  llvm::Value *expr = CreateLoad(ptr_storage_ty, ptr, true /*volatile*/);

  return CreateIntCast(expr, getInt64Ty(), false);
}

llvm::Value *IRBuilderBPF::CreatePtrOffset(const SizedType &type,
                                           llvm::Value *index)
{
  size_t elem_size = type.IsPtrTy()
                         ? getPointerStorageTy()->getIntegerBitWidth() / 8
                         : type.GetSize();

  return CreateMul(index, getInt64(elem_size));
}

llvm::Value *IRBuilderBPF::CreateSafeGEP(llvm::Type *ty,
                                         llvm::Value *ptr,
                                         llvm::ArrayRef<Value *> offsets,
                                         const llvm::Twine &name)
{
  if (!ptr->getType()->isPointerTy()) {
    assert(ptr->getType()->isIntegerTy());
    ptr = CreateIntToPtr(ptr, getPtrTy());
  }

#if LLVM_VERSION_MAJOR >= 18
  if (!preserve_static_offset_) {
#if LLVM_VERSION_MAJOR >= 20
    preserve_static_offset_ = llvm::Intrinsic::getOrInsertDeclaration(
        &module_, llvm::Intrinsic::preserve_static_offset);
#else
    preserve_static_offset_ = llvm::Intrinsic::getDeclaration(
        &module_, llvm::Intrinsic::preserve_static_offset);
#endif
  }
  ptr = CreateCall(preserve_static_offset_, ptr);
#endif

  // Create the GEP itself; on newer versions of LLVM this coerces the pointer
  // value into a pointer to the given type, and older versions have guaranteed
  // a suitable cast above (first from integer, then to the right pointer).
  return CreateGEP(ty, ptr, offsets, name);
}

llvm::Type *IRBuilderBPF::getPointerStorageTy()
{
  static int ptr_width = arch::Host::kernel_ptr_width();
  return getIntNTy(ptr_width);
}

void IRBuilderBPF::CreateMinMax(Value *val,
                                Value *val_ptr,
                                Value *is_set_ptr,
                                bool max,
                                bool is_signed)
{
  llvm::Function *parent = GetInsertBlock()->getParent();

  BasicBlock *is_set_block = BasicBlock::Create(module_.getContext(),
                                                "is_set",
                                                parent);
  BasicBlock *min_max_block = BasicBlock::Create(module_.getContext(),
                                                 "min_max",
                                                 parent);
  BasicBlock *merge_block = BasicBlock::Create(module_.getContext(),
                                               "merge",
                                               parent);

  Value *curr = CreateLoad(getInt64Ty(), val_ptr);
  Value *is_set_condition = CreateICmpEQ(CreateLoad(getInt64Ty(), is_set_ptr),
                                         getInt64(1),
                                         "is_set_cond");

  CreateCondBr(is_set_condition, is_set_block, min_max_block);

  SetInsertPoint(is_set_block);

  Value *min_max_condition;

  if (max) {
    min_max_condition = is_signed ? CreateICmpSGE(val, curr)
                                  : CreateICmpUGE(val, curr);
  } else {
    min_max_condition = is_signed ? CreateICmpSGE(curr, val)
                                  : CreateICmpUGE(curr, val);
  }

  CreateCondBr(min_max_condition, min_max_block, merge_block);

  SetInsertPoint(min_max_block);

  CreateStore(val, val_ptr);

  CreateStore(getInt64(1), is_set_ptr);

  CreateBr(merge_block);

  SetInsertPoint(merge_block);
}

llvm::Value *IRBuilderBPF::CreateCheckedBinop(Binop &binop,
                                              Value *lhs,
                                              Value *rhs)
{
  assert(binop.op == Operator::DIV || binop.op == Operator::MOD);
  // We need to do an explicit 0 check or else a Clang compiler optimization
  // will assume that the value can't ever be 0, as this is undefined behavior,
  // and remove a conditional null check for map values which will return 0 if
  // the map value is null (this happens in CreateMapLookupElem). This would be
  // fine but the BPF verifier will complain about the lack of a null check.
  // Issue: https://github.com/bpftrace/bpftrace/issues/4379
  // From Google's AI: "LLVM, like other optimizing compilers, is allowed to
  // make assumptions based on the absence of undefined behavior. If a program's
  // code, after optimization, would result in undefined behavior (like division
  // by zero by CreateURem), the compiler is free to make transformations that
  // assume such a situation will never occur."
  AllocaInst *op_result = CreateAllocaBPF(getInt64Ty(), "op_result");

  llvm::Function *parent = GetInsertBlock()->getParent();
  BasicBlock *is_zero = BasicBlock::Create(module_.getContext(),
                                           "is_zero",
                                           parent);
  BasicBlock *not_zero = BasicBlock::Create(module_.getContext(),
                                            "not_zero",
                                            parent);
  BasicBlock *zero_merge = BasicBlock::Create(module_.getContext(),
                                              "zero_merge",
                                              parent);

  Value *cond = CreateICmpEQ(rhs, getInt64(0), "zero_cond");

  CreateCondBr(cond, is_zero, not_zero);
  SetInsertPoint(is_zero);
  CreateStore(getInt64(1), op_result);
  CreateRuntimeError(RuntimeErrorId::DIVIDE_BY_ZERO, binop.loc);
  CreateBr(zero_merge);

  SetInsertPoint(not_zero);
  if (binop.op == Operator::MOD) {
    CreateStore(CreateURem(lhs, rhs), op_result);
  } else if (binop.op == Operator::DIV) {
    CreateStore(CreateUDiv(lhs, rhs), op_result);
  }

  CreateBr(zero_merge);

  SetInsertPoint(zero_merge);
  auto *result = CreateLoad(getInt64Ty(), op_result);
  CreateLifetimeEnd(op_result);
  return result;
}

bool IRBuilderBPF::HasTerminator()
{
  BasicBlock *current_block = GetInsertBlock();
  return current_block && current_block->getTerminator();
}

} // namespace bpftrace::ast
