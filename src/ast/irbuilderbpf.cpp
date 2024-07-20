#include "ast/irbuilderbpf.h"

#include <iostream>
#include <sstream>
#include <thread>

#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Module.h>

#include "arch/arch.h"
#include "ast/async_event_types.h"
#include "ast/codegen_helper.h"
#include "bpfmap.h"
#include "bpftrace.h"
#include "globalvars.h"
#include "log.h"
#include "utils.h"

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {
namespace ast {

namespace {
std::string probeReadHelperName(libbpf::bpf_func_id id)
{
  switch (id) {
    case libbpf::BPF_FUNC_probe_read:
      return "probe_read";
    case libbpf::BPF_FUNC_probe_read_user:
      return "probe_read_user";
    case libbpf::BPF_FUNC_probe_read_kernel:
      return "probe_read_kernel";
    case libbpf::BPF_FUNC_probe_read_str:
      return "probe_read_str";
    case libbpf::BPF_FUNC_probe_read_user_str:
      return "probe_read_user_str";
    case libbpf::BPF_FUNC_probe_read_kernel_str:
      return "probe_read_kernel_str";
    default:
      LOG(BUG) << "unknown probe_read id: " << std::to_string(id);
  }
}
} // namespace

libbpf::bpf_func_id IRBuilderBPF::selectProbeReadHelper(AddrSpace as, bool str)
{
  libbpf::bpf_func_id fn;
  // Assume that if a kernel has probe_read_kernel it has the other 3 too
  if (bpftrace_.feature_->has_helper_probe_read_kernel()) {
    if (as == AddrSpace::kernel) {
      fn = str ? libbpf::BPF_FUNC_probe_read_kernel_str
               : libbpf::BPF_FUNC_probe_read_kernel;
    } else if (as == AddrSpace::user) {
      fn = str ? libbpf::BPF_FUNC_probe_read_user_str
               : libbpf::BPF_FUNC_probe_read_user;
    } else {
      // if the kernel has the new helpers but AS is still none it is a bug
      // in bpftrace, assert catches it for debug builds.
      // assert(as != AddrSpace::none);
      static bool warnonce = false;
      if (!warnonce) {
        warnonce = true;
        LOG(WARNING) << "Addrspace is not set";
      }
      fn = str ? libbpf::BPF_FUNC_probe_read_str : libbpf::BPF_FUNC_probe_read;
    }
  } else {
    fn = str ? libbpf::BPF_FUNC_probe_read_str : libbpf::BPF_FUNC_probe_read;
  }

  return fn;
}

AllocaInst *IRBuilderBPF::CreateUSym(llvm::Value *val,
                                     int probe_id,
                                     const location &loc)
{
  std::vector<llvm::Type *> elements = {
    getInt64Ty(), // addr
    getInt64Ty(), // pid
    getInt64Ty(), // probe id
  };
  StructType *usym_t = GetStructType("usym_t", elements, false);
  AllocaInst *buf = CreateAllocaBPF(usym_t, "usym");

  Value *pid = CreateLShr(CreateGetPidTgid(loc), 32);
  Value *probe_id_val = Constant::getIntegerValue(getInt64Ty(),
                                                  APInt(64, probe_id));

  // The extra 0 here ensures the type of addr_offset will be int64
  Value *addr_offset = CreateGEP(usym_t, buf, { getInt64(0), getInt32(0) });
  Value *pid_offset = CreateGEP(usym_t, buf, { getInt64(0), getInt32(1) });
  Value *probeid_offset = CreateGEP(usym_t, buf, { getInt64(0), getInt32(2) });

  CreateStore(val, addr_offset);
  CreateStore(pid, pid_offset);
  CreateStore(probe_id_val, probeid_offset);
  return buf;
}

StructType *IRBuilderBPF::GetStructType(
    std::string name,
    const std::vector<llvm::Type *> &elements,
    bool packed)
{
  auto search = structs_.find(name);
  if (search != structs_.end())
    return search->second;

  StructType *s = StructType::create(elements, name, packed);
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
  Function::Create(pseudo_func_type,
                   GlobalValue::ExternalLinkage,
                   "llvm.bpf.pseudo",
                   &module_);
}

void IRBuilderBPF::hoist(const std::function<void()> &functor)
{
  Function *parent = GetInsertBlock()->getParent();
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
                                          llvm::Value *arraysize,
                                          const std::string &name)
{
  AllocaInst *alloca;
  hoist([this, ty, arraysize, &name, &alloca]() {
    alloca = CreateAlloca(ty, arraysize, name);
  });

  CreateLifetimeStart(alloca);
  return alloca;
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(llvm::Type *ty,
                                          const std::string &name)
{
  return CreateAllocaBPF(ty, nullptr, name);
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(const SizedType &stype,
                                          const std::string &name)
{
  llvm::Type *ty = GetType(stype);
  return CreateAllocaBPF(ty, nullptr, name);
}

AllocaInst *IRBuilderBPF::CreateAllocaBPFInit(const SizedType &stype,
                                              const std::string &name)
{
  AllocaInst *alloca;
  hoist([this, &stype, &name, &alloca]() {
    llvm::Type *ty = GetType(stype);
    alloca = CreateAlloca(ty, nullptr, name);
    CreateLifetimeStart(alloca);
    if (needMemcpy(stype)) {
      CreateMemsetBPF(alloca, getInt8(0), stype.GetSize());
    } else {
      CreateStore(ConstantInt::get(ty, 0), alloca);
    }
  });
  return alloca;
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(const SizedType &stype,
                                          llvm::Value *arraysize,
                                          const std::string &name)
{
  llvm::Type *ty = GetType(stype);
  return CreateAllocaBPF(ty, arraysize, name);
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(int bytes, const std::string &name)
{
  llvm::Type *ty = ArrayType::get(getInt8Ty(), bytes);
  return CreateAllocaBPF(ty, name);
}

void IRBuilderBPF::CreateMemsetBPF(Value *ptr, Value *val, uint32_t size)
{
  if (size > 512 && bpftrace_.feature_->has_helper_probe_read_kernel()) {
    // Note we are "abusing" bpf_probe_read_kernel() by reading from NULL
    // which triggers a call into the kernel-optimized memset().
    //
    // Upstream blesses this trick so we should be able to count on them
    // to maintain these semantics.
    //
    // Also note we are avoiding a call to CreateProbeRead(), as it wraps
    // calls to probe read helpers with the -kk error reporting feature.
    // The call here will always fail and we want it that way. So avoid
    // reporting errors to the user.
    auto probe_read_id = libbpf::BPF_FUNC_probe_read_kernel;
    FunctionType *proberead_func_type = FunctionType::get(
        getInt64Ty(),
        { ptr->getType(), getInt32Ty(), GetNull()->getType() },
        false);
    PointerType *proberead_func_ptr_type = PointerType::get(proberead_func_type,
                                                            0);
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

llvm::Type *IRBuilderBPF::GetType(const SizedType &stype)
{
  llvm::Type *ty;
  if (stype.IsByteArray() || stype.IsRecordTy()) {
    ty = ArrayType::get(getInt8Ty(), stype.GetSize());
  } else if (stype.IsArrayTy()) {
    ty = ArrayType::get(GetType(*stype.GetElementTy()), stype.GetNumElements());
  } else if (stype.IsTupleTy()) {
    std::vector<llvm::Type *> llvm_elems;
    std::ostringstream ty_name;

    for (const auto &elem : stype.GetFields()) {
      auto &elemtype = elem.type;
      llvm_elems.emplace_back(GetType(elemtype));
      ty_name << elemtype << "_";
    }
    ty_name << "_tuple_t";

    ty = GetStructType(ty_name.str(), llvm_elems, false);
  } else if (stype.IsPtrTy()) {
    ty = getInt64Ty();
  } else if (stype.IsVoidTy()) {
    ty = getVoidTy();
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
  } else {
    ty = GetType(stype);
  }

  return ty;
}

CallInst *IRBuilderBPF::CreateHelperCall(libbpf::bpf_func_id func_id,
                                         FunctionType *helper_type,
                                         ArrayRef<Value *> args,
                                         const Twine &Name,
                                         const location *loc)
{
  if (loc && bpftrace_.helper_use_loc_.find(func_id) ==
                 bpftrace_.helper_use_loc_.end())
    bpftrace_.helper_use_loc_[func_id] = *loc;
  PointerType *helper_ptr_type = PointerType::get(helper_type, 0);
  Constant *helper_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                getInt64(func_id),
                                                helper_ptr_type);
  return createCall(helper_type, helper_func, args, Name);
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
  return ConstantExpr::getCast(Instruction::IntToPtr,
                               getInt64(0),
                               GET_PTR_TY());
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
  return createMapLookup(map_name, key, GET_PTR_TY(), name);
}

CallInst *IRBuilderBPF::createMapLookup(const std::string &map_name,
                                        Value *key,
                                        PointerType *val_ptr_ty,
                                        const std::string &name)
{
  Value *map_ptr = GetMapVar(map_name);
  // void *map_lookup_elem(struct bpf_map * map, void * key)
  // Return: Map value or NULL

  assert(key->getType()->isPointerTy());
  FunctionType *lookup_func_type = FunctionType::get(
      val_ptr_ty, { map_ptr->getType(), key->getType() }, false);
  PointerType *lookup_func_ptr_type = PointerType::get(lookup_func_type, 0);
  Constant *lookup_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_map_lookup_elem),
      lookup_func_ptr_type);
  return createCall(lookup_func_type, lookup_func, { map_ptr, key }, name);
}

CallInst *IRBuilderBPF::createPerCpuMapLookup(const std::string &map_name,
                                              Value *key,
                                              Value *cpu,
                                              const std::string &name)
{
  return createPerCpuMapLookup(map_name, key, cpu, GET_PTR_TY(), name);
}

CallInst *IRBuilderBPF::createPerCpuMapLookup(const std::string &map_name,
                                              Value *key,
                                              Value *cpu,
                                              PointerType *val_ptr_ty,
                                              const std::string &name)
{
  Value *map_ptr = GetMapVar(map_name);
  // void *map_lookup_percpu_elem(struct bpf_map * map, void * key, u32 cpu)
  // Return: Map value or NULL

  assert(key->getType()->isPointerTy());
  FunctionType *lookup_func_type = FunctionType::get(
      val_ptr_ty, { map_ptr->getType(), key->getType(), getInt32Ty() }, false);
  PointerType *lookup_func_ptr_type = PointerType::get(lookup_func_type, 0);
  Constant *lookup_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_map_lookup_percpu_elem),
      lookup_func_ptr_type);
  return createCall(lookup_func_type, lookup_func, { map_ptr, key, cpu }, name);
}

CallInst *IRBuilderBPF::CreateGetJoinMap(BasicBlock *failure_callback,
                                         const location &loc)
{
  return createGetScratchMap(
      to_string(MapType::Join), "join", GET_PTR_TY(), loc, failure_callback);
}

CallInst *IRBuilderBPF::CreateGetStackScratchMap(StackType stack_type,
                                                 BasicBlock *failure_callback,
                                                 const location &loc)
{
  SizedType value_type = CreateArray(stack_type.limit, CreateUInt64());
  return createGetScratchMap(StackType::scratch_name(),
                             StackType::scratch_name(),
                             GetType(value_type)->getPointerTo(),
                             loc,
                             failure_callback);
}

CallInst *IRBuilderBPF::CreateGetStrScratchMap(int idx,
                                               BasicBlock *failure_callback,
                                               const location &loc)
{
  return createGetScratchMap(to_string(MapType::StrBuffer),
                             "str",
                             GET_PTR_TY(),
                             loc,
                             failure_callback,
                             idx);
}

/*
 * Failure to lookup a scratch map will result in a jump to the
 * failure_callback, if non-null.
 *
 * In practice, a properly constructed percpu lookup will never fail. The only
 * way it can fail is if we have a bug in our code. So a null failure_callback
 * simply causes a blind 0 return. See comment in function for why this is ok.
 */
CallInst *IRBuilderBPF::createGetScratchMap(const std::string &map_name,
                                            const std::string &name,
                                            PointerType *val_ptr_ty,
                                            const location &loc,
                                            BasicBlock *failure_callback,
                                            int key)
{
  AllocaInst *keyAlloc = CreateAllocaBPF(getInt32Ty(),
                                         nullptr,
                                         "lookup_" + name + "_key");
  CreateStore(getInt32(key), keyAlloc);

  CallInst *call = createMapLookup(
      map_name, keyAlloc, val_ptr_ty, "lookup_" + name + "_map");
  CreateLifetimeEnd(keyAlloc);

  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_failure_block = BasicBlock::Create(
      module_.getContext(), "lookup_" + name + "_failure", parent);
  BasicBlock *lookup_merge_block = BasicBlock::Create(
      module_.getContext(), "lookup_" + name + "_merge", parent);
  Value *condition = CreateICmpNE(CreateIntCast(call, GET_PTR_TY(), true),
                                  GetNull(),
                                  "lookup_" + name + "_cond");
  CreateCondBr(condition, lookup_merge_block, lookup_failure_block);

  SetInsertPoint(lookup_failure_block);
  CreateDebugOutput("unable to find the scratch map value for " + name,
                    std::vector<Value *>{},
                    loc);
  if (failure_callback) {
    CreateBr(failure_callback);
  } else {
    /*
     * Think of this like an assert(). In practice, we cannot fail to lookup a
     * percpu array map unless we have a coding error. Rather than have some
     * kind of complicated fallback path where we provide an error string for
     * our caller, just indicate to verifier we want to terminate execution.
     *
     * Note that we blindly return 0 in contrast to the logic inside
     * CodegenLLVM::createRet(). That's b/c the return value doesn't matter
     * if it'll never get executed.
     */
    CreateRet(getInt64(0));
  }

  SetInsertPoint(lookup_merge_block);
  return call;
}

Value *IRBuilderBPF::CreateMapLookupElem(Value *ctx,
                                         Map &map,
                                         Value *key,
                                         const location &loc)
{
  assert(ctx && ctx->getType() == GET_PTR_TY());
  return CreateMapLookupElem(ctx, map.ident, key, map.type, loc);
}

Value *IRBuilderBPF::CreateMapLookupElem(Value *ctx,
                                         const std::string &map_name,
                                         Value *key,
                                         SizedType &type,
                                         const location &loc)
{
  assert(ctx && ctx->getType() == GET_PTR_TY());
  CallInst *call = createMapLookup(map_name, key);

  // Check if result == 0
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_success",
                                                        parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_failure",
                                                        parent);
  BasicBlock *lookup_merge_block = BasicBlock::Create(module_.getContext(),
                                                      "lookup_merge",
                                                      parent);

  AllocaInst *value = CreateAllocaBPF(type, "lookup_elem_val");
  Value *condition = CreateICmpNE(CreateIntCast(call, GET_PTR_TY(), true),
                                  GetNull(),
                                  "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);
  if (needMemcpy(type))
    CREATE_MEMCPY(value, call, type.GetSize(), 1);
  else {
    assert(value->getAllocatedType() == getInt64Ty());
    // createMapLookup  returns an u8*
    auto *cast = CreatePointerCast(call, value->getType(), "cast");
    CreateStore(CreateLoad(getInt64Ty(), cast), value);
  }
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_failure_block);
  if (needMemcpy(type))
    CreateMemsetBPF(value, getInt8(0), type.GetSize());
  else
    CreateStore(getInt64(0), value);
  CreateHelperError(ctx, getInt32(0), libbpf::BPF_FUNC_map_lookup_elem, loc);
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_merge_block);
  if (needMemcpy(type))
    return value;

  // value is a pointer to i64
  Value *ret = CreateLoad(getInt64Ty(), value);
  CreateLifetimeEnd(value);
  return ret;
}

Value *IRBuilderBPF::CreatePerCpuMapAggElems(Value *ctx,
                                             Map &map,
                                             Value *key,
                                             const SizedType &type,
                                             const location &loc)
{
  /*
   * int ret = 0;
   * int i = 0;
   * while (i < nr_cpus) {
   *   int * cpu_value = map_lookup_percpu_elem(map, key, i);
   *   if (cpu_value == NULL) {
   *     if (i == 0)
   *        log_error("Key not found")
   *     else
   *        debug("No cpu found for cpu id: %lu", i) // Mostly for AOT
   *     break;
   *   }
   *   // update ret for sum, count, avg, min, max
   *   i++;
   * }
   * return ret;
   */

  assert(ctx && ctx->getType() == GET_PTR_TY());

  const std::string &map_name = map.ident;

  AllocaInst *i = CreateAllocaBPF(getInt32Ty(), "i");
  AllocaInst *val_1 = CreateAllocaBPF(getInt64Ty(), "val_1");
  // used for min/max/avg
  AllocaInst *val_2 = CreateAllocaBPF(getInt64Ty(), "val_2");

  CreateStore(getInt32(0), i);
  CreateStore(getInt64(0), val_1);
  CreateStore(getInt64(0), val_2);

  Function *parent = GetInsertBlock()->getParent();
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
                                     module_.getGlobalVariable(
                                         bpftrace::globalvars::NUM_CPUS)),
                          "num_cpu.cmp");
  CreateCondBr(cond, while_body, while_end);

  SetInsertPoint(while_body);

  CallInst *call = createPerCpuMapLookup(map_name,
                                         key,
                                         CreateLoad(getInt32Ty(), i));

  Function *lookup_parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_success",
                                                        lookup_parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_failure",
                                                        lookup_parent);
  Value *condition = CreateICmpNE(CreateIntCast(call, GET_PTR_TY(), true),
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

  Function *error_parent = GetInsertBlock()->getParent();
  BasicBlock *error_success_block = BasicBlock::Create(module_.getContext(),
                                                       "error_success",
                                                       error_parent);
  BasicBlock *error_failure_block = BasicBlock::Create(module_.getContext(),
                                                       "error_failure",
                                                       error_parent);

  // If the CPU is 0 and the map lookup fails it means the key doesn't exist
  Value *error_condition = CreateICmpEQ(CreateLoad(getInt32Ty(), i),
                                        getInt32(0),
                                        "error_lookup_cond");
  CreateCondBr(error_condition, error_success_block, error_failure_block);

  SetInsertPoint(error_success_block);

  CreateHelperError(
      ctx, getInt32(0), libbpf::BPF_FUNC_map_lookup_percpu_elem, loc);
  CreateBr(while_end);

  SetInsertPoint(error_failure_block);

  // This should only get triggered in the AOT case
  CreateDebugOutput("No cpu found for cpu id: %lu",
                    std::vector<Value *>{ CreateLoad(getInt32Ty(), i) },
                    loc);

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
      Function *avg_parent = GetInsertBlock()->getParent();
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
  auto *cast = CreatePointerCast(call, GetType(type)->getPointerTo(), "cast");
  CreateStore(CreateAdd(CreateLoad(GetType(type), cast),
                        CreateLoad(getInt64Ty(), ret)),
              ret);
}

void IRBuilderBPF::createPerCpuMinMax(AllocaInst *ret,
                                      AllocaInst *is_ret_set,
                                      CallInst *call,
                                      const SizedType &type)
{
  auto *value_type = GetMapValueType(type);
  auto *cast = CreatePointerCast(call, value_type->getPointerTo(), "cast");
  bool is_max = type.IsMaxTy();

  Value *mm_val = CreateLoad(
      getInt64Ty(), CreateGEP(value_type, cast, { getInt64(0), getInt32(0) }));

  Value *is_val_set = CreateLoad(
      getInt64Ty(), CreateGEP(value_type, cast, { getInt64(0), getInt32(1) }));

  /*
   * (ret, is_ret_set, min_max_val, is_val_set) {
   * // if the min_max_val is 0, which is the initial map value,
   * // we need to know if it was explicitly set by user
   * if (!is_val_set == 1) {
   *   return;
   * }
   * if (!is_ret_set == 1) {
   *   ret = min_max_val;
   *   is_ret_set = 1;
   * } else if (min_max_val > ret) { // or min_max_val < ret if min operation
   *   ret = min_max_val;
   *   is_ret_set = 1;
   * }
   */

  Function *parent = GetInsertBlock()->getParent();
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
  auto *cast = CreatePointerCast(call, value_type->getPointerTo(), "cast");

  Value *total_val = CreateLoad(
      getInt64Ty(), CreateGEP(value_type, cast, { getInt64(0), getInt32(0) }));

  Value *count_val = CreateLoad(
      getInt64Ty(), CreateGEP(value_type, cast, { getInt64(0), getInt32(1) }));

  CreateStore(CreateAdd(total_val, CreateLoad(getInt64Ty(), total)), total);
  CreateStore(CreateAdd(count_val, CreateLoad(getInt64Ty(), count)), count);
}

void IRBuilderBPF::CreateMapUpdateElem(Value *ctx,
                                       const std::string &map_ident,
                                       Value *key,
                                       Value *val,
                                       const location &loc,
                                       int64_t flags)
{
  Value *map_ptr = GetMapVar(map_ident);
  assert(ctx && ctx->getType() == GET_PTR_TY());
  assert(key->getType()->isPointerTy());
  assert(val->getType()->isPointerTy());

  Value *flags_val = getInt64(flags);

  // long map_update_elem(struct bpf_map * map, void *key, void * value, u64
  // flags) Return: 0 on success or negative error
  FunctionType *update_func_type = FunctionType::get(
      getInt64Ty(),
      { map_ptr->getType(), key->getType(), val->getType(), getInt64Ty() },
      false);
  PointerType *update_func_ptr_type = PointerType::get(update_func_type, 0);
  Constant *update_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_map_update_elem),
      update_func_ptr_type);
  CallInst *call = createCall(update_func_type,
                              update_func,
                              { map_ptr, key, val, flags_val },
                              "update_elem");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_map_update_elem, loc);
}

void IRBuilderBPF::CreateMapDeleteElem(Value *ctx,
                                       Map &map,
                                       Value *key,
                                       const location &loc)
{
  assert(ctx && ctx->getType() == GET_PTR_TY());
  assert(key->getType()->isPointerTy());
  Value *map_ptr = GetMapVar(map.ident);

  // long map_delete_elem(&map, &key)
  // Return: 0 on success or negative error
  FunctionType *delete_func_type = FunctionType::get(
      getInt64Ty(), { map_ptr->getType(), key->getType() }, false);
  PointerType *delete_func_ptr_type = PointerType::get(delete_func_type, 0);
  Constant *delete_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_map_delete_elem),
      delete_func_ptr_type);
  CallInst *call = createCall(
      delete_func_type, delete_func, { map_ptr, key }, "delete_elem");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_map_delete_elem, loc);
}

void IRBuilderBPF::CreateForEachMapElem(Value *ctx,
                                        Map &map,
                                        Value *callback,
                                        Value *callback_ctx,
                                        const location &loc)
{
  Value *map_ptr = GetMapVar(map.ident);

  // long bpf_for_each_map_elem(struct bpf_map *map, void *callback_fn, void
  // *callback_ctx, u64 flags)
  //
  // Return: 0 on success or negative error
  //
  // callback is long (*callback_fn)(struct bpf_map *map, const void *key, void
  // *value, void *ctx);

  auto *int8_ptr = getInt8Ty()->getPointerTo();

  FunctionType *for_each_map_type = FunctionType::get(
      getInt64Ty(),
      { map_ptr->getType(), callback->getType(), int8_ptr, getInt64Ty() },
      false);
  PointerType *for_each_map_ptr_type = PointerType::get(for_each_map_type, 0);

  Constant *for_each_map_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_for_each_map_elem),
      for_each_map_ptr_type);
  CallInst *call = createCall(for_each_map_type,
                              for_each_map_func,
                              { map_ptr,
                                callback,
                                CreateBitCast(callback_ctx, int8_ptr),
                                /*flags=*/getInt64(0) },
                              "for_each_map_elem");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_for_each_map_elem, loc);
}

void IRBuilderBPF::CreateCheckSetRecursion(const location &loc,
                                           int early_exit_ret)
{
  const std::string map_ident = to_string(MapType::RecursionPrevention);

  AllocaInst *key = CreateAllocaBPF(getInt32Ty(), "lookup_key");
  CreateStore(getInt32(0), key);

  CallInst *call = createMapLookup(map_ident, key);

  Function *parent = GetInsertBlock()->getParent();
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
      CreateIntCast(call, GET_PTR_TY(), true),
      ConstantExpr::getCast(Instruction::IntToPtr, getInt64(0), GET_PTR_TY()),
      "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);

  CreateLifetimeEnd(key);

  // createMapLookup  returns an u8*
  auto *cast = CreatePointerCast(call, getInt64Ty(), "cast");

  Value *prev_value = CREATE_ATOMIC_RMW(AtomicRMWInst::BinOp::Xchg,
                                        cast,
                                        getInt64(1),
                                        8,
                                        AtomicOrdering::SequentiallyConsistent);

  Function *set_parent = GetInsertBlock()->getParent();
  BasicBlock *value_is_set_block = BasicBlock::Create(module_.getContext(),
                                                      "value_is_set",
                                                      set_parent);
  Value *set_condition = CreateICmpEQ(prev_value,
                                      getInt64(0),
                                      "value_set_condition");
  CreateCondBr(set_condition, merge_block, value_is_set_block);

  SetInsertPoint(value_is_set_block);
  /*
   * The counter is set, we need to exit early from the probe.
   * Most of the time this will happen for the functions that can lead
   * to a crash e.g. "queued_spin_lock_slowpath" but it can also happen
   * for nested probes e.g. "page_fault_user" -> "print".
   */
  CreateAtomicIncCounter(to_string(MapType::EventLossCounter),
                         bpftrace_.event_loss_cnt_key_);
  CreateRet(getInt64(early_exit_ret));

  SetInsertPoint(lookup_failure_block);

  CreateDebugOutput(
      "Value for per-cpu map key 0 is null. This shouldn't happen.",
      std::vector<Value *>{},
      loc);
  CreateRet(getInt64(0));

  SetInsertPoint(merge_block);
}

void IRBuilderBPF::CreateUnSetRecursion(const location &loc)
{
  const std::string map_ident = to_string(MapType::RecursionPrevention);

  AllocaInst *key = CreateAllocaBPF(getInt32Ty(), "lookup_key");
  CreateStore(getInt32(0), key);

  CallInst *call = createMapLookup(map_ident, key);

  Function *parent = GetInsertBlock()->getParent();
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
      CreateIntCast(call, GET_PTR_TY(), true),
      ConstantExpr::getCast(Instruction::IntToPtr, getInt64(0), GET_PTR_TY()),
      "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);

  CreateLifetimeEnd(key);

  // createMapLookup  returns an u8*
  auto *cast = CreatePointerCast(call, getInt64Ty(), "cast");
  CreateStore(getInt64(0), cast);

  CreateBr(merge_block);

  SetInsertPoint(lookup_failure_block);

  CreateDebugOutput(
      "Value for per-cpu map key 0 is null. This shouldn't happen.",
      std::vector<Value *>{},
      loc);

  CreateBr(merge_block);

  SetInsertPoint(merge_block);
}

void IRBuilderBPF::CreateProbeRead(Value *ctx,
                                   Value *dst,
                                   llvm::Value *size,
                                   Value *src,
                                   AddrSpace as,
                                   const location &loc)
{
  assert(ctx && ctx->getType() == GET_PTR_TY());
  assert(size && size->getType()->getIntegerBitWidth() <= 32);
  size = CreateIntCast(size, getInt32Ty(), false);

  // int bpf_probe_read(void *dst, int size, void *src)
  // Return: 0 on success or negative error

  auto read_fn = selectProbeReadHelper(as, false);

  FunctionType *proberead_func_type = FunctionType::get(
      getInt64Ty(), { dst->getType(), getInt32Ty(), src->getType() }, false);
  PointerType *proberead_func_ptr_type = PointerType::get(proberead_func_type,
                                                          0);
  Constant *proberead_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                   getInt64(read_fn),
                                                   proberead_func_ptr_type);
  CallInst *call = createCall(proberead_func_type,
                              proberead_func,
                              { dst, size, src },
                              probeReadHelperName(read_fn));
  CreateHelperErrorCond(ctx, call, read_fn, loc);
}

CallInst *IRBuilderBPF::CreateProbeReadStr(Value *ctx,
                                           Value *dst,
                                           size_t size,
                                           Value *src,
                                           AddrSpace as,
                                           const location &loc)
{
  return CreateProbeReadStr(ctx, dst, getInt32(size), src, as, loc);
}

CallInst *IRBuilderBPF::CreateProbeReadStr(Value *ctx,
                                           Value *dst,
                                           llvm::Value *size,
                                           Value *src,
                                           AddrSpace as,
                                           const location &loc)
{
  assert(ctx && ctx->getType() == GET_PTR_TY());
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
  PointerType *probereadstr_func_ptr_type = PointerType::get(
      probereadstr_func_type, 0);
  Constant *probereadstr_callee = ConstantExpr::getCast(
      Instruction::IntToPtr, getInt64(read_fn), probereadstr_func_ptr_type);
  CallInst *call = createCall(probereadstr_func_type,
                              probereadstr_callee,
                              { dst, size_i32, src },
                              probeReadHelperName(read_fn));
  CreateHelperErrorCond(ctx, call, read_fn, loc);
  return call;
}

Value *IRBuilderBPF::CreateUSDTReadArgument(Value *ctx,
                                            struct bcc_usdt_argument *argument,
                                            Builtin &builtin,
                                            AddrSpace as,
                                            const location &loc)
{
  assert(ctx && ctx->getType() == GET_PTR_TY());
  // Argument size must be 1, 2, 4, or 8. See
  // https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
  int abs_size = std::abs(argument->size);
  assert(abs_size == 1 || abs_size == 2 || abs_size == 4 || abs_size == 8);
  if (argument->valid & BCC_USDT_ARGUMENT_DEREF_IDENT)
    LOG(ERROR) << "deref ident is not handled yet [" << argument->deref_ident
               << "]";
  // USDT arguments can be any valid gas (GNU asm) operand.
  // BCC normalises these into the bcc_usdt_argument and supports most
  // valid gas operands.
  //
  // This code handles the following argument types:
  // * A constant (ARGUMENT_CONSTANT)
  //
  // * The value of a register (ARGUMENT_BASE_REGISTER_NAME without
  // ARGUMENT_DEREF_OFFSET set).
  //
  // * The value at address: base_register + offset + (index_register * scale)
  // Where index_register and scale are optional.
  // Note: Offset is optional in the gas operand, however will be set as zero
  // if the register needs to be dereferenced.

  if (argument->valid & BCC_USDT_ARGUMENT_CONSTANT) {
    // Correctly sign extend and convert to a 64-bit int
    return CreateIntCast(getIntN(abs_size * 8, argument->constant),
                         getInt64Ty(),
                         argument->size < 0);
  }

  if (argument->valid & BCC_USDT_ARGUMENT_INDEX_REGISTER_NAME &&
      !(argument->valid & BCC_USDT_ARGUMENT_BASE_REGISTER_NAME)) {
    // Invalid combination??
    LOG(ERROR) << "index register set without base register;"
               << " this case is not yet handled";
  }
  Value *result = nullptr;
  if (argument->valid & BCC_USDT_ARGUMENT_BASE_REGISTER_NAME) {
    int offset = 0;
    offset = arch::offset(argument->base_register_name);
    if (offset < 0) {
      LOG(BUG) << "offset for register " << argument->base_register_name
               << " not known";
    }

    // bpftrace's args are internally represented as 64 bit integers. However,
    // the underlying argument (of the target program) may be less than 64
    // bits. So we must be careful to zero out unused bits.
    Value *reg = CreateGEP(getInt8Ty(),
                           ctx,
                           getInt64(offset * sizeof(uintptr_t)),
                           "load_register");
    AllocaInst *dst = CreateAllocaBPF(builtin.type, builtin.ident);
    Value *index_offset = nullptr;
    if (argument->valid & BCC_USDT_ARGUMENT_INDEX_REGISTER_NAME) {
      int ioffset = arch::offset(argument->index_register_name);
      if (ioffset < 0) {
        LOG(BUG) << "offset for register " << argument->index_register_name
                 << " not known";
      }
      index_offset = CreateGEP(getInt8Ty(),
                               ctx,
                               getInt64(ioffset * sizeof(uintptr_t)),
                               "load_register");
      index_offset = CreateLoad(getInt64Ty(), index_offset);
      if (argument->valid & BCC_USDT_ARGUMENT_SCALE) {
        index_offset = CreateMul(index_offset, getInt64(argument->scale));
      }
    }
    if (argument->valid & BCC_USDT_ARGUMENT_DEREF_OFFSET) {
      Value *ptr = CreateAdd(CreateLoad(getInt64Ty(), reg),
                             getInt64(argument->deref_offset));
      if (index_offset) {
        ptr = CreateAdd(ptr, index_offset);
      }
      CreateProbeRead(ctx, dst, getInt32(abs_size), ptr, as, loc);
      result = CreateLoad(getIntNTy(abs_size * 8), dst);
    } else {
      result = CreateLoad(getIntNTy(abs_size * 8), reg);
    }
    // Sign extend and convert to a bpftools standard 64-bit integer type
    result = CreateIntCast(result, getInt64Ty(), argument->size < 0);
    CreateLifetimeEnd(dst);
  }
  return result;
}

Value *IRBuilderBPF::CreateUSDTReadArgument(Value *ctx,
                                            AttachPoint *attach_point,
                                            int usdt_location_index,
                                            int arg_num,
                                            Builtin &builtin,
                                            pid_t pid,
                                            AddrSpace as,
                                            const location &loc)
{
  assert(ctx && ctx->getType() == GET_PTR_TY());
  struct bcc_usdt_argument argument;

  void *usdt;

  if (pid) {
    // FIXME use attach_point->target when iovisor/bcc#2064 is merged
    usdt = bcc_usdt_new_frompid(pid, nullptr);
  } else {
    usdt = bcc_usdt_new_frompath(attach_point->target.c_str());
  }

  if (usdt == nullptr) {
    LOG(ERROR) << "failed to initialize usdt context for probe "
               << attach_point->target;
    exit(-1);
  }

  std::string ns = attach_point->usdt.provider;
  std::string func = attach_point->usdt.name;

  if (bcc_usdt_get_argument(usdt,
                            ns.c_str(),
                            func.c_str(),
                            usdt_location_index,
                            arg_num,
                            &argument) != 0) {
    LOG(ERROR) << "couldn't get argument " << arg_num << " for "
               << attach_point->target << ":" << attach_point->ns << ":"
               << attach_point->func;
    exit(-2);
  }

  Value *result = CreateUSDTReadArgument(ctx, &argument, builtin, as, loc);

  bcc_usdt_close(usdt);
  return result;
}

std::optional<std::string> ValToString(Value *val)
{
  std::optional<std::string> literal;
  if (auto constString2 = dyn_cast<ConstantDataArray>(val))
    literal = constString2->getAsString();
  else if (isa<ConstantAggregateZero>(val))
    literal = "";
  else
    literal = std::nullopt;
  return literal;
}

Value *IRBuilderBPF::CreateStrncmp(Value *str1,
                                   Value *str2,
                                   uint64_t n,
                                   bool inverse)
{
  /*
  // This function compares each character of the two string.
  // It returns true if all are equal and false if any are different
  // strcmp(String val1, String val2)
     {
        for (size_t i = 0; i < n; i++)
        {

          if (val1[i] != val2[i])
          {
            return false;
          }
          if (val1[i] == NULL)
          {
            return true;
          }
        }

        return true;
     }
  */

  // Check if the compared strings are literals.
  // If so, we can avoid storing the literal in memory.
  std::optional<std::string> literal1 = ValToString(str1);
  std::optional<std::string> literal2 = ValToString(str2);

  Function *parent = GetInsertBlock()->getParent();
  AllocaInst *store = CreateAllocaBPF(getInt1Ty(), "strcmp.result");
  BasicBlock *str_ne = BasicBlock::Create(module_.getContext(),
                                          "strcmp.false",
                                          parent);
  BasicBlock *done = BasicBlock::Create(module_.getContext(),
                                        "strcmp.done",
                                        parent);

  CreateStore(getInt1(!inverse), store);

  Value *null_byte = getInt8(0);
  for (size_t i = 0; i < n; i++) {
    BasicBlock *char_eq = BasicBlock::Create(module_.getContext(),
                                             "strcmp.loop",
                                             parent);
    BasicBlock *loop_null_check = BasicBlock::Create(module_.getContext(),
                                                     "strcmp.loop_null_cmp",
                                                     parent);

    Value *l;
    if (literal1)
      l = getInt8(literal1->c_str()[i]);
    else {
      auto *ptr_l = CreateGEP(getInt8Ty(),
                              CreatePointerCast(str1,
                                                getInt8Ty()->getPointerTo()),
                              { getInt32(i) });
      l = CreateLoad(getInt8Ty(), ptr_l);
    }

    Value *r;
    if (literal2)
      r = getInt8(literal2->c_str()[i]);
    else {
      auto *ptr_r = CreateGEP(getInt8Ty(),
                              CreatePointerCast(str2,
                                                getInt8Ty()->getPointerTo()),
                              { getInt32(i) });
      r = CreateLoad(getInt8Ty(), ptr_r);
    }

    Value *cmp = CreateICmpNE(l, r, "strcmp.cmp");
    CreateCondBr(cmp, str_ne, loop_null_check);

    SetInsertPoint(loop_null_check);

    Value *cmp_null = CreateICmpEQ(l, null_byte, "strcmp.cmp_null");
    CreateCondBr(cmp_null, done, char_eq);

    SetInsertPoint(char_eq);
  }

  CreateBr(done);
  SetInsertPoint(done);
  CreateStore(getInt1(inverse), store);

  CreateBr(str_ne);
  SetInsertPoint(str_ne);

  // store is a pointer to bool (i1 *)
  Value *result = CreateLoad(getInt1Ty(), store);
  CreateLifetimeEnd(store);
  result = CreateIntCast(result, getInt64Ty(), false);

  return result;
}

Value *IRBuilderBPF::CreateStrcontains(Value *val1,
                                       uint64_t str1_size,
                                       Value *val2,
                                       uint64_t str2_size,
                                       bool inverse)
{
  /*
  // This function compares whether the string val1 contains the string val2.
  // It returns true if val2 is contained by val1, false if not contained.
  // strcontains(String val1, String val2, int str1_size, int str2_size)
     {
        for (size_t j = 0; (str1_size >= str2_size) && (j <= str1_size -
  str2_size); j++)
        {
          for (size_t i = 0; i < str2_size; i++)
          {
            if (val2[i] == NULL)
            {
              return true;
            }
            if (val1[i + j] != val2[i])
            {
              break;
            }
          }
          if (val1[j] == NULL) {
            return false;
          }
        }
        return false;
     }
  */
  // Check if the compared strings are literals.
  // If so, we can avoid storing the literal in memory.
  std::optional<std::string> literal1 = ValToString(val1);
  std::optional<std::string> literal2 = ValToString(val2);

  if (literal1 && literal2) {
    std::string s1 = literal1.value();
    std::string s2 = literal2.value();
    s2 = s2.substr(0, s2.size() - 1);
    std::size_t position = s1.find(s2);

    if (position != std::string::npos) {
      return getInt64(1);
    } else {
      return getInt64(0);
    }
  }

  Function *parent = GetInsertBlock()->getParent();
  AllocaInst *store = CreateAllocaBPF(getInt1Ty(), "strcontains.result");
  BasicBlock *done_true = BasicBlock::Create(module_.getContext(),
                                             "strcontains.true",
                                             parent);
  BasicBlock *done_false = BasicBlock::Create(module_.getContext(),
                                              "strcontains.false",
                                              parent);

  CreateStore(getInt1(!inverse), store);
  Value *null_byte = getInt8(0);

  for (size_t j = 0; (str1_size >= str2_size) && (j <= str1_size - str2_size);
       j++) {
    BasicBlock *first_loop = BasicBlock::Create(module_.getContext(),
                                                "strcontains.firstloop",
                                                parent);

    Value *str_c;
    if (literal1)
      str_c = getInt8(literal1->c_str()[j]);
    else {
      auto *ptr_str = CreateGEP(ArrayType::get(getInt8Ty(), str1_size),
                                val1,
                                { getInt32(0), getInt32(j) });
      str_c = CreateLoad(getInt8Ty(), ptr_str);
    }

    for (size_t i = 0; i < str2_size; i++) {
      BasicBlock *second_loop = BasicBlock::Create(module_.getContext(),
                                                   "strcontains.secondloop",
                                                   parent);
      BasicBlock *cmp_char = BasicBlock::Create(module_.getContext(),
                                                "strcontains.cmp_char",
                                                parent);

      Value *l;
      if (literal1)
        l = getInt8(literal1->c_str()[i + j]);
      else {
        auto *ptr_l = CreateGEP(ArrayType::get(getInt8Ty(), str1_size),
                                val1,
                                { getInt32(0), getInt32(i + j) });
        l = CreateLoad(getInt8Ty(), ptr_l);
      }

      Value *r;
      if (literal2)
        r = getInt8(literal2->c_str()[i]);
      else {
        auto *ptr_r = CreateGEP(ArrayType::get(getInt8Ty(), str2_size),
                                val2,
                                { getInt32(0), getInt32(i) });
        r = CreateLoad(getInt8Ty(), ptr_r);
      }

      Value *cmp_null = CreateICmpEQ(r, null_byte, "strcontains.cmp_null");
      CreateCondBr(cmp_null, done_true, cmp_char);

      SetInsertPoint(cmp_char);

      Value *cmp = CreateICmpNE(l, r, "strcontains.cmp");
      CreateCondBr(cmp, first_loop, second_loop);

      SetInsertPoint(second_loop);
    }
    Value *cmp_null = CreateICmpEQ(str_c, null_byte, "strcontains.cmp_null");
    CreateCondBr(cmp_null, done_false, first_loop);

    SetInsertPoint(first_loop);
  }
  CreateBr(done_false);
  SetInsertPoint(done_false);
  CreateStore(getInt1(inverse), store);

  CreateBr(done_true);
  SetInsertPoint(done_true);

  // store is a pointer to bool (i1 *)
  Value *result = CreateLoad(getInt1Ty(), store);
  CreateLifetimeEnd(store);
  result = CreateIntCast(result, getInt64Ty(), false);

  return result;
}

CallInst *IRBuilderBPF::CreateGetNs(TimestampMode ts, const location &loc)
{
  libbpf::bpf_func_id fn;
  switch (ts) {
    case TimestampMode::monotonic:
      fn = libbpf::BPF_FUNC_ktime_get_ns;
      break;
    case TimestampMode::boot:
      fn = bpftrace_.feature_->has_helper_ktime_get_boot_ns()
               ? libbpf::BPF_FUNC_ktime_get_boot_ns
               : libbpf::BPF_FUNC_ktime_get_ns;
      break;
    case TimestampMode::tai:
      fn = libbpf::BPF_FUNC_ktime_get_tai_ns;
      break;
    case TimestampMode::sw_tai:
      LOG(BUG) << "Invalid timestamp mode: "
               << std::to_string(
                      static_cast<std::underlying_type_t<TimestampMode>>(ts));
  }

  // u64 ktime_get_*ns()
  // Return: current ktime
  FunctionType *gettime_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(fn, gettime_func_type, {}, "get_ns", &loc);
}

CallInst *IRBuilderBPF::CreateJiffies64(const location &loc)
{
  // u64 bpf_jiffies64()
  // Return: jiffies (BITS_PER_LONG == 64) or jiffies_64 (otherwise)
  FunctionType *jiffies64_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(
      libbpf::BPF_FUNC_jiffies64, jiffies64_func_type, {}, "jiffies64", &loc);
}

Value *IRBuilderBPF::CreateIntegerArrayCmpUnrolled(Value *ctx,
                                                   Value *val1,
                                                   Value *val2,
                                                   const SizedType &val1_type,
                                                   const SizedType &val2_type,
                                                   const bool inverse,
                                                   const location &loc)
{
  /*
   // This function compares each character of the two arrays.
   // It returns true if all are equal and false if any are different
   // cmp([]char val1, []char val2)
   {
      for (size_t i = 0; i < n; i++)
      {
        if (val1[i] != val2[i])
        {
          return false;
        }
      }
      return true;
   }
*/
  auto elem_type = *val1_type.GetElementTy();
  const size_t num = val1_type.GetNumElements();

  Value *val1_elem_i, *val2_elem_i, *cmp;
  AllocaInst *v1 = CreateAllocaBPF(elem_type, "v1");
  AllocaInst *v2 = CreateAllocaBPF(elem_type, "v2");

  Function *parent = GetInsertBlock()->getParent();
  AllocaInst *store = CreateAllocaBPF(getInt1Ty(), "arraycmp.result");
  CreateStore(getInt1(inverse), store);
  BasicBlock *arr_ne = BasicBlock::Create(module_.getContext(),
                                          "arraycmp.false",
                                          parent);
  BasicBlock *done = BasicBlock::Create(module_.getContext(),
                                        "arraycmp.done",
                                        parent);

  Value *ptr_val1 = CreateIntToPtr(val1, GetType(val1_type)->getPointerTo());
  Value *ptr_val2 = CreateIntToPtr(val2, GetType(val2_type)->getPointerTo());

  for (size_t i = 0; i < num; i++) {
    BasicBlock *arr_eq = BasicBlock::Create(module_.getContext(),
                                            "arraycmp.loop",
                                            parent);
    auto *ptr_val1_elem_i = CreateGEP(GetType(val1_type),
                                      ptr_val1,
                                      { getInt32(0), getInt32(i) });
    if (onStack(val1_type)) {
      val1_elem_i = CreateLoad(GetType(elem_type), ptr_val1_elem_i);
    } else {
      CreateProbeRead(ctx,
                      v1,
                      getInt32(elem_type.GetSize()),
                      ptr_val1_elem_i,
                      val1_type.GetAS(),
                      loc);
      val1_elem_i = CreateLoad(GetType(elem_type), v1);
    }

    auto *ptr_val2_elem_i = CreateGEP(GetType(val2_type),
                                      ptr_val2,
                                      { getInt32(0), getInt32(i) });
    if (onStack(val2_type)) {
      val2_elem_i = CreateLoad(GetType(elem_type), ptr_val2_elem_i);
    } else {
      CreateProbeRead(ctx,
                      v2,
                      getInt32(elem_type.GetSize()),
                      ptr_val2_elem_i,
                      val2_type.GetAS(),
                      loc);
      val2_elem_i = CreateLoad(GetType(elem_type), v2);
    }
    cmp = CreateICmpNE(val1_elem_i, val2_elem_i, "arraycmp.cmp");

    CreateCondBr(cmp, arr_ne, arr_eq);
    SetInsertPoint(arr_eq);
  }
  CreateBr(done);

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

Value *IRBuilderBPF::CreateIntegerArrayCmp(Value *ctx,
                                           Value *val1,
                                           Value *val2,
                                           const SizedType &val1_type,
                                           const SizedType &val2_type,
                                           const bool inverse,
                                           const location &loc,
                                           MDNode *metadata)
{
  /*
   // This function compares each character of the two arrays.
   // It returns true if all are equal and false if any are different
   // cmp([]char val1, []char val2)
   {
      for (size_t i = 0; i < n; i++)
      {
        if (val1[i] != val2[i])
        {
          return false;
        }
      }
      return true;
   }
*/
  auto elem_type = *val1_type.GetElementTy();
  const size_t num = val1_type.GetNumElements();

  Value *val1_elem_i, *val2_elem_i, *cmp;
  AllocaInst *v1 = CreateAllocaBPF(elem_type, "v1");
  AllocaInst *v2 = CreateAllocaBPF(elem_type, "v2");
  AllocaInst *store = CreateAllocaBPF(getInt1Ty(), "arraycmp.result");
  CreateStore(getInt1(inverse), store);

  Function *parent = GetInsertBlock()->getParent();
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

  Value *ptr_val1 = CreateIntToPtr(val1, GetType(val1_type)->getPointerTo());
  Value *ptr_val2 = CreateIntToPtr(val2, GetType(val2_type)->getPointerTo());
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
  if (onStack(val1_type)) {
    val1_elem_i = CreateLoad(GetType(elem_type), ptr_val1_elem_i);
  } else {
    CreateProbeRead(ctx,
                    v1,
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
  if (onStack(val2_type)) {
    val2_elem_i = CreateLoad(GetType(elem_type), ptr_val2_elem_i);
  } else {
    CreateProbeRead(ctx,
                    v2,
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

CallInst *IRBuilderBPF::CreateGetPidTgid(const location &loc)
{
  // u64 bpf_get_current_pid_tgid(void)
  // Return: current->tgid << 32 | current->pid
  FunctionType *getpidtgid_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(libbpf::BPF_FUNC_get_current_pid_tgid,
                          getpidtgid_func_type,
                          {},
                          "get_pid_tgid",
                          &loc);
}

CallInst *IRBuilderBPF::CreateGetCurrentCgroupId(const location &loc)
{
  // u64 bpf_get_current_cgroup_id(void)
  // Return: 64-bit cgroup-v2 id
  FunctionType *getcgroupid_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(libbpf::BPF_FUNC_get_current_cgroup_id,
                          getcgroupid_func_type,
                          {},
                          "get_cgroup_id",
                          &loc);
}

CallInst *IRBuilderBPF::CreateGetUidGid(const location &loc)
{
  // u64 bpf_get_current_uid_gid(void)
  // Return: current_gid << 32 | current_uid
  FunctionType *getuidgid_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(libbpf::BPF_FUNC_get_current_uid_gid,
                          getuidgid_func_type,
                          {},
                          "get_uid_gid",
                          &loc);
}

CallInst *IRBuilderBPF::CreateGetNumaId(const location &loc)
{
  // long bpf_get_numa_node_id(void)
  // Return: NUMA Node ID
  FunctionType *numaid_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(libbpf::BPF_FUNC_get_numa_node_id,
                          numaid_func_type,
                          {},
                          "get_numa_id",
                          &loc);
}

CallInst *IRBuilderBPF::CreateGetCpuId(const location &loc)
{
  // u32 bpf_raw_smp_processor_id(void)
  // Return: SMP processor ID
  FunctionType *getcpuid_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(libbpf::BPF_FUNC_get_smp_processor_id,
                          getcpuid_func_type,
                          {},
                          "get_cpu_id",
                          &loc);
}

CallInst *IRBuilderBPF::CreateGetCurrentTask(const location &loc)
{
  // u64 bpf_get_current_task(void)
  // Return: current task_struct
  FunctionType *getcurtask_func_type = FunctionType::get(getInt64Ty(), false);
  return CreateHelperCall(libbpf::BPF_FUNC_get_current_task,
                          getcurtask_func_type,
                          {},
                          "get_cur_task",
                          &loc);
}

CallInst *IRBuilderBPF::CreateGetRandom(const location &loc)
{
  // u32 bpf_get_prandom_u32(void)
  // Return: random
  FunctionType *getrandom_func_type = FunctionType::get(getInt32Ty(), false);
  return CreateHelperCall(libbpf::BPF_FUNC_get_prandom_u32,
                          getrandom_func_type,
                          {},
                          "get_random",
                          &loc);
}

CallInst *IRBuilderBPF::CreateGetStack(Value *ctx,
                                       bool ustack,
                                       Value *buf,
                                       StackType stack_type,
                                       const location &loc)
{
  assert(ctx && ctx->getType() == GET_PTR_TY());

  int flags = 0;
  if (ustack)
    flags |= (1 << 8);
  Value *flags_val = getInt64(flags);
  Value *stack_size = getInt32(stack_type.limit * sizeof(uint64_t));

  // long bpf_get_stack(void *ctx, void *buf, u32 size, u64 flags)
  // Return: The non-negative copied *buf* length equal to or less than
  // *size* on success, or a negative error in case of failure.
  FunctionType *getstack_func_type = FunctionType::get(
      getInt32Ty(),
      { GET_PTR_TY(), GET_PTR_TY(), getInt32Ty(), getInt64Ty() },
      false);
  CallInst *call = CreateHelperCall(libbpf::BPF_FUNC_get_stack,
                                    getstack_func_type,
                                    { ctx, buf, stack_size, flags_val },
                                    "get_stack",
                                    &loc);
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_get_stack, loc);
  return call;
}

CallInst *IRBuilderBPF::CreateGetFuncIp(Value *ctx, const location &loc)
{
  // u64 bpf_get_func_ip(void *ctx)
  // Return:
  // 		Address of the traced function for kprobe.
  //		0 for kprobes placed within the function (not at the entry).
  //		Address of the probe for uprobe and return uprobe.
  FunctionType *getfuncip_func_type = FunctionType::get(getInt64Ty(),
                                                        { GET_PTR_TY() },
                                                        false);
  return CreateHelperCall(libbpf::BPF_FUNC_get_func_ip,
                          getfuncip_func_type,
                          { ctx },
                          "get_func_ip",
                          &loc);
}

void IRBuilderBPF::CreateGetCurrentComm(Value *ctx,
                                        AllocaInst *buf,
                                        size_t size,
                                        const location &loc)
{
  assert(buf->getAllocatedType()->isArrayTy() &&
         buf->getAllocatedType()->getArrayNumElements() >= size &&
         buf->getAllocatedType()->getArrayElementType() == getInt8Ty());

  // long bpf_get_current_comm(char *buf, int size_of_buf)
  // Return: 0 on success or negative error
  FunctionType *getcomm_func_type = FunctionType::get(
      getInt64Ty(), { buf->getType(), getInt64Ty() }, false);
  CallInst *call = CreateHelperCall(libbpf::BPF_FUNC_get_current_comm,
                                    getcomm_func_type,
                                    { buf, getInt64(size) },
                                    "get_comm",
                                    &loc);
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_get_current_comm, loc);
}

void IRBuilderBPF::CreateOutput(Value *ctx,
                                Value *data,
                                size_t size,
                                const location *loc)
{
  assert(ctx && ctx->getType() == GET_PTR_TY());
  assert(data && data->getType()->isPointerTy());

  if (bpftrace_.feature_->has_map_ringbuf()) {
    CreateRingbufOutput(data, size, loc);
  } else {
    CreatePerfEventOutput(ctx, data, size, loc);
  }
}

void IRBuilderBPF::CreateRingbufOutput(Value *data,
                                       size_t size,
                                       const location *loc)
{
  Value *map_ptr = GetMapVar(to_string(MapType::Ringbuf));

  // long bpf_ringbuf_output(void *ringbuf, void *data, u64 size, u64 flags)
  FunctionType *ringbuf_output_func_type = FunctionType::get(
      getInt64Ty(),
      { map_ptr->getType(), data->getType(), getInt64Ty(), getInt64Ty() },
      false);

  Value *ret = CreateHelperCall(libbpf::BPF_FUNC_ringbuf_output,
                                ringbuf_output_func_type,
                                { map_ptr, data, getInt64(size), getInt64(0) },
                                "ringbuf_output",
                                loc);

  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *loss_block = BasicBlock::Create(module_.getContext(),
                                              "event_loss_counter",
                                              parent);
  BasicBlock *merge_block = BasicBlock::Create(module_.getContext(),
                                               "counter_merge",
                                               parent);
  Value *condition = CreateICmpSLT(ret, getInt64(0), "ringbuf_loss");
  CreateCondBr(condition, loss_block, merge_block);

  SetInsertPoint(loss_block);
  CreateAtomicIncCounter(to_string(MapType::EventLossCounter),
                         bpftrace_.event_loss_cnt_key_);
  CreateBr(merge_block);

  SetInsertPoint(merge_block);
}

void IRBuilderBPF::CreateAtomicIncCounter(const std::string &map_name,
                                          uint32_t idx)
{
  AllocaInst *key = CreateAllocaBPF(getInt32Ty(), "key");
  CreateStore(getInt32(idx), key);

  CallInst *call = createMapLookup(map_name, key);
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_success",
                                                        parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_failure",
                                                        parent);
  BasicBlock *lookup_merge_block = BasicBlock::Create(module_.getContext(),
                                                      "lookup_merge",
                                                      parent);

  Value *condition = CreateICmpNE(CreateIntCast(call, GET_PTR_TY(), true),
                                  GetNull(),
                                  "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);
  Value *val = CreatePointerCast(call, getInt64Ty()->getPointerTo());
  CREATE_ATOMIC_RMW(AtomicRMWInst::BinOp::Add,
                    val,
                    getInt64(1),
                    8,
                    AtomicOrdering::SequentiallyConsistent);
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_failure_block);
  // ignore lookup failure
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_merge_block);
  CreateLifetimeEnd(key);
}

void IRBuilderBPF::CreateMapElemInit(Value *ctx,
                                     Map &map,
                                     Value *key,
                                     Value *val,
                                     const location &loc)
{
  AllocaInst *initValue = CreateAllocaBPF(val->getType(), "initial_value");
  CreateStore(val, initValue);
  CreateMapUpdateElem(ctx, map.ident, key, initValue, loc, BPF_NOEXIST);
  CreateLifetimeEnd(initValue);
  return;
}

void IRBuilderBPF::CreateMapElemAdd(Value *ctx,
                                    Map &map,
                                    Value *key,
                                    Value *val,
                                    const location &loc)
{
  CallInst *call = CreateMapLookup(map, key);
  SizedType &type = map.type;

  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_success",
                                                        parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(),
                                                        "lookup_failure",
                                                        parent);
  BasicBlock *lookup_merge_block = BasicBlock::Create(module_.getContext(),
                                                      "lookup_merge",
                                                      parent);

  AllocaInst *value = CreateAllocaBPF(type, "lookup_elem_val");
  Value *condition = CreateICmpNE(CreateIntCast(call, GET_PTR_TY(), true),
                                  GetNull(),
                                  "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);

  // createMapLookup  returns an u8*
  auto *cast = CreatePointerCast(call, value->getType(), "cast");
  CreateStore(CreateAdd(CreateLoad(value->getAllocatedType(), cast), val),
              cast);

  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_failure_block);

  CreateMapElemInit(ctx, map, key, val, loc);

  CreateBr(lookup_merge_block);
  SetInsertPoint(lookup_merge_block);
  CreateLifetimeEnd(value);
  return;
}

void IRBuilderBPF::CreatePerfEventOutput(Value *ctx,
                                         Value *data,
                                         size_t size,
                                         const location *loc)
{
  Value *map_ptr = GetMapVar(to_string(MapType::PerfEvent));

  Value *flags_val = getInt64(BPF_F_CURRENT_CPU);
  Value *size_val = getInt64(size);

  // long bpf_perf_event_output(struct pt_regs *ctx, struct bpf_map *map,
  //                            u64 flags, void *data, u64 size)
  FunctionType *perfoutput_func_type = FunctionType::get(getInt64Ty(),
                                                         { GET_PTR_TY(),
                                                           map_ptr->getType(),
                                                           getInt64Ty(),
                                                           data->getType(),
                                                           getInt64Ty() },
                                                         false);
  CreateHelperCall(libbpf::BPF_FUNC_perf_event_output,
                   perfoutput_func_type,
                   { ctx, map_ptr, flags_val, data, size_val },
                   "perf_event_output",
                   loc);
}

void IRBuilderBPF::CreateDebugOutput(std::string fmt_str,
                                     const std::vector<Value *> &values,
                                     const location &loc)
{
  if (!bpftrace_.debug_output_)
    return;
  fmt_str = "[BPFTRACE_DEBUG_OUTPUT] " + fmt_str;
  Constant *const_str = ConstantDataArray::getString(module_.getContext(),
                                                     fmt_str,
                                                     true);
  AllocaInst *fmt = CreateAllocaBPF(
      ArrayType::get(getInt8Ty(), fmt_str.length() + 1), "fmt_str");
  CreateMemsetBPF(fmt, getInt8(0), fmt_str.length() + 1);
  CreateStore(const_str, fmt);
  CreateTracePrintk(CreatePointerCast(fmt, getInt8Ty()->getPointerTo()),
                    getInt32(fmt_str.length() + 1),
                    values,
                    loc);
}

void IRBuilderBPF::CreateTracePrintk(Value *fmt_ptr,
                                     Value *fmt_size,
                                     const std::vector<Value *> &values,
                                     const location &loc)
{
  std::vector<Value *> args = { fmt_ptr, fmt_size };
  for (auto val : values) {
    args.push_back(val);
  }

  // long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)
  FunctionType *traceprintk_func_type = FunctionType::get(
      getInt64Ty(), { GET_PTR_TY(), getInt32Ty() }, true);

  CreateHelperCall(libbpf::BPF_FUNC_trace_printk,
                   traceprintk_func_type,
                   args,
                   "trace_printk",
                   &loc);
}

void IRBuilderBPF::CreateSignal(Value *ctx, Value *sig, const location &loc)
{
  // long bpf_send_signal(u32 sig)
  // Return: 0 or error
  FunctionType *signal_func_type = FunctionType::get(getInt64Ty(),
                                                     { getInt32Ty() },
                                                     false);
  PointerType *signal_func_ptr_type = PointerType::get(signal_func_type, 0);
  Constant *signal_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_send_signal),
      signal_func_ptr_type);
  CallInst *call = createCall(signal_func_type, signal_func, { sig }, "signal");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_send_signal, loc);
}

void IRBuilderBPF::CreateOverrideReturn(Value *ctx, Value *rc)
{
  // long bpf_override_return(struct pt_regs *regs, u64 rc)
  // Return: 0
  FunctionType *override_func_type = FunctionType::get(
      getInt64Ty(), { GET_PTR_TY(), getInt64Ty() }, false);
  PointerType *override_func_ptr_type = PointerType::get(override_func_type, 0);
  Constant *override_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_override_return),
      override_func_ptr_type);
  createCall(override_func_type, override_func, { ctx, rc }, "override");
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
  FunctionType *skb_output_func_type = FunctionType::get(getInt32Ty(),
                                                         { skb->getType(),
                                                           map_ptr->getType(),
                                                           getInt64Ty(),
                                                           data->getType(),
                                                           getInt64Ty() },
                                                         false);

  PointerType *skb_output_func_ptr_type = PointerType::get(skb_output_func_type,
                                                           0);
  Constant *skb_output_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_skb_output),
      skb_output_func_ptr_type);
  CallInst *call = createCall(skb_output_func_type,
                              skb_output_func,
                              { skb, map_ptr, flags, data, size_val },
                              "skb_output");
  return call;
}

Value *IRBuilderBPF::CreatKFuncArg(Value *ctx,
                                   SizedType &type,
                                   std::string &name)
{
  assert(type.IsIntTy() || type.IsPtrTy());
  ctx = CreatePointerCast(ctx, getInt64Ty()->getPointerTo());
  Value *expr = CreateLoad(
      GetType(type),
      CreateGEP(getInt64Ty(), ctx, getInt64(type.funcarg_idx)),
      name);

  // LLVM 7.0 <= does not have CreateLoad(*Ty, *Ptr, isVolatile, Name),
  // so call setVolatile() manually
  dyn_cast<LoadInst>(expr)->setVolatile(true);
  return expr;
}

Value *IRBuilderBPF::CreateRawTracepointArg(Value *ctx,
                                            const std::string &builtin)
{
  // argX
  int offset = atoi(builtin.substr(3).c_str());
  llvm::Type *type = getInt64Ty();

  ctx = CreatePointerCast(ctx, type->getPointerTo());
  Value *expr = CreateLoad(type,
                           CreateGEP(type, ctx, getInt64(offset)),
                           builtin);

  return expr;
}

Value *IRBuilderBPF::CreateUprobeArgsRecord(Value *ctx,
                                            const SizedType &args_type)
{
  assert(args_type.IsRecordTy());

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
  int offset;
  if (builtin == "retval")
    offset = arch::ret_offset();
  else if (builtin == "func")
    offset = arch::pc_offset();
  else // argX
    offset = arch::arg_offset(atoi(builtin.substr(3).c_str()));

  return CreateRegisterRead(ctx, offset, builtin);
}

Value *IRBuilderBPF::CreateRegisterRead(Value *ctx,
                                        int offset,
                                        const std::string &name)
{
  // Bitwidth of register values in struct pt_regs is the same as the kernel
  // pointer width on all supported architectures.
  llvm::Type *registerTy = getKernelPointerStorageTy();
  Value *ctx_ptr = CreatePointerCast(ctx, registerTy->getPointerTo());
  // LLVM optimization is possible to transform `(uint64*)ctx` into
  // `(uint8*)ctx`, but sometimes this causes invalid context access.
  // Mark every context access to suppress any LLVM optimization.
  Value *result = CreateLoad(registerTy,
                             CreateGEP(registerTy, ctx_ptr, getInt64(offset)),
                             name);
  // LLVM 7.0 <= does not have CreateLoad(*Ty, *Ptr, isVolatile, Name),
  // so call setVolatile() manually
  dyn_cast<LoadInst>(result)->setVolatile(true);
  // Caller expects an int64, so add a cast if the register size is different.
  if (result->getType()->getIntegerBitWidth() != 64) {
    result = CreateIntCast(result, getInt64Ty(), false);
  }
  return result;
}

static bool return_zero_if_err(libbpf::bpf_func_id func_id)
{
  switch (func_id) {
    /*
     * When these function fails, bpftrace stores zero as a result.
     * A user script can check an error by seeing the value.
     * Therefore error checks of these functions are omitted if
     * helper_check_level == 1.
     */
    case libbpf::BPF_FUNC_probe_read:
    case libbpf::BPF_FUNC_probe_read_str:
    case libbpf::BPF_FUNC_probe_read_kernel:
    case libbpf::BPF_FUNC_probe_read_kernel_str:
    case libbpf::BPF_FUNC_probe_read_user:
    case libbpf::BPF_FUNC_probe_read_user_str:
    case libbpf::BPF_FUNC_map_lookup_elem:
      return true;
    default:
      return false;
  }
  return false;
}

void IRBuilderBPF::CreateHelperError(Value *ctx,
                                     Value *return_value,
                                     libbpf::bpf_func_id func_id,
                                     const location &loc)
{
  assert(ctx && ctx->getType() == GET_PTR_TY());
  assert(return_value && return_value->getType() == getInt32Ty());

  if (bpftrace_.helper_check_level_ == 0 ||
      (bpftrace_.helper_check_level_ == 1 && return_zero_if_err(func_id)))
    return;

  int error_id = async_ids_.helper_error();
  bpftrace_.resources.helper_error_info[error_id] = { .func_id = func_id,
                                                      .loc = loc };

  auto elements = AsyncEvent::HelperError().asLLVMType(*this);
  StructType *helper_error_struct = GetStructType("helper_error_t",
                                                  elements,
                                                  true);
  AllocaInst *buf = CreateAllocaBPF(helper_error_struct, "helper_error_t");
  CreateStore(
      GetIntSameSize(asyncactionint(AsyncAction::helper_error), elements.at(0)),
      CreateGEP(helper_error_struct, buf, { getInt64(0), getInt32(0) }));
  CreateStore(
      GetIntSameSize(error_id, elements.at(1)),
      CreateGEP(helper_error_struct, buf, { getInt64(0), getInt32(1) }));
  CreateStore(
      return_value,
      CreateGEP(helper_error_struct, buf, { getInt64(0), getInt32(2) }));

  auto &layout = module_.getDataLayout();
  auto struct_size = layout.getTypeAllocSize(helper_error_struct);
  CreateOutput(ctx, buf, struct_size, &loc);
  CreateLifetimeEnd(buf);
}

// Report error if a return value < 0 (or return value == 0 if compare_zero is
// true)
void IRBuilderBPF::CreateHelperErrorCond(Value *ctx,
                                         Value *return_value,
                                         libbpf::bpf_func_id func_id,
                                         const location &loc,
                                         bool compare_zero)
{
  assert(ctx && ctx->getType() == GET_PTR_TY());
  if (bpftrace_.helper_check_level_ == 0 ||
      (bpftrace_.helper_check_level_ == 1 && return_zero_if_err(func_id)))
    return;

  Function *parent = GetInsertBlock()->getParent();
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
  Value *condition;
  if (compare_zero)
    condition = CreateICmpNE(ret, Constant::getNullValue(ret->getType()));
  else
    condition = CreateICmpSGE(ret, Constant::getNullValue(ret->getType()));
  CreateCondBr(condition, helper_merge_block, helper_failure_block);
  SetInsertPoint(helper_failure_block);
  CreateHelperError(ctx, ret, func_id, loc);
  CreateBr(helper_merge_block);
  SetInsertPoint(helper_merge_block);
}

void IRBuilderBPF::CreatePath(Value *ctx,
                              Value *buf,
                              Value *path,
                              const location &loc)
{
  // int bpf_d_path(struct path *path, char *buf, u32 sz)
  // Return: 0 or error
  FunctionType *d_path_func_type = FunctionType::get(
      getInt64Ty(), { GET_PTR_TY(), buf->getType(), getInt32Ty() }, false);
  CallInst *call = CreateHelperCall(
      libbpf::bpf_func_id::BPF_FUNC_d_path,
      d_path_func_type,
      { path, buf, getInt32(bpftrace_.config_.get(ConfigKeyInt::max_strlen)) },
      "d_path",
      &loc);
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_d_path, loc);
}

void IRBuilderBPF::CreateSeqPrintf(Value *ctx,
                                   Value *fmt,
                                   Value *fmt_size,
                                   Value *data,
                                   Value *data_len,
                                   const location &loc)
{
  // long bpf_seq_printf(struct seq_file *m, const char *fmt, __u32 fmt_size,
  //                     const void *data, __u32 data_len)
  // Return: 0 or error
  FunctionType *seq_printf_func_type = FunctionType::get(
      getInt64Ty(),
      { getInt64Ty(), GET_PTR_TY(), getInt32Ty(), GET_PTR_TY(), getInt32Ty() },
      false);
  PointerType *seq_printf_func_ptr_type = PointerType::get(seq_printf_func_type,
                                                           0);
  Constant *seq_printf_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_seq_printf),
      seq_printf_func_ptr_type);

  ctx = CreatePointerCast(ctx, getInt8Ty()->getPointerTo());
  Value *meta = CreateLoad(getInt64Ty()->getPointerTo(),
                           CreateGEP(getInt8Ty(), ctx, getInt64(0)),
                           "meta");
  dyn_cast<LoadInst>(meta)->setVolatile(true);

  Value *seq = CreateLoad(getInt64Ty(),
                          CreateGEP(getInt64Ty(), meta, getInt64(0)),
                          "seq");

  CallInst *call = createCall(seq_printf_func_type,
                              seq_printf_func,
                              { seq, fmt, fmt_size, data, data_len },
                              "seq_printf");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_seq_printf, loc);
}

StoreInst *IRBuilderBPF::createAlignedStore(Value *val,
                                            Value *ptr,
                                            unsigned int align)
{
  return CreateAlignedStore(val, ptr, MaybeAlign(align));
}

void IRBuilderBPF::CreateProbeRead(Value *ctx,
                                   Value *dst,
                                   const SizedType &type,
                                   Value *src,
                                   const location &loc,
                                   std::optional<AddrSpace> addrSpace)
{
  AddrSpace as = addrSpace ? addrSpace.value() : type.GetAS();

  if (!type.IsPtrTy())
    return CreateProbeRead(ctx, dst, getInt32(type.GetSize()), src, as, loc);

  // Pointers are internally always represented as 64-bit integers, matching the
  // BPF register size (BPF is a 64-bit ISA). This helps to avoid BPF codegen
  // issues such as truncating PTR_TO_STACK registers using shift operations,
  // which is disallowed (see https://github.com/bpftrace/bpftrace/pull/2361).
  // However, when reading pointers from kernel or user memory, we need to use
  // the appropriate size for the target system.
  const size_t ptr_size = getPointerStorageTy(as)->getIntegerBitWidth() / 8;

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  // TODO: support 32-bit big-endian systems
  assert(ptr_size == type.GetSize());
#endif

  if (ptr_size != type.GetSize())
    CreateMemsetBPF(dst, getInt8(0), type.GetSize());

  CreateProbeRead(ctx, dst, getInt32(ptr_size), src, as, loc);
}

llvm::Value *IRBuilderBPF::CreateDatastructElemLoad(
    const SizedType &type,
    llvm::Value *ptr,
    bool isVolatile,
    std::optional<AddrSpace> addrSpace)
{
  AddrSpace as = addrSpace ? addrSpace.value() : type.GetAS();
  llvm::Type *ptr_storage_ty = getPointerStorageTy(as);

  if (!type.IsPtrTy() || ptr_storage_ty == getInt64Ty())
    return CreateLoad(GetType(type), ptr, isVolatile);

  assert(GetType(type) == getInt64Ty());

  // Pointer size for the given address space doesn't match the BPF-side
  // representation. Use ptr_storage_ty as the load type and cast the result
  // back to int64.
  llvm::Value *expr = CreateLoad(
      ptr_storage_ty,
      CreatePointerCast(ptr, ptr_storage_ty->getPointerTo()),
      isVolatile);

  return CreateIntCast(expr, getInt64Ty(), false);
}

llvm::Value *IRBuilderBPF::CreatePtrOffset(const SizedType &type,
                                           llvm::Value *index,
                                           AddrSpace as)
{
  size_t elem_size = type.IsPtrTy()
                         ? getPointerStorageTy(as)->getIntegerBitWidth() / 8
                         : type.GetSize();

  return CreateMul(index, getInt64(elem_size));
}

llvm::Type *IRBuilderBPF::getPointerStorageTy(AddrSpace as)
{
  switch (as) {
    case AddrSpace::user:
      return getUserPointerStorageTy();
    default:
      return getKernelPointerStorageTy();
  }
}

llvm::Type *IRBuilderBPF::getKernelPointerStorageTy()
{
  static int ptr_width = arch::get_kernel_ptr_width();

  return getIntNTy(ptr_width);
}

llvm::Type *IRBuilderBPF::getUserPointerStorageTy()
{
  // TODO: we don't currently have an easy way of determining the pointer size
  // of the uprobed process, so assume it's the same as the kernel's for now.
  return getKernelPointerStorageTy();
}

} // namespace ast
} // namespace bpftrace
