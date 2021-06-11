#include <iostream>
#include <sstream>

#include "arch/arch.h"
#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "codegen_helper.h"
#include "irbuilderbpf.h"
#include "log.h"
#include "utils.h"

#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Module.h>

namespace libbpf {
#undef __BPF_FUNC_MAPPER
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {
namespace ast {

namespace {
std::string probeReadHelperName(libbpf::bpf_func_id id)
{
  switch (id)
  {
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
      throw std::runtime_error("BUG: unknown probe_read id: " +
                               std::to_string(id));
  }
}
} // namespace

libbpf::bpf_func_id IRBuilderBPF::selectProbeReadHelper(AddrSpace as, bool str)
{
  libbpf::bpf_func_id fn;
  // Assume that if a kernel has probe_read_kernel it has the other 3 too
  if (bpftrace_.feature_->has_helper_probe_read_kernel())
  {
    if (as == AddrSpace::kernel)
    {
      fn = str ? libbpf::BPF_FUNC_probe_read_kernel_str
               : libbpf::BPF_FUNC_probe_read_kernel;
    }
    else if (as == AddrSpace::user)
    {
      fn = str ? libbpf::BPF_FUNC_probe_read_user_str
               : libbpf::BPF_FUNC_probe_read_user;
    }
    else
    {
      // if the kernel has the new helpers but AS is still none it is a bug
      // in bpftrace, assert catches it for debug builds.
      // assert(as != AddrSpace::none);
      static bool warnonce = false;
      if (!warnonce)
      {
        warnonce = true;
        LOG(WARNING) << "Addrspace is not set";
      }
      fn = str ? libbpf::BPF_FUNC_probe_read_str : libbpf::BPF_FUNC_probe_read;
    }
  }
  else
  {
    fn = str ? libbpf::BPF_FUNC_probe_read_str : libbpf::BPF_FUNC_probe_read;
  }

  return fn;
}

AllocaInst *IRBuilderBPF::CreateUSym(llvm::Value *val)
{
  std::vector<llvm::Type *> elements = {
    getInt64Ty(), // addr
    getInt64Ty(), // pid
  };
  StructType *usym_t = GetStructType("usym_t", elements, false);
  AllocaInst *buf = CreateAllocaBPF(usym_t, "usym");

  Value *pid = CreateLShr(CreateGetPidTgid(), 32);

  // The extra 0 here ensures the type of addr_offset will be int64
  Value *addr_offset = CreateGEP(buf, { getInt64(0), getInt32(0) });
  Value *pid_offset = CreateGEP(buf, { getInt64(0), getInt32(1) });

  CreateStore(val, addr_offset);
  CreateStore(pid, pid_offset);
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
                           BPFtrace &bpftrace)
  : IRBuilder<>(context),
    module_(module),
    bpftrace_(bpftrace)
{
  // Declare external LLVM function
  FunctionType *pseudo_func_type = FunctionType::get(
      getInt64Ty(),
      {getInt64Ty(), getInt64Ty()},
      false);
  Function::Create(
      pseudo_func_type,
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

AllocaInst *IRBuilderBPF::CreateAllocaBPF(llvm::Type *ty, const std::string &name)
{
  return CreateAllocaBPF(ty, nullptr, name);
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(const SizedType &stype, const std::string &name)
{
  llvm::Type *ty = GetType(stype);
  return CreateAllocaBPF(ty, nullptr, name);
}

AllocaInst *IRBuilderBPF::CreateAllocaBPFInit(const SizedType &stype, const std::string &name)
{
  AllocaInst *alloca;
  hoist([this, &stype, &name, &alloca]() {
    llvm::Type *ty = GetType(stype);
    alloca = CreateAlloca(ty, nullptr, name);
    CreateLifetimeStart(alloca);
    if (needMemcpy(stype))
    {
      CREATE_MEMSET(alloca, getInt8(0), stype.GetSize(), 1);
    }
    else
    {
      CreateStore(ConstantInt::get(ty, 0), alloca);
    }
  });
  return alloca;
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(const SizedType &stype, llvm::Value *arraysize, const std::string &name)
{
  llvm::Type *ty = GetType(stype);
  return CreateAllocaBPF(ty, arraysize, name);
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(int bytes, const std::string &name)
{
  llvm::Type *ty = ArrayType::get(getInt8Ty(), bytes);
  return CreateAllocaBPF(ty, name);
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
  if (stype.IsByteArray() || stype.IsRecordTy())
  {
    ty = ArrayType::get(getInt8Ty(), stype.GetSize());
  }
  else if (stype.IsArrayTy())
  {
    ty = ArrayType::get(GetType(*stype.GetElementTy()), stype.GetNumElements());
  }
  else if (stype.IsTupleTy())
  {
    std::vector<llvm::Type *> llvm_elems;
    std::ostringstream ty_name;

    for (const auto &elem : stype.GetFields())
    {
      auto &elemtype = elem.type;
      llvm_elems.emplace_back(GetType(elemtype));
      ty_name << elemtype << "_";
    }
    ty_name << "_tuple_t";

    ty = GetStructType(ty_name.str(), llvm_elems, false);
  }
  else if (stype.IsPtrTy())
  {
    ty = getInt64Ty();
  }
  else
  {
    switch (stype.GetSize())
    {
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
        LOG(FATAL) << stype.GetSize()
                   << " is not a valid type size for GetType";
    }
  }
  return ty;
}

CallInst *IRBuilderBPF::createCall(Value *callee,
                                   ArrayRef<Value *> args,
                                   const Twine &Name)
{
#if LLVM_VERSION_MAJOR >= 11
  auto *calleePtrType = cast<PointerType>(callee->getType());
  auto *calleeType = cast<FunctionType>(calleePtrType->getElementType());
  return CreateCall(calleeType, callee, args, Name);
#else
  return CreateCall(callee, args, Name);
#endif
}

CallInst *IRBuilderBPF::CreateBpfPseudoCallId(int mapid)
{
  Function *pseudo_func = module_.getFunction("llvm.bpf.pseudo");
  return createCall(pseudo_func,
                    { getInt64(BPF_PSEUDO_MAP_FD), getInt64(mapid) },
                    "pseudo");
}

CallInst *IRBuilderBPF::CreateBpfPseudoCallId(Map &map)
{
  int mapid = bpftrace_.maps[map.ident].value()->id;
  return CreateBpfPseudoCallId(mapid);
}

CallInst *IRBuilderBPF::CreateBpfPseudoCallValue(int mapid)
{
  Function *pseudo_func = module_.getFunction("llvm.bpf.pseudo");
  return CreateCall(pseudo_func,
                    { getInt64(BPF_PSEUDO_MAP_VALUE), getInt64(mapid) },
                    "pseudo");
}

CallInst *IRBuilderBPF::CreateBpfPseudoCallValue(Map &map)
{
  int mapid = bpftrace_.maps[map.ident].value()->id;
  return CreateBpfPseudoCallValue(mapid);
}

CallInst *IRBuilderBPF::createMapLookup(int mapid, Value *key)
{
  Value *map_ptr = CreateBpfPseudoCallId(mapid);
  // void *map_lookup_elem(struct bpf_map * map, void * key)
  // Return: Map value or NULL

  assert(key->getType()->isPointerTy());
  FunctionType *lookup_func_type = FunctionType::get(
      getInt8PtrTy(), { map_ptr->getType(), key->getType() }, false);
  PointerType *lookup_func_ptr_type = PointerType::get(lookup_func_type, 0);
  Constant *lookup_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_map_lookup_elem),
      lookup_func_ptr_type);
  return createCall(lookup_func, { map_ptr, key }, "lookup_elem");
}

CallInst *IRBuilderBPF::CreateGetJoinMap(Value *ctx, const location &loc)
{
  AllocaInst *key = CreateAllocaBPF(getInt32Ty(), "key");
  CreateStore(getInt32(0), key);

  CallInst *call = createMapLookup(
      bpftrace_.maps[MapManager::Type::Join].value()->id, key);
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_map_lookup_elem, loc, true);
  return call;
}

Value *IRBuilderBPF::CreateMapLookupElem(Value *ctx,
                                         Map &map,
                                         Value *key,
                                         const location &loc)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());
  int mapid = bpftrace_.maps[map.ident].value()->id;
  return CreateMapLookupElem(ctx, mapid, key, map.type, loc);
}

Value *IRBuilderBPF::CreateMapLookupElem(Value *ctx,
                                         int mapid,
                                         Value *key,
                                         SizedType &type,
                                         const location &loc)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());
  CallInst *call = createMapLookup(mapid, key);

  // Check if result == 0
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(), "lookup_success", parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(), "lookup_failure", parent);
  BasicBlock *lookup_merge_block = BasicBlock::Create(module_.getContext(), "lookup_merge", parent);

  AllocaInst *value = CreateAllocaBPF(type, "lookup_elem_val");
  Value *condition = CreateICmpNE(
      CreateIntCast(call, getInt8PtrTy(), true),
      ConstantExpr::getCast(Instruction::IntToPtr, getInt64(0), getInt8PtrTy()),
      "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);
  if (needMemcpy(type))
    CREATE_MEMCPY(value, call, type.GetSize(), 1);
  else
  {
    assert(value->getType()->isPointerTy() &&
           (value->getType()->getElementType() == getInt64Ty()));
    // createMapLookup  returns an u8*
    auto *cast = CreatePointerCast(call, value->getType(), "cast");
    CreateStore(CreateLoad(getInt64Ty(), cast), value);
  }
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_failure_block);
  if (needMemcpy(type))
    CREATE_MEMSET(value, getInt8(0), type.GetSize(), 1);
  else
    CreateStore(getInt64(0), value);
  CreateHelperError(ctx, getInt32(0), libbpf::BPF_FUNC_map_lookup_elem, loc);
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_merge_block);
  if (needMemcpy(type))
    return value;

  Value *ret = CreateLoad(value);
  CreateLifetimeEnd(value);
  return ret;
}

void IRBuilderBPF::CreateMapUpdateElem(Value *ctx,
                                       Map &map,
                                       Value *key,
                                       Value *val,
                                       const location &loc)
{
  Value *map_ptr = CreateBpfPseudoCallId(map);

  assert(ctx && ctx->getType() == getInt8PtrTy());
  assert(key->getType()->isPointerTy());
  assert(val->getType()->isPointerTy());

  Value *flags = getInt64(0);

  // int map_update_elem(struct bpf_map * map, void *key, void * value, u64
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
  CallInst *call = createCall(update_func,
                              { map_ptr, key, val, flags },
                              "update_elem");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_map_update_elem, loc);
}

void IRBuilderBPF::CreateMapDeleteElem(Value *ctx,
                                       Map &map,
                                       Value *key,
                                       const location &loc)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());
  assert(key->getType()->isPointerTy());
  Value *map_ptr = CreateBpfPseudoCallId(map);

  // int map_delete_elem(&map, &key)
  // Return: 0 on success or negative error
  FunctionType *delete_func_type = FunctionType::get(
      getInt64Ty(), { map_ptr->getType(), key->getType() }, false);
  PointerType *delete_func_ptr_type = PointerType::get(delete_func_type, 0);
  Constant *delete_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_map_delete_elem),
      delete_func_ptr_type);
  CallInst *call = createCall(delete_func, { map_ptr, key }, "delete_elem");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_map_delete_elem, loc);
}

void IRBuilderBPF::CreateProbeRead(Value *ctx,
                                   Value *dst,
                                   size_t size,
                                   Value *src,
                                   AddrSpace as,
                                   const location &loc)
{
  return CreateProbeRead(ctx, dst, getInt32(size), src, as, loc);
}

void IRBuilderBPF::CreateProbeRead(Value *ctx,
                                   Value *dst,
                                   llvm::Value *size,
                                   Value *src,
                                   AddrSpace as,
                                   const location &loc)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());
  assert(size && size->getType()->getIntegerBitWidth() <= 32);
  size = CreateIntCast(size, getInt32Ty(), false);

  // int bpf_probe_read(void *dst, int size, void *src)
  // Return: 0 on success or negative error

  auto read_fn = selectProbeReadHelper(as, false);

  FunctionType *proberead_func_type = FunctionType::get(
      getInt64Ty(), { dst->getType(), getInt32Ty(), src->getType() }, false);
  PointerType *proberead_func_ptr_type = PointerType::get(proberead_func_type, 0);
  Constant *proberead_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                   getInt64(read_fn),
                                                   proberead_func_ptr_type);
  CallInst *call = createCall(proberead_func,
                              { dst, size, src },
                              probeReadHelperName(read_fn));
  CreateHelperErrorCond(ctx, call, read_fn, loc);
}

Constant *IRBuilderBPF::createProbeReadStrFn(llvm::Type *dst,
                                             llvm::Type *src,
                                             AddrSpace as)
{
  assert(src && (src->isIntegerTy() || src->isPointerTy()));
  // int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
  FunctionType *probereadstr_func_type = FunctionType::get(
      getInt64Ty(), { dst, getInt32Ty(), src }, false);
  PointerType *probereadstr_func_ptr_type = PointerType::get(
      probereadstr_func_type, 0);
  return ConstantExpr::getCast(Instruction::IntToPtr,
                               getInt64(selectProbeReadHelper(as, true)),
                               probereadstr_func_ptr_type);
}

CallInst *IRBuilderBPF::CreateProbeReadStr(Value *ctx,
                                           AllocaInst *dst,
                                           size_t size,
                                           Value *src,
                                           AddrSpace as,
                                           const location &loc)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());
  return CreateProbeReadStr(ctx, dst, getInt32(size), src, as, loc);
}

CallInst *IRBuilderBPF::CreateProbeReadStr(Value *ctx,
                                           Value *dst,
                                           size_t size,
                                           Value *src,
                                           AddrSpace as,
                                           const location &loc)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());
  Constant *fn = createProbeReadStrFn(dst->getType(), src->getType(), as);
  auto read_fn = selectProbeReadHelper(as, true);
  CallInst *call = createCall(fn,
                              { dst, getInt32(size), src },
                              probeReadHelperName(read_fn));
  CreateHelperErrorCond(ctx, call, read_fn, loc);
  return call;
}

CallInst *IRBuilderBPF::CreateProbeReadStr(Value *ctx,
                                           AllocaInst *dst,
                                           llvm::Value *size,
                                           Value *src,
                                           AddrSpace as,
                                           const location &loc)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());
  assert(dst && dst->getAllocatedType()->isArrayTy() &&
         dst->getAllocatedType()->getArrayElementType() == getInt8Ty());
  assert(size && size->getType()->isIntegerTy());

  auto *size_i32 = CreateIntCast(size, getInt32Ty(), false);

  Constant *fn = createProbeReadStrFn(dst->getType(), src->getType(), as);
  auto read_fn = selectProbeReadHelper(as, true);
  CallInst *call = createCall(fn,
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
  assert(ctx && ctx->getType() == getInt8PtrTy());
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

  if (argument->valid & BCC_USDT_ARGUMENT_CONSTANT)
  {
    // Correctly sign extend and convert to a 64-bit int
    return CreateIntCast(getIntN(abs_size * 8, argument->constant),
                         getInt64Ty(),
                         argument->size < 0);
  }

  if (argument->valid & BCC_USDT_ARGUMENT_INDEX_REGISTER_NAME &&
      !(argument->valid & BCC_USDT_ARGUMENT_BASE_REGISTER_NAME))
  {
    // Invalid combination??
    LOG(ERROR) << "index register set without base register;"
               << " this case is not yet handled";
  }
  Value *result = nullptr;
  if (argument->valid & BCC_USDT_ARGUMENT_BASE_REGISTER_NAME) {
    int offset = 0;
    offset = arch::offset(argument->base_register_name);
    if (offset < 0)
    {
      LOG(FATAL) << "offset for register " << argument->base_register_name
                 << " not known";
    }


    // bpftrace's args are internally represented as 64 bit integers. However,
    // the underlying argument (of the target program) may be less than 64
    // bits. So we must be careful to zero out unused bits.
    Value* reg = CreateGEP(ctx, getInt64(offset * sizeof(uintptr_t)), "load_register");
    AllocaInst *dst = CreateAllocaBPF(builtin.type, builtin.ident);
    Value *index_offset = nullptr;
    if (argument->valid & BCC_USDT_ARGUMENT_INDEX_REGISTER_NAME)
    {
      int ioffset = arch::offset(argument->index_register_name);
      if (ioffset < 0)
      {
        LOG(FATAL) << "offset for register " << argument->index_register_name
                   << " not known";
      }
      index_offset = CreateGEP(ctx,
                               getInt64(ioffset * sizeof(uintptr_t)),
                               "load_register");
      index_offset = CreateLoad(getInt64Ty(), index_offset);
      if (argument->valid & BCC_USDT_ARGUMENT_SCALE)
      {
        index_offset = CreateMul(index_offset, getInt64(argument->scale));
      }
    }
    if (argument->valid & BCC_USDT_ARGUMENT_DEREF_OFFSET) {
      Value *ptr = CreateAdd(CreateLoad(getInt64Ty(), reg),
                             getInt64(argument->deref_offset));
      if (index_offset)
      {
        ptr = CreateAdd(ptr, index_offset);
      }
      CreateProbeRead(ctx, dst, abs_size, ptr, as, loc);
      result = CreateLoad(getIntNTy(abs_size * 8), dst);
    }
    else
    {
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
  assert(ctx && ctx->getType() == getInt8PtrTy());
  struct bcc_usdt_argument argument;

  void *usdt;

  if (pid) {
    //FIXME use attach_point->target when iovisor/bcc#2064 is merged
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
                            &argument) != 0)
  {
    LOG(ERROR) << "couldn't get argument " << arg_num << " for "
               << attach_point->target << ":" << attach_point->ns << ":"
               << attach_point->func;
    exit(-2);
  }

  Value *result = CreateUSDTReadArgument(ctx, &argument, builtin, as, loc);

  bcc_usdt_close(usdt);
  return result;
}

Value *IRBuilderBPF::CreateStrcmp(Value *ctx,
                                  Value *val,
                                  AddrSpace as,
                                  std::string str,
                                  const location &loc,
                                  bool inverse)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());
  auto cmpAmount = strlen(str.c_str()) + 1;
  return CreateStrncmp(ctx, val, as, str, cmpAmount, loc, inverse);
}

Value *IRBuilderBPF::CreateStrncmp(Value *ctx __attribute__((unused)),
                                   Value *val,
                                   AddrSpace as __attribute__((unused)),
                                   std::string str,
                                   uint64_t n,
                                   const location &loc __attribute__((unused)),
                                   bool inverse)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());
  PointerType *valp = cast<PointerType>(val->getType());
#ifndef NDEBUG
  assert(valp->getElementType()->isArrayTy() &&
         valp->getElementType()->getArrayElementType() == getInt8Ty());
#endif

  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *str_ne = BasicBlock::Create(module_.getContext(), "strcmp.false", parent);
  AllocaInst *store = CreateAllocaBPF(getInt1Ty(), "strcmp.result");

  CreateStore(getInt1(!inverse), store);

  // If the size of array is smaller than n, the condition is always false
  if (valp->getElementType()->getArrayNumElements() >= n)
  {
    const char *c_str = str.c_str();
    for (size_t i = 0; i < n; i++)
    {
      BasicBlock *char_eq = BasicBlock::Create(module_.getContext(),
                                               "strcmp.loop",
                                               parent);

      auto *ptr = CreateGEP(val, { getInt32(0), getInt32(i) });
      Value *l = CreateLoad(getInt8Ty(), ptr);
      Value *r = getInt8(c_str[i]);
      Value *cmp = CreateICmpNE(l, r, "strcmp.cmp");
      CreateCondBr(cmp, str_ne, char_eq);
      SetInsertPoint(char_eq);
    }
  }

  CreateStore(getInt1(inverse), store);
  CreateBr(str_ne);

  SetInsertPoint(str_ne);
  Value *result = CreateLoad(store);
  CreateLifetimeEnd(store);
  result = CreateIntCast(result, getInt64Ty(), false);
  return result;
}

Value *IRBuilderBPF::CreateStrcmp(Value *ctx,
                                  Value *val1,
                                  AddrSpace as1,
                                  Value *val2,
                                  AddrSpace as2,
                                  const location &loc,
                                  bool inverse)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());
  return CreateStrncmp(
      ctx, val1, as1, val2, as2, bpftrace_.strlen_, loc, inverse);
}

Value *IRBuilderBPF::CreateStrncmp(Value *ctx,
                                   Value *val1,
                                   AddrSpace as1,
                                   Value *val2,
                                   AddrSpace as2,
                                   uint64_t n,
                                   const location &loc,
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

#ifndef NDEBUG
  PointerType *val1p = cast<PointerType>(val1->getType());
  PointerType *val2p = cast<PointerType>(val2->getType());

  assert(val1p->getElementType()->isArrayTy() &&
         val1p->getElementType()->getArrayElementType() == getInt8Ty());

  assert(val2p->getElementType()->isArrayTy() &&
         val2p->getElementType()->getArrayElementType() == getInt8Ty());
#endif

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

  AllocaInst *val_l = CreateAllocaBPF(getInt8Ty(), "strcmp.char_l");
  AllocaInst *val_r = CreateAllocaBPF(getInt8Ty(), "strcmp.char_r");
  for (size_t i = 0; i < n; i++)
  {
    BasicBlock *char_eq = BasicBlock::Create(module_.getContext(),
                                             "strcmp.loop",
                                             parent);
    BasicBlock *loop_null_check = BasicBlock::Create(module_.getContext(),
                                                     "strcmp.loop_null_cmp",
                                                     parent);

    auto *ptr1 = CreateGEP(val1, { getInt32(0), getInt32(i) });
    CreateProbeRead(ctx, val_l, 1, ptr1, as1, loc);
    Value *l = CreateLoad(getInt8Ty(), val_l);

    auto *ptr2 = CreateGEP(val2, { getInt32(0), getInt32(i) });
    CreateProbeRead(ctx, val_r, 1, ptr2, as2, loc);
    Value *r = CreateLoad(getInt8Ty(), val_r);

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

  Value *result = CreateLoad(store);
  CreateLifetimeEnd(store);
  CreateLifetimeEnd(val_l);
  CreateLifetimeEnd(val_r);
  result = CreateIntCast(result, getInt64Ty(), false);

  return result;
}

CallInst *IRBuilderBPF::CreateGetNs(bool boot_time)
{
  // u64 ktime_get_ns()
  // Return: current ktime

  auto fn = boot_time ? libbpf::BPF_FUNC_ktime_get_boot_ns
                      : libbpf::BPF_FUNC_ktime_get_ns;

  FunctionType *gettime_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *gettime_func_ptr_type = PointerType::get(gettime_func_type, 0);
  Constant *gettime_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                 getInt64(fn),
                                                 gettime_func_ptr_type);
  return createCall(gettime_func, {}, "get_ns");
}

CallInst *IRBuilderBPF::CreateGetPidTgid()
{
  // u64 bpf_get_current_pid_tgid(void)
  // Return: current->tgid << 32 | current->pid
  FunctionType *getpidtgid_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *getpidtgid_func_ptr_type = PointerType::get(getpidtgid_func_type, 0);
  Constant *getpidtgid_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_get_current_pid_tgid),
      getpidtgid_func_ptr_type);
  return createCall(getpidtgid_func, {}, "get_pid_tgid");
}

CallInst *IRBuilderBPF::CreateGetCurrentCgroupId()
{
  // u64 bpf_get_current_cgroup_id(void)
  // Return: 64-bit cgroup-v2 id
  FunctionType *getcgroupid_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *getcgroupid_func_ptr_type = PointerType::get(
      getcgroupid_func_type, 0);
  Constant *getcgroupid_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_get_current_cgroup_id),
      getcgroupid_func_ptr_type);
  return createCall(getcgroupid_func, {}, "get_cgroup_id");
}

CallInst *IRBuilderBPF::CreateGetUidGid()
{
  // u64 bpf_get_current_uid_gid(void)
  // Return: current_gid << 32 | current_uid
  FunctionType *getuidgid_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *getuidgid_func_ptr_type = PointerType::get(getuidgid_func_type, 0);
  Constant *getuidgid_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_get_current_uid_gid),
      getuidgid_func_ptr_type);
  return createCall(getuidgid_func, {}, "get_uid_gid");
}

CallInst *IRBuilderBPF::CreateGetCpuId()
{
  // u32 bpf_raw_smp_processor_id(void)
  // Return: SMP processor ID
  FunctionType *getcpuid_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *getcpuid_func_ptr_type = PointerType::get(getcpuid_func_type, 0);
  Constant *getcpuid_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_get_smp_processor_id),
      getcpuid_func_ptr_type);
  return createCall(getcpuid_func, {}, "get_cpu_id");
}

CallInst *IRBuilderBPF::CreateGetCurrentTask()
{
  // u64 bpf_get_current_task(void)
  // Return: current task_struct
  FunctionType *getcurtask_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *getcurtask_func_ptr_type = PointerType::get(getcurtask_func_type, 0);
  Constant *getcurtask_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_get_current_task),
      getcurtask_func_ptr_type);
  return createCall(getcurtask_func, {}, "get_cur_task");
}

CallInst *IRBuilderBPF::CreateGetRandom()
{
  // u64 bpf_get_prandom_u32(void)
  // Return: random
  FunctionType *getrandom_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *getrandom_func_ptr_type = PointerType::get(getrandom_func_type, 0);
  Constant *getrandom_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_get_prandom_u32),
      getrandom_func_ptr_type);
  return createCall(getrandom_func, {}, "get_random");
}

CallInst *IRBuilderBPF::CreateGetStackId(Value *ctx,
                                         bool ustack,
                                         StackType stack_type,
                                         const location &loc)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());

  Value *map_ptr = CreateBpfPseudoCallId(
      bpftrace_.maps[stack_type].value()->id);

  int flags = 0;
  if (ustack)
    flags |= (1<<8);
  Value *flags_val = getInt64(flags);

  // int bpf_get_stackid(struct pt_regs *ctx, struct bpf_map *map, u64 flags)
  // Return: >= 0 stackid on success or negative error
  FunctionType *getstackid_func_type = FunctionType::get(
      getInt64Ty(),
      { getInt8PtrTy(), map_ptr->getType(), getInt64Ty() },
      false);
  PointerType *getstackid_func_ptr_type = PointerType::get(getstackid_func_type, 0);
  Constant *getstackid_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_get_stackid),
      getstackid_func_ptr_type);
  CallInst *call = createCall(getstackid_func,
                              { ctx, map_ptr, flags_val },
                              "get_stackid");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_get_stackid, loc);
  return call;
}

void IRBuilderBPF::CreateGetCurrentComm(Value *ctx,
                                        AllocaInst *buf,
                                        size_t size,
                                        const location &loc)
{
  assert(buf->getType()->getElementType()->isArrayTy() &&
         buf->getType()->getElementType()->getArrayNumElements() >= size &&
         buf->getType()->getElementType()->getArrayElementType() ==
             getInt8Ty());

  // int bpf_get_current_comm(char *buf, int size_of_buf)
  // Return: 0 on success or negative error
  FunctionType *getcomm_func_type = FunctionType::get(
      getInt64Ty(), { buf->getType(), getInt64Ty() }, false);
  PointerType *getcomm_func_ptr_type = PointerType::get(getcomm_func_type, 0);
  Constant *getcomm_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_get_current_comm),
      getcomm_func_ptr_type);
  CallInst *call = createCall(getcomm_func,
                              { buf, getInt64(size) },
                              "get_comm");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_get_current_comm, loc);
}

void IRBuilderBPF::CreatePerfEventOutput(Value *ctx, Value *data, size_t size)
{
  assert(ctx && ctx->getType() == getInt8PtrTy());
  assert(data && data->getType()->isPointerTy());

  Value *map_ptr = CreateBpfPseudoCallId(
      bpftrace_.maps[MapManager::Type::PerfEvent].value()->id);

  Value *flags_val = getInt64(BPF_F_CURRENT_CPU);
  Value *size_val = getInt64(size);

  // int bpf_perf_event_output(struct pt_regs *ctx, struct bpf_map *map,
  //                           u64 flags, void *data, u64 size)
  FunctionType *perfoutput_func_type = FunctionType::get(getInt64Ty(),
                                                         { getInt8PtrTy(),
                                                           map_ptr->getType(),
                                                           getInt64Ty(),
                                                           data->getType(),
                                                           getInt64Ty() },
                                                         false);

  PointerType *perfoutput_func_ptr_type = PointerType::get(perfoutput_func_type, 0);
  Constant *perfoutput_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_perf_event_output),
      perfoutput_func_ptr_type);
  createCall(perfoutput_func,
             { ctx, map_ptr, flags_val, data, size_val },
             "perf_event_output");
}

void IRBuilderBPF::CreateSignal(Value *ctx, Value *sig, const location &loc)
{
  // int bpf_send_signal(u32 sig)
  // Return: 0 or error
  FunctionType *signal_func_type = FunctionType::get(
      getInt64Ty(),
      {getInt32Ty()},
      false);
  PointerType *signal_func_ptr_type = PointerType::get(signal_func_type, 0);
  Constant *signal_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_send_signal),
      signal_func_ptr_type);
  CallInst *call = createCall(signal_func, { sig }, "signal");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_send_signal, loc);
}

void IRBuilderBPF::CreateOverrideReturn(Value *ctx, Value *rc)
{
  // int bpf_override_return(struct pt_regs *regs, u64 rc)
  // Return: 0
  FunctionType *override_func_type = FunctionType::get(
      getInt64Ty(), { getInt8PtrTy(), getInt64Ty() }, false);
  PointerType *override_func_ptr_type = PointerType::get(override_func_type, 0);
  Constant *override_func = ConstantExpr::getCast(Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_override_return),
      override_func_ptr_type);
  createCall(override_func, { ctx, rc }, "override");
}

Value *IRBuilderBPF::CreatKFuncArg(Value *ctx,
                                   SizedType &type,
                                   std::string &name)
{
  ctx = CreatePointerCast(ctx, getInt64Ty()->getPointerTo());
  Value *expr = CreateLoad(getInt64Ty(),
                           CreateGEP(ctx, getInt64(type.kfarg_idx)),
                           name);

  // LLVM 7.0 <= does not have CreateLoad(*Ty, *Ptr, isVolatile, Name),
  // so call setVolatile() manually
  dyn_cast<LoadInst>(expr)->setVolatile(true);
  return expr;
}

static bool return_zero_if_err(libbpf::bpf_func_id func_id)
{
  switch (func_id)
  {
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
  assert(ctx && ctx->getType() == getInt8PtrTy());
  assert(return_value && return_value->getType() == getInt32Ty());

  if (bpftrace_.helper_check_level_ == 0 ||
      (bpftrace_.helper_check_level_ == 1 && return_zero_if_err(func_id)))
    return;

  int error_id = helper_error_id_++;
  bpftrace_.resources.helper_error_info[error_id] = { .func_id = func_id,
                                                      .loc = loc };

  auto elements = AsyncEvent::HelperError().asLLVMType(*this);
  StructType *helper_error_struct = GetStructType("helper_error_t",
                                                  elements,
                                                  true);
  AllocaInst *buf = CreateAllocaBPF(helper_error_struct, "helper_error_t");
  CreateStore(GetIntSameSize(asyncactionint(AsyncAction::helper_error),
                             elements.at(0)),
              CreateGEP(buf, { getInt64(0), getInt32(0) }));
  CreateStore(GetIntSameSize(error_id, elements.at(1)),
              CreateGEP(buf, { getInt64(0), getInt32(1) }));
  CreateStore(return_value, CreateGEP(buf, { getInt64(0), getInt32(2) }));

  auto &layout = module_.getDataLayout();
  auto struct_size = layout.getTypeAllocSize(helper_error_struct);
  CreatePerfEventOutput(ctx, buf, struct_size);
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
  assert(ctx && ctx->getType() == getInt8PtrTy());
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
                              AllocaInst *buf,
                              Value *path,
                              const location &loc)
{
  // int bpf_d_path(struct path *path, char *buf, u32 sz)
  // Return: 0 or error
  FunctionType *d_path_func_type = FunctionType::get(
      getInt64Ty(), { getInt8PtrTy(), buf->getType(), getInt32Ty() }, false);
  PointerType *d_path_func_ptr_type = PointerType::get(d_path_func_type, 0);
  Constant *d_path_func = ConstantExpr::getCast(Instruction::IntToPtr,
                                                getInt64(
                                                    libbpf::BPF_FUNC_d_path),
                                                d_path_func_ptr_type);
  CallInst *call = createCall(d_path_func,
                              { path, buf, getInt32(bpftrace_.strlen_) },
                              "d_path");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_d_path, loc);
}

void IRBuilderBPF::CreateSeqPrintf(Value *ctx,
                                   Value *fmt,
                                   Value *fmt_size,
                                   AllocaInst *data,
                                   Value *data_len,
                                   const location &loc)
{
  // long bpf_seq_printf(struct seq_file *m, const char *fmt, __u32 fmt_size,
  //                     const void *data, __u32 data_len)
  // Return: 0 or error
  FunctionType *seq_printf_func_type = FunctionType::get(getInt64Ty(),
                                                         { getInt64Ty(),
                                                           getInt8PtrTy(),
                                                           getInt32Ty(),
                                                           getInt8PtrTy(),
                                                           getInt32Ty() },
                                                         false);
  PointerType *seq_printf_func_ptr_type = PointerType::get(seq_printf_func_type,
                                                           0);
  Constant *seq_printf_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_seq_printf),
      seq_printf_func_ptr_type);

  ctx = CreatePointerCast(ctx, getInt8Ty()->getPointerTo());
  Value *meta = CreateLoad(getInt64Ty()->getPointerTo(),
                           CreateGEP(ctx, getInt64(0)),
                           "meta");
  dyn_cast<LoadInst>(meta)->setVolatile(true);

  Value *seq = CreateLoad(getInt64Ty(), CreateGEP(meta, getInt64(0)), "seq");

  CallInst *call = createCall(seq_printf_func,
                              { seq, fmt, fmt_size, data, data_len },
                              "seq_printf");
  CreateHelperErrorCond(ctx, call, libbpf::BPF_FUNC_seq_printf, loc);
}

} // namespace ast
} // namespace bpftrace
