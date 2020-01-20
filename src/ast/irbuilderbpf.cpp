#include <iostream>

#include "irbuilderbpf.h"
#include "bcc_usdt.h"
#include "arch/arch.h"
#include "utils.h"

#include <llvm/IR/Module.h>

namespace libbpf {
#undef __BPF_FUNC_MAPPER
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {
namespace ast {

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

AllocaInst *IRBuilderBPF::CreateAllocaBPF(llvm::Type *ty, llvm::Value *arraysize, const std::string &name)
{
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock &entry_block = parent->getEntryBlock();

  auto ip = saveIP();
  if (entry_block.empty())
    SetInsertPoint(&entry_block);
  else
    SetInsertPoint(&entry_block.front());
  AllocaInst *alloca = CreateAlloca(ty, arraysize, name);
  restoreIP(ip);

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
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock &entry_block = parent->getEntryBlock();

  auto ip = saveIP();
  if (entry_block.empty())
    SetInsertPoint(&entry_block);
  else
    SetInsertPoint(&entry_block.front());

  llvm::Type *ty = GetType(stype);
  AllocaInst *alloca = CreateAllocaBPF(ty, nullptr, name);

  if (!stype.IsArray())
  {
    CreateStore(getInt64(0), alloca);
  }
  else
  {
    CreateMemSet(alloca, getInt64(0), stype.size, 1);
  }

  restoreIP(ip);

  CreateLifetimeStart(alloca);
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

llvm::ConstantInt *IRBuilderBPF::GetIntSameSize(uint64_t C, llvm::Value *expr)
{
  unsigned size = expr->getType()->getIntegerBitWidth();
  return getIntN(size, C);
}

llvm::Type *IRBuilderBPF::GetType(const SizedType &stype)
{
  llvm::Type *ty;
  if (stype.IsArray())
  {
    ty = ArrayType::get(getInt8Ty(), stype.size);
  }
  else
  {
    switch (stype.size)
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
        std::cerr << stype.size << " is not a valid type size for GetType" << std::endl;
        abort();
    }
  }
  return ty;
}

CallInst *IRBuilderBPF::CreateBpfPseudoCall(int mapfd)
{
  Function *pseudo_func = module_.getFunction("llvm.bpf.pseudo");
  return CreateCall(pseudo_func, {getInt64(BPF_PSEUDO_MAP_FD), getInt64(mapfd)}, "pseudo");
}

CallInst *IRBuilderBPF::CreateBpfPseudoCall(Map &map)
{
  int mapfd = bpftrace_.maps_[map.ident]->mapfd_;
  return CreateBpfPseudoCall(mapfd);
}

CallInst *IRBuilderBPF::createMapLookup(int mapfd, AllocaInst *key)
{
  Value *map_ptr = CreateBpfPseudoCall(mapfd);
  // void *map_lookup_elem(&map, &key)
  // Return: Map value or NULL
  FunctionType *lookup_func_type = FunctionType::get(
      getInt8PtrTy(),
      {getInt8PtrTy(), getInt8PtrTy()},
      false);
  PointerType *lookup_func_ptr_type = PointerType::get(lookup_func_type, 0);
  Constant *lookup_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_map_lookup_elem),
      lookup_func_ptr_type);
  return CreateCall(lookup_func, { map_ptr, key }, "lookup_elem");
}

CallInst *IRBuilderBPF::CreateGetJoinMap(Value *ctx __attribute__((unused)))
{
  AllocaInst *key = CreateAllocaBPF(getInt32Ty(), "key");
  CreateStore(getInt32(0), key);

  CallInst *call = createMapLookup(bpftrace_.join_map_->mapfd_, key);
  return call;
}

Value *IRBuilderBPF::CreateMapLookupElem(Map &map, AllocaInst *key) {
  int mapfd = bpftrace_.maps_[map.ident]->mapfd_;
  return CreateMapLookupElem(mapfd, key, map.type);
}

Value *IRBuilderBPF::CreateMapLookupElem(int mapfd, AllocaInst *key, SizedType &type)
{
  CallInst *call = createMapLookup(mapfd, key);

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

  bool is_array = (type.type == Type::string ||
                   (type.type == Type::cast && !type.is_pointer) ||
                   type.type == Type::inet);

  SetInsertPoint(lookup_success_block);
  if (is_array)
    CREATE_MEMCPY(value, call, type.size, 1);
  else
    CreateStore(CreateLoad(getInt64Ty(), call), value);
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_failure_block);
  if (is_array)
    CreateMemSet(value, getInt8(0), type.size, 1);
  else
    CreateStore(getInt64(0), value);
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_merge_block);
  if (is_array)
    return value;

  return CreateLoad(value);
}

void IRBuilderBPF::CreateMapUpdateElem(Map &map, AllocaInst *key, Value *val)
{
  Value *map_ptr = CreateBpfPseudoCall(map);
  Value *flags = getInt64(0);

  // int map_update_elem(&map, &key, &value, flags)
  // Return: 0 on success or negative error
  FunctionType *update_func_type = FunctionType::get(
      getInt64Ty(),
      {getInt8PtrTy(), getInt8PtrTy(), getInt8PtrTy(), getInt64Ty()},
      false);
  PointerType *update_func_ptr_type = PointerType::get(update_func_type, 0);
  Constant *update_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_map_update_elem),
      update_func_ptr_type);
  CreateCall(update_func, {map_ptr, key, val, flags}, "update_elem");
}

void IRBuilderBPF::CreateMapDeleteElem(Map &map, AllocaInst *key)
{
  Value *map_ptr = CreateBpfPseudoCall(map);

  // int map_delete_elem(&map, &key)
  // Return: 0 on success or negative error
  FunctionType *delete_func_type = FunctionType::get(
      getInt64Ty(),
      {getInt8PtrTy(), getInt8PtrTy()},
      false);
  PointerType *delete_func_ptr_type = PointerType::get(delete_func_type, 0);
  Constant *delete_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_map_delete_elem),
      delete_func_ptr_type);
  CreateCall(delete_func, {map_ptr, key}, "delete_elem");
}

void IRBuilderBPF::CreateProbeRead(AllocaInst *dst, size_t size, Value *src)
{
  // int bpf_probe_read(void *dst, int size, void *src)
  // Return: 0 on success or negative error
  FunctionType *proberead_func_type = FunctionType::get(
      getInt64Ty(),
      {getInt8PtrTy(), getInt64Ty(), getInt8PtrTy()},
      false);
  PointerType *proberead_func_ptr_type = PointerType::get(proberead_func_type, 0);
  Constant *proberead_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_probe_read),
      proberead_func_ptr_type);
  CreateCall(proberead_func, {dst, getInt64(size), src}, "probe_read");
}

CallInst *IRBuilderBPF::CreateProbeReadStr(AllocaInst *dst, size_t size, Value *src)
{
  return CreateProbeReadStr(dst, getInt64(size), src);
}

CallInst *IRBuilderBPF::CreateProbeReadStr(AllocaInst *dst, llvm::Value *size, Value *src)
{
  // int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
  FunctionType *probereadstr_func_type = FunctionType::get(
      getInt64Ty(),
      {getInt8PtrTy(), getInt64Ty(), getInt8PtrTy()},
      false);
  PointerType *probereadstr_func_ptr_type = PointerType::get(probereadstr_func_type, 0);
  Constant *probereadstr_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_probe_read_str),
      probereadstr_func_ptr_type);
  return CreateCall(probereadstr_func, {dst, size, src}, "probe_read_str");
}

CallInst *IRBuilderBPF::CreateProbeReadStr(Value *dst, size_t size, Value *src)
{
  // int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
  FunctionType *probereadstr_func_type = FunctionType::get(
      getInt64Ty(),
      {getInt8PtrTy(), getInt64Ty(), getInt8PtrTy()},
      false);
  PointerType *probereadstr_func_ptr_type = PointerType::get(probereadstr_func_type, 0);
  Constant *probereadstr_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_probe_read_str),
      probereadstr_func_ptr_type);
  return CreateCall(probereadstr_func, {dst, getInt64(size), src}, "map_read_str");
}

Value *IRBuilderBPF::CreateUSDTReadArgument(Value *ctx, struct bcc_usdt_argument *argument, Builtin &builtin) {
  // TODO (mmarchini): Handle base + index * scale addressing.
  // https://github.com/iovisor/bcc/pull/988
  if (argument->valid & BCC_USDT_ARGUMENT_INDEX_REGISTER_NAME)
    std::cerr << "index register is not handled yet [" << argument->index_register_name << "]" << std::endl;
  if (argument->valid & BCC_USDT_ARGUMENT_SCALE)
    std::cerr << "scale is not handled yet [" << argument->scale << "]" << std::endl;
  if (argument->valid & BCC_USDT_ARGUMENT_DEREF_IDENT)
    std::cerr << "defer ident is not handled yet [" << argument->deref_ident << "]" << std::endl;

  if (argument->valid & BCC_USDT_ARGUMENT_CONSTANT)
    return getInt64(argument->constant);

  Value *result = nullptr;
  if (argument->valid & BCC_USDT_ARGUMENT_BASE_REGISTER_NAME) {
    int offset = 0;
    offset = arch::offset(argument->base_register_name);
    Value* reg = CreateGEP(ctx, getInt64(offset * sizeof(uintptr_t)), "load_register");
    AllocaInst *dst = CreateAllocaBPF(builtin.type, builtin.ident);
    CreateProbeRead(dst, builtin.type.size, reg);
    result = CreateLoad(dst);
    if (argument->valid & BCC_USDT_ARGUMENT_DEREF_OFFSET) {
      Value *ptr = CreateAdd(
          result,
          getInt64(argument->deref_offset));
      CreateProbeRead(dst, builtin.type.size, ptr);
      result = CreateLoad(dst);
    }
    CreateLifetimeEnd(dst);
  }
  return result;
}

Value *IRBuilderBPF::CreateUSDTReadArgument(Value *ctx, AttachPoint *attach_point, int arg_num, Builtin &builtin, int pid)
{
  struct bcc_usdt_argument argument;

  void *usdt;

  if (pid) {
    //FIXME use attach_point->target when iovisor/bcc#2064 is merged
    usdt = bcc_usdt_new_frompid(pid, nullptr);
  } else {
    usdt = bcc_usdt_new_frompath(attach_point->target.c_str());
  }

  if (usdt == nullptr) {
    std::cerr << "failed to initialize usdt context for probe " << attach_point->target << std::endl;
    exit(-1);
  }

  std::string ns = std::get<USDT_PROVIDER_INDEX>(attach_point->usdt);
  std::string func = std::get<USDT_FNAME_INDEX>(attach_point->usdt);

  if (bcc_usdt_get_argument(usdt, ns.c_str(), func.c_str(), 0, arg_num, &argument) != 0) {
    std::cerr << "couldn't get argument " << arg_num << " for " << attach_point->target << ":"
              << attach_point->ns << ":" << attach_point->func << std::endl;
    exit(-2);
  }

  Value *result = CreateUSDTReadArgument(ctx, &argument, builtin);

  bcc_usdt_close(usdt);
  return result;
}

Value *IRBuilderBPF::CreateStrcmp(Value* val, std::string str, bool inverse) {
  auto cmpAmount = strlen(str.c_str()) + 1;
  return CreateStrncmp(val, str, cmpAmount, inverse);
}

Value *IRBuilderBPF::CreateStrncmp(Value* val, std::string str, uint64_t n, bool inverse) {
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *str_ne = BasicBlock::Create(module_.getContext(), "strcmp.false", parent);
  AllocaInst *store = CreateAllocaBPF(getInt8Ty(), "strcmp.result");

  CreateStore(getInt1(!inverse), store);

  const char *c_str = str.c_str();
  for (size_t i = 0; i < n; i++)
  {
    BasicBlock *char_eq = BasicBlock::Create(module_.getContext(), "strcmp.loop", parent);
    Value *ptr = CreateAdd(
        val,
        getInt64(i));
    Value *l = CreateLoad(getInt8Ty(), ptr);
    Value *r = getInt8(c_str[i]);
    Value *cmp = CreateICmpNE(l, r, "strcmp.cmp");
    CreateCondBr(cmp, str_ne, char_eq);
    SetInsertPoint(char_eq);
  }
  CreateStore(getInt1(inverse), store);
  CreateBr(str_ne);

  SetInsertPoint(str_ne);
  Value *result = CreateLoad(store);
  CreateLifetimeEnd(store);
  result = CreateIntCast(result, getInt64Ty(), false);
  return result;
}

Value *IRBuilderBPF::CreateStrcmp(Value* val1, Value* val2, bool inverse) {
  return CreateStrncmp(val1, val2, bpftrace_.strlen_, inverse);
}

Value *IRBuilderBPF::CreateStrncmp(Value* val1, Value* val2, uint64_t n, bool inverse) {
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
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *str_ne = BasicBlock::Create(module_.getContext(), "strcmp.false", parent);
  AllocaInst *store = CreateAllocaBPF(getInt8Ty(), "strcmp.result");
  BasicBlock *done = BasicBlock::Create(module_.getContext(), "strcmp.done", parent);

  CreateStore(getInt1(!inverse), store);

  Value *null_byte = getInt8(0);

  AllocaInst *val_l = CreateAllocaBPF(getInt8Ty(), "strcmp.char_l");
  AllocaInst *val_r = CreateAllocaBPF(getInt8Ty(), "strcmp.char_r");
  for (size_t i = 0; i < n; i++)
  {
    BasicBlock *char_eq = BasicBlock::Create(module_.getContext(), "strcmp.loop", parent);
    BasicBlock *loop_null_check = BasicBlock::Create(module_.getContext(), "strcmp.loop_null_cmp", parent);

    Value *ptr1 = CreateAdd(val1, getInt64(i));
    CreateProbeRead(val_l, 1, ptr1);
    Value *l = CreateLoad(getInt8Ty(), val_l);

    Value *ptr2 = CreateAdd(val2, getInt64(i));
    CreateProbeRead(val_r, 1, ptr2);
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

CallInst *IRBuilderBPF::CreateGetNs()
{
  // u64 ktime_get_ns()
  // Return: current ktime
  FunctionType *gettime_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *gettime_func_ptr_type = PointerType::get(gettime_func_type, 0);
  Constant *gettime_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_ktime_get_ns),
      gettime_func_ptr_type);
  return CreateCall(gettime_func, {}, "get_ns");
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
  return CreateCall(getpidtgid_func, {}, "get_pid_tgid");
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
  return CreateCall(getcgroupid_func, {}, "get_cgroup_id");
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
  return CreateCall(getuidgid_func, {}, "get_uid_gid");
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
  return CreateCall(getcpuid_func, {}, "get_cpu_id");
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
  return CreateCall(getcurtask_func, {}, "get_cur_task");
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
  return CreateCall(getrandom_func, {}, "get_random");
}

CallInst *IRBuilderBPF::CreateGetStackId(Value *ctx, bool ustack, StackType stack_type)
{
  assert(bpftrace_.stackid_maps_.count(stack_type) == 1);
  Value *map_ptr = CreateBpfPseudoCall(bpftrace_.stackid_maps_[stack_type]->mapfd_);

  int flags = 0;
  if (ustack)
    flags |= (1<<8);
  Value *flags_val = getInt64(flags);

  // int bpf_get_stackid(ctx, map, flags)
  // Return: >= 0 stackid on success or negative error
  FunctionType *getstackid_func_type = FunctionType::get(
      getInt64Ty(),
      {getInt8PtrTy(), getInt8PtrTy(), getInt64Ty()},
      false);
  PointerType *getstackid_func_ptr_type = PointerType::get(getstackid_func_type, 0);
  Constant *getstackid_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_get_stackid),
      getstackid_func_ptr_type);
  return CreateCall(getstackid_func, {ctx, map_ptr, flags_val}, "get_stackid");
}

void IRBuilderBPF::CreateGetCurrentComm(AllocaInst *buf, size_t size)
{
  // int bpf_get_current_comm(char *buf, int size_of_buf)
  // Return: 0 on success or negative error
  FunctionType *getcomm_func_type = FunctionType::get(
      getInt64Ty(),
      {getInt8PtrTy(), getInt64Ty()},
      false);
  PointerType *getcomm_func_ptr_type = PointerType::get(getcomm_func_type, 0);
  Constant *getcomm_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_get_current_comm),
      getcomm_func_ptr_type);
  CreateCall(getcomm_func, {buf, getInt64(size)}, "get_comm");
}

void IRBuilderBPF::CreatePerfEventOutput(Value *ctx, Value *data, size_t size)
{
  Value *map_ptr = CreateBpfPseudoCall(bpftrace_.perf_event_map_->mapfd_);

  Value *flags_val = CreateGetCpuId();
  Value *size_val = getInt64(size);

  // int bpf_perf_event_output(ctx, map, flags, data, size)
  FunctionType *perfoutput_func_type = FunctionType::get(
      getInt64Ty(),
      {
        getInt8PtrTy(),
        getInt64Ty(),
        getInt64Ty(),
        cast<PointerType>(data->getType()),
        getInt64Ty()
      },
      false);
  PointerType *perfoutput_func_ptr_type = PointerType::get(perfoutput_func_type, 0);
  Constant *perfoutput_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(libbpf::BPF_FUNC_perf_event_output),
      perfoutput_func_ptr_type);
  CreateCall(perfoutput_func, {ctx, map_ptr, flags_val, data, size_val}, "perf_event_output");
}

void IRBuilderBPF::CreateSignal(Value *sig)
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
  CreateCall(signal_func, {sig}, "signal");
}

} // namespace ast
} // namespace bpftrace
