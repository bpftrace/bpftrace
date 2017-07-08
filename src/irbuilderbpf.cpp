#include "irbuilderbpf.h"
#include "libbpf.h"

#include <llvm/IR/Module.h>

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

AllocaInst *IRBuilderBPF::CreateAllocaBPF(const SizedType &stype, const std::string &name)
{
  llvm::Type *ty;
  switch (stype.size)
  {
    case 8:
      ty = getInt64Ty();
      break;
    case 4:
      ty = getInt32Ty();
      break;
    default:
      abort();
  }
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock &entry_block = parent->getEntryBlock();
  if (entry_block.empty())
    return new AllocaInst(ty, name, &entry_block);
  else
    return new AllocaInst(ty, name, &entry_block.front());
}

AllocaInst *IRBuilderBPF::CreateAllocaMapKey(int bytes, const std::string &name)
{
  llvm::Type *ty = ArrayType::get(getInt8Ty(), bytes);
  Value *array_size = getInt64(bytes);
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock &entry_block = parent->getEntryBlock();
  if (entry_block.empty())
    return new AllocaInst(ty, name, &entry_block);
  else
    return new AllocaInst(ty, name, &entry_block.front());
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

LoadInst *IRBuilderBPF::CreateMapLookupElem(Map &map, AllocaInst *key)
{
  Value *map_ptr = CreateBpfPseudoCall(map);

  // void *map_lookup_elem(&map, &key)
  // Return: Map value or NULL
  FunctionType *lookup_func_type = FunctionType::get(
      getInt8PtrTy(),
      {getInt8PtrTy(), getInt8PtrTy()},
      false);
  PointerType *lookup_func_ptr_type = PointerType::get(lookup_func_type, 0);
  Constant *lookup_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(BPF_FUNC_map_lookup_elem),
      lookup_func_ptr_type);
  CallInst *call = CreateCall(lookup_func, {map_ptr, key}, "lookup_elem");

  // Check if result == 0
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(), "lookup_success", parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(), "lookup_failure", parent);
  BasicBlock *lookup_merge_block = BasicBlock::Create(module_.getContext(), "lookup_merge", parent);

  Value *value = CreateAllocaBPF(SizedType(Type::integer, 8), "lookup_elem_val");
  Value *condition = CreateICmpNE(
      CreateIntCast(call, getInt8PtrTy(), true),
      ConstantExpr::getCast(Instruction::IntToPtr, getInt64(0), getInt8PtrTy()),
      "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);
  SetInsertPoint(lookup_success_block);
  Value *loaded_value = CreateLoad(getInt64Ty(), call);
  CreateStore(loaded_value, value);
  CreateBr(lookup_merge_block);
  SetInsertPoint(lookup_failure_block);
  CreateStore(getInt64(0), value);
  CreateBr(lookup_merge_block);
  SetInsertPoint(lookup_merge_block);
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
      getInt64(BPF_FUNC_map_update_elem),
      update_func_ptr_type);
  CallInst *call = CreateCall(update_func, {map_ptr, key, val, flags}, "update_elem");
}

void IRBuilderBPF::CreateMapDeleteElem(Map &map, AllocaInst *key)
{
  Value *map_ptr = CreateBpfPseudoCall(map);
  Value *flags = getInt64(0);

  // int map_delete_elem(&map, &key)
  // Return: 0 on success or negative error
  FunctionType *delete_func_type = FunctionType::get(
      getInt64Ty(),
      {getInt8PtrTy(), getInt8PtrTy()},
      false);
  PointerType *delete_func_ptr_type = PointerType::get(delete_func_type, 0);
  Constant *delete_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(BPF_FUNC_map_delete_elem),
      delete_func_ptr_type);
  CallInst *call = CreateCall(delete_func, {map_ptr, key}, "delete_elem");
}

void IRBuilderBPF::CreateProbeRead(AllocaInst *dst, Value *size, Value *src)
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
      getInt64(BPF_FUNC_probe_read),
      proberead_func_ptr_type);
  CallInst *call = CreateCall(proberead_func, {dst, size, src}, "probe_read");
}

CallInst *IRBuilderBPF::CreateGetNs()
{
  // u64 ktime_get_ns()
  // Return: current ktime
  FunctionType *gettime_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *gettime_func_ptr_type = PointerType::get(gettime_func_type, 0);
  Constant *gettime_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(BPF_FUNC_ktime_get_ns),
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
      getInt64(BPF_FUNC_get_current_pid_tgid),
      getpidtgid_func_ptr_type);
  return CreateCall(getpidtgid_func, {}, "get_pid_tgid");
}

CallInst *IRBuilderBPF::CreateGetUidGid()
{
  // u64 bpf_get_current_uid_gid(void)
  // Return: current_gid << 32 | current_uid
  FunctionType *getuidgid_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *getuidgid_func_ptr_type = PointerType::get(getuidgid_func_type, 0);
  Constant *getuidgid_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(BPF_FUNC_get_current_uid_gid),
      getuidgid_func_ptr_type);
  return CreateCall(getuidgid_func, {}, "get_uid_gid");
}

CallInst *IRBuilderBPF::CreateGetStackId(Value *ctx, bool ustack)
{
  Value *map_ptr = CreateBpfPseudoCall(bpftrace_.stackid_map_->mapfd_);

  int flags = 0;
  if (ustack)
    flags |= (1<<8);
  Value *flags_val = getInt64(flags);

  // int bpf_get_stackid(ctx, map, flags)
  // Return: >= 0 stackid on success or negative error
  FunctionType *getstackid_func_type = FunctionType::get(
      getInt64Ty(),
      {getInt8PtrTy(), getInt8PtrTy(), getInt8PtrTy()},
      false);
  PointerType *getstackid_func_ptr_type = PointerType::get(getstackid_func_type, 0);
  Constant *getstackid_func = ConstantExpr::getCast(
      Instruction::IntToPtr,
      getInt64(BPF_FUNC_get_stackid),
      getstackid_func_ptr_type);
  return CreateCall(getstackid_func, {ctx, map_ptr, flags_val}, "get_stackid");
}

} // namespace ast
} // namespace bpftrace
