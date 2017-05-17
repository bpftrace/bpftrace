#include "irbuilderbpf.h"
#include "libbpf.h"

#include <llvm/IR/Module.h>

namespace ebpf {
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

AllocaInst *IRBuilderBPF::CreateAllocaBPF(llvm::Type *ty, const std::string &name) const
{
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock &entry_block = parent->getEntryBlock();
  if (entry_block.empty())
    return new AllocaInst(ty, "", &entry_block);
  else
    return new AllocaInst(ty, "", &entry_block.front());
}

Value *IRBuilderBPF::CreateBpfPseudoCall(Map &map)
{
  int mapfd;
  if (bpftrace_.maps_.find(map.ident) == bpftrace_.maps_.end()) {
    bpftrace_.maps_[map.ident] = std::make_unique<ebpf::bpftrace::Map>(map.ident);
  }
  mapfd = bpftrace_.maps_[map.ident]->mapfd_;
  Function *pseudo_func = module_.getFunction("llvm.bpf.pseudo");
  return CreateCall(pseudo_func, {getInt64(BPF_PSEUDO_MAP_FD), getInt64(mapfd)});
}

Value *IRBuilderBPF::CreateMapLookupElem(Map &map, Value *key)
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
  CallInst *call = CreateCall(lookup_func, {map_ptr, key});

  // Check if result == 0
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(), "lookup_success", parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(), "lookup_failure", parent);
  BasicBlock *lookup_merge_block = BasicBlock::Create(module_.getContext(), "lookup_merge", parent);

  Value *value = CreateAllocaBPF(getInt64Ty());
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

void IRBuilderBPF::CreateMapUpdateElem(Map &map, Value *key, Value *val)
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
  CallInst *call = CreateCall(update_func, {map_ptr, key, val, flags});
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
