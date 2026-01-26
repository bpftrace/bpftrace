#pragma once

#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <llvm/IR/DIBuilder.h>

#include "ast/location.h"
#include "types.h"

namespace bpftrace::ast {

using namespace llvm;

class DIBuilderBPF : public DIBuilder {
public:
  DIBuilderBPF(Module &module);

  DILocalScope *createFunctionDebugInfo(llvm::Function &func,
                                        const SizedType &ret_type,
                                        const Struct &args,
                                        bool is_declaration = false);
  DILocalScope *createProbeDebugInfo(llvm::Function &probe_func);

  DIType *getInt8Ty();
  DIType *getInt16Ty();
  DIType *getInt32Ty();
  DIType *getInt64Ty();
  DIType *getInt8PtrTy();
  // We need a separate type called "int" to mimic libbpf's behaviour of
  // generating debuginfo for some BPF map fields. For details, see comment in
  // DIBuilderBPF::GetMapFieldInt.
  DIType *getIntTy();

  DIType *GetType(const SizedType &stype);
  DIType *CreateTupleType(const SizedType &stype);
  DIType *CreateRecordType(const SizedType &stype);
  DIType *CreateMapStructType(const SizedType &stype);
  DIType *CreateTSeriesStructType(const SizedType &stype);
  DIType *CreateByteArrayType(uint64_t num_bytes);
  DIType *createPointerMemberType(const std::string &name,
                                  uint64_t offset,
                                  DIType *type);
  DIType *GetMapKeyType(const SizedType &key_type,
                        const SizedType &value_type,
                        bpf_map_type map_type);
  DIType *GetMapFieldInt(int value);
  DIGlobalVariableExpression *createMapEntry(const std::string &name,
                                             bpf_map_type map_type,
                                             uint64_t max_entries,
                                             DIType *key_type,
                                             const SizedType &value_type);
  DIGlobalVariableExpression *createGlobalVariable(std::string_view name,
                                                   const SizedType &stype);
  DILocation *createDebugLocation(llvm::LLVMContext &ctx,
                                  DILocalScope *scope,
                                  const ast::Location &loc);

  DIFile *file = nullptr;

private:
  struct {
    DIType *int8 = nullptr;
    DIType *int16 = nullptr;
    DIType *int32 = nullptr;
    DIType *int64 = nullptr;
    DIType *int128 = nullptr;
    DIType *int8_ptr = nullptr;
    DIType *int_ = nullptr;
  } types_;

  std::unordered_map<std::string, DIType *> structs_;
};

} // namespace bpftrace::ast
