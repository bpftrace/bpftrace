#pragma once

#include "functions.h"
#include "types.h"

#include <linux/bpf.h>

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

#include <llvm/IR/DIBuilder.h>

namespace bpftrace {
namespace ast {

using namespace llvm;

class DIBuilderBPF : public DIBuilder {
public:
  DIBuilderBPF(Module &module);

  // TODO get rid of this overload?
  void createFunctionDebugInfo(llvm::Function &func,
                               const SizedType &ret_type,
                               const Struct &args,
                               bool is_declaration = false);
  void createProbeDebugInfo(llvm::Function &probe_func);
  // TODO is this overload still needed after rebase?
  void createFunctionDebugInfo(llvm::Function &func);
  void createFunctionDebugInfo(llvm::Function &func,
                               const SizedType &returnType,
                               const std::vector<Param> &params);
  // void createFunctionDebugInfo(llvm::Function &func, const SizedType
  // &returnType, const std::vector<SizedType> &params);

  DIType *getInt8Ty();
  DIType *getInt16Ty();
  DIType *getInt32Ty();
  DIType *getInt64Ty();
  DIType *getInt8PtrTy();
  // We need a separate type called "int" to mimic libbpf's behaviour of
  // generating debuginfo for some BPF map fields. For details, see comment in
  // DIBuilderBPF::GetMapFieldInt.
  DIType *getIntTy();
  DIType *getVoidTy();

  DIType *GetType(const SizedType &stype, bool emit_codegen_types = false);
  DIType *CreateTupleType(const SizedType &stype);
  DIType *CreateMapStructType(const SizedType &stype);
  DIType *CreateByteArrayType(uint64_t num_bytes);
  DIType *createPointerMemberType(const std::string &name,
                                  uint64_t offset,
                                  DIType *type);
  DICompositeType *createStructTypeBPF(const SizedType &stype);
  DIType *GetMapKeyType(const SizedType &key_type,
                        const SizedType &value_type,
                        libbpf::bpf_map_type map_type);
  DIType *GetMapFieldInt(int value);
  DIGlobalVariableExpression *createMapEntry(const std::string &name,
                                             libbpf::bpf_map_type map_type,
                                             uint64_t max_entries,
                                             DIType *key_type,
                                             const SizedType &value_type);
  DIGlobalVariableExpression *createGlobalVariable(std::string_view name,
                                                   const SizedType &stype);
  // TODO are these overloads still needed after rebase?
  DIGlobalVariableExpression *createGlobalInt64(std::string_view name);
  DIGlobalVariableExpression *createGlobalString(std::string_view name,
                                                 std::string_view contents);

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

  std::unordered_map<const SizedType *, DIType *> aaatypes_;
};

} // namespace ast
} // namespace bpftrace
