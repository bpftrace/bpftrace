#pragma once

#include "mapkey.h"
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

  void createFunctionDebugInfo(Function &func);

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
  DIType *CreateMapStructType(const SizedType &stype);
  DIType *createPointerMemberType(const std::string &name,
                                  uint64_t offset,
                                  DIType *type);
  DIType *GetMapKeyType(const MapKey &key,
                        const SizedType &value_type,
                        libbpf::bpf_map_type map_type);
  DIType *GetMapFieldInt(int value);
  DIGlobalVariableExpression *createMapEntry(const std::string &name,
                                             libbpf::bpf_map_type map_type,
                                             uint64_t max_entries,
                                             const MapKey &key,
                                             const SizedType &value_type);
  DIGlobalVariableExpression *createGlobalInt64(std::string_view name);

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

} // namespace ast
} // namespace bpftrace
