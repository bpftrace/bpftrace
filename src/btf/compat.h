#pragma once

#include "btf/btf.h"
#include "types.h"
#include "util/result.h"

namespace bpftrace::btf {

class CompatTypeError : public ErrorInfo<CompatTypeError> {
public:
  template <typename T>
  CompatTypeError(const T &type)
  {
    std::stringstream ss;
    ss << "no compatible type for " << type;
    msg_ = ss.str();
  }
  static char ID;
  void log(llvm::raw_ostream &OS) const override;
  const std::string &msg() const
  {
    return msg_;
  }

private:
  std::string msg_;
};

// For struct resolution, this indicates the set of structs
// that have already been resolved for the purposes of cycles.
using CompatTypeCache = std::map<uint32_t, std::shared_ptr<bpftrace::Struct>>;

template <typename T>
struct compatTypeFor {
  Result<SizedType> operator()(const T &t, CompatTypeCache &type_cache);
};

template <typename... Ts>
struct compatTypeFor<VariantType<Ts...>> {
  Result<SizedType> operator()(const VariantType<Ts...> &type, CompatTypeCache &type_cache)
  {
    return std::visit([&](const auto &v) { return getCompatType(v, type_cache); },
                      type.value());
  }
};

Result<SizedType> getCompatType(const Void &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Integer &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Pointer &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Array &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Struct &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Union &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Enum &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Enum64 &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const TypeTag &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const DeclTag &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Typedef &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Const &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Volatile &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Restrict &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Function &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const FunctionProto &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const DataSection &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Float &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const Var &type, CompatTypeCache &type_cache);
Result<SizedType> getCompatType(const ForwardDecl &type, CompatTypeCache &type_cache);

template <typename T>
Result<SizedType> getCompatType(const T &type, CompatTypeCache &type_cache)
{
  compatTypeFor<T> op;
  return op(type, type_cache);
}

template <typename T>
Result<SizedType> getCompatType(const T &type)
{
  CompatTypeCache type_cache; // Empty initial cache.
  return getCompatType(type, type_cache);
}

} // namespace bpftrace::btf
