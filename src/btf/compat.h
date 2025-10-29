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

template <typename T>
struct compatTypeFor {
  Result<SizedType> operator()(const T &t)
  {
    return make_error<CompatTypeError>(t);
  }
};

template <typename... Ts>
struct compatTypeFor<VariantType<Ts...>> {
  Result<SizedType> operator()(const VariantType<Ts...> &type)
  {
    return std::visit([&](const auto &v) { return getCompatType(v); },
                      type.value());
  }
};

Result<SizedType> getCompatType(const Void &type);
Result<SizedType> getCompatType(const Integer &type);
Result<SizedType> getCompatType(const Pointer &type);
Result<SizedType> getCompatType(const Array &type);
Result<SizedType> getCompatType(const Struct &type);
Result<SizedType> getCompatType(const Enum &type);
Result<SizedType> getCompatType(const Enum64 &type);
Result<SizedType> getCompatType(const TypeTag &type);
Result<SizedType> getCompatType(const Typedef &type);

template <typename T>
Result<SizedType> getCompatType(const T &type)
{
  compatTypeFor<T> op;
  return op(type);
}

Result<ValueType> convertType(Types &btf, const SizedType &type);

} // namespace bpftrace::btf
