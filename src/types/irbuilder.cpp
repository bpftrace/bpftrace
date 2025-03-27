#include "types/irbuilder.h"

namespace bpftrace::types {

static Result<llvm::Type *> intType(llvm::IRBuilderBase &base, size_t bits)
{
  switch (bits) {
    case 1:
      return base.getInt1Ty();
    case 8:
      return base.getInt8Ty();
    case 16:
      return base.getInt16Ty();
    case 32:
      return base.getInt32Ty();
    case 64:
      return base.getInt64Ty();
    default:
      return make_error<TypeError>(EINVAL);
  }
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Integer &type)
{
  return intType(base, 8 * type.bytes());
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base,
                             [[maybe_unused]] const Pointer &type)
{
  return base.getPtrTy();
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Array &type)
{
  auto t = type.element_type();
  if (!t) {
    return t.takeError();
  }
  auto ty = getType(base, t);
  if (!ty) {
    return ty.takeError();
  }
  return llvm::ArrayType::get(*ty, type.element_count());
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Struct &type)
{
  llvm::SmallVector<llvm::Type *> fields;
  auto f = type.fields();
  if (!f) {
    return f.takeError();
  }
  size_t last_offset = 0;
  bool packed = true;
  for (const auto &[name, info] : *f) {
    if (info.bit_offset != last_offset) {
      packed = false;
    }
    if (info.bit_size != 0) {
      last_offset += info.bit_size;
    } else {
      auto size = info.type.size();
      if (!size) {
        return size.takeError();
      }
      last_offset += 8 * (*size);
    }
    auto ft = getType(base, info.type);
    if (!ft) {
      return ft.takeError();
    }
    fields.push_back(*ft);
  }
  return llvm::StructType::create(
      base.getContext(), fields, type.name(), packed);
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Union &type)
{
  // There no unions in LLVM IR. Therefore, we need to construct a
  // struct with appropriate size.
  auto size = type.size();
  if (!size) {
    return size.takeError();
  }
  auto *bytes = llvm::ArrayType::get(base.getInt8Ty(), *size);
  return llvm::StructType::create(
      base.getContext(), { bytes }, type.name(), true);
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Enum &type)
{
  auto size = type.size();
  if (!size) {
    return size.takeError();
  }
  return intType(base, 8 * (*size));
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Enum64 &type)
{
  auto size = type.size();
  if (!size) {
    return size.takeError();
  }

  return intType(base, 8 * (*size));
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Typedef &type)
{
  auto t = type.type();
  if (!t) {
    return t.takeError();
  }
  return getType(base, *t);
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Volatile &type)
{
  auto t = type.type();
  if (!t) {
    return t.takeError();
  }
  return getType(base, *t);
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Const &type)
{
  auto t = type.type();
  if (!t) {
    return t.takeError();
  }
  return getType(base, *t);
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Restrict &type)
{
  auto t = type.type();
  if (!t) {
    return t.takeError();
  }
  return getType(base, *t);
}

Result<llvm::Type *> getType(llvm::IRBuilderBase &base,
                             const FunctionProto &type)
{
  llvm::SmallVector<llvm::Type *> params;
  auto rt = type.return_type();
  if (!rt) {
    return rt.takeError();
  }
  auto rtt = getType(base, rt);
  if (!rtt) {
    return rtt.takeError();
  }
  auto args = type.argument_types();
  if (!args) {
    return args.takeError();
  }
  bool varargs = false;
  size_t count = 0;
  for (const auto &[_, arg] : *args) {
    if (count == args->size() - 1 && arg.is<Void>()) {
      // This is a vararg function.
      varargs = true;
      break;
    }
    auto t = getType(base, arg);
    if (!t) {
      return t.takeError();
    }
    params.push_back(*t);
    count++;
  }
  return llvm::FunctionType::get(*rtt, params, varargs);
}

} // namespace bpftrace::types
