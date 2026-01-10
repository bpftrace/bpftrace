#include "btf/compat.h"
#include "struct.h"

namespace bpftrace::btf {

char CompatTypeError::ID;

void CompatTypeError::log(llvm::raw_ostream &OS) const
{
  OS << msg_;
}

Result<SizedType> getCompatType([[maybe_unused]] const Void &type)
{
  return CreateVoid();
}

Result<SizedType> getCompatType(const Integer &type)
{
  if (type.is_bool()) {
    return CreateBool();
  }
  return CreateInteger(8 * type.bytes(), type.is_signed());
}

Result<SizedType> getCompatType(const Pointer &type)
{
  auto t = type.element_type();
  if (!t) {
    return t.takeError();
  }
  auto ty = getCompatType(*t);
  if (!ty) {
    return ty.takeError();
  }
  return CreatePointer(*ty);
}

Result<SizedType> getCompatType(const Array &type)
{
  auto t = type.element_type();
  if (!t) {
    return t.takeError();
  }
  auto ty = getCompatType(*t);
  if (!ty) {
    return ty.takeError();
  }
  return CreateArray(type.element_count(), *ty);
}

Result<SizedType> getCompatType(const Struct &type)
{
  std::vector<SizedType> fields;
  std::vector<std::string_view> idents;
  auto f = type.fields();
  if (!f) {
    return f.takeError();
  }
  // We have no ability to control how things are packed,
  // so this may or may not generate the correct type.
  for (const auto &[name, info] : *f) {
    auto ft = getCompatType(info.type);
    if (!ft) {
      return ft.takeError();
    }
    fields.emplace_back(*ft);
    idents.emplace_back(name);
  }
  return CreateCStruct(bpftrace::Struct::CreateRecord(fields, idents));
}

Result<SizedType> getCompatType(const Enum &type)
{
  auto size = type.size();
  if (!size) {
    return size.takeError();
  }
  return CreateEnum(8 * (*size), type.name());
}

Result<SizedType> getCompatType(const Enum64 &type)
{
  auto size = type.size();
  if (!size) {
    return size.takeError();
  }
  return CreateEnum(8 * (*size), type.name());
}

Result<SizedType> getCompatType(const TypeTag &type)
{
  // Values are: user, percpu, rcu.
  if (type.value() == "user") {
    auto t = type.element_type();
    if (!t) {
      return t.takeError();
    }
    auto ty = getCompatType(*t);
    if (!ty) {
      return ty.takeError();
    }
    ty->SetAS(AddrSpace::user);
    return *ty;
  } else {
    return make_error<CompatTypeError>(type);
  }
}

Result<SizedType> getCompatType(const Typedef &type)
{
  auto t = type.type();
  if (!t) {
    return t.takeError();
  }
  return getCompatType(*t);
}

} // namespace bpftrace::btf
