#include "btf/compat.h"
#include "btf/btf.h"
#include "log.h"
#include "struct.h"
#include "types.h"

namespace bpftrace::btf {

char CompatTypeError::ID;

void CompatTypeError::log(llvm::raw_ostream &OS) const
{
  OS << msg_;
}

Result<SizedType> getCompatType([[maybe_unused]] const Void &type,
                                [[maybe_unused]] CompatTypeCache &type_cache)
{
  return CreateVoid();
}

Result<SizedType> getCompatType(const Integer &type,
                                [[maybe_unused]] CompatTypeCache &type_cache)
{
  if (type.is_bool()) {
    return CreateBool();
  }
  return CreateInteger(8 * type.bytes(), type.is_signed());
}

Result<SizedType> getCompatType(const Pointer &type,
                                CompatTypeCache &type_cache)
{
  auto t = type.element_type();
  if (!t) {
    return t.takeError();
  }
  auto ty = getCompatType(*t, type_cache);
  if (!ty) {
    return ty.takeError();
  }
  return CreatePointer(*ty);
}

Result<SizedType> getCompatType(const Array &type, CompatTypeCache &type_cache)
{
  auto t = type.element_type();
  if (!t) {
    return t.takeError();
  }
  auto ty = getCompatType(*t, type_cache);
  if (!ty) {
    return ty.takeError();
  }
  // Special case; all int8 arrays are treated as strings.
  if (ty->IsIntegerTy() && ty->GetIntBitWidth() == 8) {
    return CreateString(type.element_count());
  }
  return CreateArray(type.element_count(), *ty);
}

Result<SizedType> asCStruct(
    uint32_t type_id,
    std::vector<std::pair<std::string, FieldInfo>> &&fields,
    CompatTypeCache &type_cache)
{
  auto it = type_cache.find(type_id);
  if (it != type_cache.end()) {
    return CreateCStruct(std::shared_ptr<bpftrace::Struct>(it->second));
  }

  // The record start empty, and we construct below.
  auto s = bpftrace::Struct::CreateRecord({}, {});
  type_cache.emplace(type_id, std::shared_ptr<bpftrace::Struct>(s));

  // We can only generate a type based on the offsets.
  std::vector<std::string_view> idents;
  std::vector<FieldInfo> infos;
  std::vector<SizedType> types;
  for (const auto &[name, info] : fields) {
    auto ft = getCompatType(info.type, type_cache);
    if (!ft) {
      return ft.takeError();
    }
    s->fields.emplace_back(Field{
        .name = name,
        .type = *ft,
        .offset = static_cast<ssize_t>(info.bit_offset / 8),
        .bitfield = std::nullopt,
    });
  }
  return CreateCStruct(std::move(s));
}

Result<SizedType> getCompatType(const Struct &type, CompatTypeCache &type_cache)
{
  auto f = type.fields();
  if (!f) {
    return f.takeError();
  }
  return asCStruct(type.type_id(), std::move(*f), type_cache);
}

Result<SizedType> getCompatType(const Union &type, CompatTypeCache &type_cache)
{
  auto f = type.fields();
  if (!f) {
    return f.takeError();
  }
  return asCStruct(type.type_id(), std::move(*f), type_cache);
}

Result<SizedType> getCompatType(const Enum &type,
                                [[maybe_unused]] CompatTypeCache &type_cache)
{
  auto size = type.size();
  if (!size) {
    return size.takeError();
  }
  return CreateEnum(8 * (*size), type.name());
}

Result<SizedType> getCompatType(const Enum64 &type,
                                [[maybe_unused]] CompatTypeCache &type_cache)
{
  auto size = type.size();
  if (!size) {
    return size.takeError();
  }
  return CreateEnum(8 * (*size), type.name());
}

Result<SizedType> getCompatType(const TypeTag &type,
                                CompatTypeCache &type_cache)
{
  // Values are: user, percpu, rcu.
  if (type.value() == "user") {
    auto t = type.element_type();
    if (!t) {
      return t.takeError();
    }
    auto ty = getCompatType(*t, type_cache);
    if (!ty) {
      return ty.takeError();
    }
    ty->SetAS(AddrSpace::user);
    return *ty;
  } else if (type.value() == "percpu" || type.value() == "rcu") {
    auto t = type.element_type();
    if (!t) {
      return t.takeError();
    }
    auto ty = getCompatType(*t, type_cache);
    if (!ty) {
      return ty.takeError();
    }
    return *ty;
  } else {
    return make_error<CompatTypeError>(type);
  }
}

Result<SizedType> getCompatType(const DeclTag &type,
                                [[maybe_unused]] CompatTypeCache &type_cache)
{
  return make_error<CompatTypeError>(type);
}

Result<SizedType> getCompatType(const Typedef &type,
                                CompatTypeCache &type_cache)
{
  auto t = type.type();
  if (!t) {
    return t.takeError();
  }
  return getCompatType(*t, type_cache);
}

Result<SizedType> getCompatType(const Const &type, CompatTypeCache &type_cache)
{
  auto t = type.type();
  if (!t) {
    return t.takeError();
  }
  return getCompatType(*t, type_cache);
}

Result<SizedType> getCompatType(const Volatile &type,
                                CompatTypeCache &type_cache)
{
  auto t = type.type();
  if (!t) {
    return t.takeError();
  }
  return getCompatType(*t, type_cache);
}

Result<SizedType> getCompatType(const Restrict &type,
                                CompatTypeCache &type_cache)
{
  auto t = type.type();
  if (!t) {
    return t.takeError();
  }
  return getCompatType(*t, type_cache);
}

Result<SizedType> getCompatType([[maybe_unused]] const Function &type,
                                [[maybe_unused]] CompatTypeCache &type_cache)
{
  return CreatePointer(CreateVoid());
}

Result<SizedType> getCompatType([[maybe_unused]] const FunctionProto &type,
                                [[maybe_unused]] CompatTypeCache &type_cache)
{
  return CreatePointer(CreateVoid());
}

Result<SizedType> getCompatType([[maybe_unused]] const Float &type,
                                [[maybe_unused]] CompatTypeCache &type_cache)
{
  auto size = type.size();
  if (!size) {
    return size.takeError();
  }
  return CreateBuffer(*size);
}

Result<SizedType> getCompatType([[maybe_unused]] const Var &type,
                                [[maybe_unused]] CompatTypeCache &type_cache)
{
  return CreatePointer(CreateVoid());
}

Result<SizedType> getCompatType([[maybe_unused]] const DataSection &type,
                                [[maybe_unused]] CompatTypeCache &type_cache)
{
  return CreatePointer(CreateVoid());
}

Result<SizedType> getCompatType(const ForwardDecl &type,
                                CompatTypeCache &type_cache)
{
  // Attempt to resolve the forward declaration by looking up
  // the type name in the existing type system.
  auto kind = type.kind();
  auto name = type.name();
  auto types = Types(type.handle());
  switch (kind) {
    case ForwardDecl::Struct: {
      auto struct_type = types.lookup<Struct>(name);
      if (!struct_type) {
        return CreatePointer(CreateVoid());
      }
      return getCompatType(*struct_type, type_cache);
    }
    case ForwardDecl::Union: {
      auto union_type = types.lookup<Union>(name);
      if (!union_type) {
        return CreatePointer(CreateVoid());
      }
      return getCompatType(*union_type, type_cache);
    }
    case ForwardDecl::Enum: {
      auto enum_type = types.lookup<Enum>(name);
      if (!enum_type) {
        return CreatePointer(CreateVoid());
      }
      return getCompatType(*enum_type, type_cache);
    }
    default:
      return CreatePointer(CreateVoid());
  }
}

} // namespace bpftrace::btf
