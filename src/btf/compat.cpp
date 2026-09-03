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

// We can only generate the fields based on the offsets.
static Result<bpftrace::Fields> resolveFields(
    std::vector<std::pair<std::string, FieldInfo>> &&fields,
    CompatTypeCache &type_cache)
{
  bpftrace::Fields resolved;
  for (const auto &[name, info] : fields) {
    auto ft = getCompatType(info.type, type_cache);
    if (!ft) {
      return ft.takeError();
    }
    resolved.emplace_back(Field{
        .name = name,
        .type = *ft,
        .offset = static_cast<ssize_t>(info.bit_offset / 8),
        .bitfield = std::nullopt,
    });
  }
  return resolved;
}

Result<SizedType> asRecord(
    uint32_t type_id,
    const std::string &name,
    size_t size,
    std::vector<std::pair<std::string, FieldInfo>> &&fields,
    CompatTypeCache &type_cache)
{
  // While this record's fields are being resolved, the cache holds a null
  // entry for it. Since this function recurses this null entry is used to
  // determine if we're also dealing with a recursive type.
  auto [it, first_visit] = type_cache.records.try_emplace(type_id, nullptr);

  if (!name.empty()) {
    auto record = type_cache.structs.LookupOrAdd(name, size).lock();
    if (first_visit && !record->HasFields()) {
      auto resolved = resolveFields(std::move(fields), type_cache);
      if (!resolved) {
        type_cache.records.erase(it);
        return resolved.takeError();
      }
      // Another BTF type with the same name may have filled in this record
      // while its fields were being resolved; don't clobber it.
      if (!record->HasFields()) {
        record->fields = std::move(*resolved);
      }
    }
    return CreateCStruct(name, std::weak_ptr<bpftrace::Struct>(record));
  }

  // Anonymous records have no name to share them under, so they are owned by
  // the type that refers to them.
  auto make_record = [size](bpftrace::Fields &&fields) {
    auto record = bpftrace::Struct::CreateRecord({}, {});
    record->size = static_cast<int>(size);
    record->fields = std::move(fields);
    return record;
  };

  if (!first_visit) {
    if (it->second) {
      return CreateCStruct(name, std::shared_ptr<bpftrace::Struct>(it->second));
    }
    // This type is still being resolved. We need to break the recursion cycle
    // by returning an empty record of the right size.
    return CreateCStruct(name, make_record({}));
  }

  auto resolved = resolveFields(std::move(fields), type_cache);
  if (!resolved) {
    type_cache.records.erase(it);
    return resolved.takeError();
  }
  it->second = make_record(std::move(*resolved));
  return CreateCStruct(name, std::shared_ptr<bpftrace::Struct>(it->second));
}

Result<SizedType> getCompatType(const Struct &type, CompatTypeCache &type_cache)
{
  auto f = type.fields();
  if (!f) {
    return f.takeError();
  }
  auto sz = type.size();
  if (!sz) {
    return sz.takeError();
  }
  auto name = type.name();
  return asRecord(type.type_id(),
                  name.empty() ? name : "struct " + name,
                  *sz,
                  std::move(*f),
                  type_cache);
}

Result<SizedType> getCompatType(const Union &type, CompatTypeCache &type_cache)
{
  auto f = type.fields();
  if (!f) {
    return f.takeError();
  }
  auto sz = type.size();
  if (!sz) {
    return sz.takeError();
  }
  auto name = type.name();
  return asRecord(type.type_id(),
                  name.empty() ? name : "union " + name,
                  *sz,
                  std::move(*f),
                  type_cache);
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
