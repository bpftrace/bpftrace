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
  return CreateRecord(bpftrace::Struct::CreateRecord(fields, idents));
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

template <typename T, typename R = T, typename... Args>
static Result<R> unwrap(Types &btf, const std::string &name, Args &&...args)
{
  auto lookup = btf.lookup<T>(name);
  if (!lookup) {
    auto create = btf.add<T>(name, std::forward<Args>(args)...);
    if (!create) {
      return create.takeError();
    }
    return R(*create);
  }
  return R(*lookup);
}

Result<ValueType> convertType(Types &btf, const SizedType &type)
{
  if (type.IsVoidTy() || type.IsNoneTy()) {
    return ValueType(*btf.lookup<Void>("void")); // Require this exists.
  } else if (type.IsArrayTy()) {
    auto index = unwrap<Integer>(btf, "uint32_t", 4, 0);
    if (!index) {
      return index.takeError();
    }
    auto elem = convertType(btf, *type.GetElementTy());
    if (!elem) {
      return elem.takeError();
    }
    auto array_type = btf.add<Array>(*index, *elem, type.GetNumElements());
    if (!array_type) {
      return array_type.takeError();
    }
    return ValueType(*array_type);
  } else if (type.IsPtrTy()) {
    auto elem = convertType(btf, *type.GetPointeeTy());
    if (!elem) {
      return elem.takeError();
    }
    auto ptr_type = btf.add<Pointer>(*elem);
    if (!ptr_type) {
      return ptr_type.takeError();
    }
    return ValueType(*ptr_type);
  } else if (type.IsBoolTy()) {
    return unwrap<Integer>(btf, "_Bool", 1, BTF_INT_BOOL);
  } else if (type.IsBufferTy() || type.IsStringTy()) {
    auto index = unwrap<Integer>(btf, "uint32_t", 4, 0);
    if (!index) {
      return index.takeError();
    }
    auto char_type = unwrap<Integer>(btf, "char", 1, BTF_INT_CHAR);
    if (!char_type) {
      return char_type.takeError();
    }
    auto array_type = btf.add<Array>(*index, *char_type, type.GetSize());
    if (!array_type) {
      return array_type.takeError();
    }
    return ValueType(*array_type);
  } else if (type.IsEnumTy()) {
    // We can't encode all the values, so just claim that this is a
    // 64-bit integer. This should be fixed in the future.
    return unwrap<Integer, ValueType>(btf, "int64_t", 8, BTF_INT_SIGNED);
  } else if (type.IsRecordTy() || type.IsTupleTy()) {
    auto lookup = btf.lookup<Struct>(type.GetName());
    if (lookup) {
      return *lookup;
    }
    const auto &fields = type.GetFields();
    std::vector<std::pair<std::string, ValueType>> btf_fields;
    for (const auto &field : fields) {
      auto field_type = convertType(btf, field.type);
      if (!field_type) {
        return field_type.takeError();
      }
      btf_fields.emplace_back(field.name, *field_type);
    }
    auto struct_type = btf.add<Struct>(type.GetName(), btf_fields);
    if (!struct_type) {
      return struct_type.takeError();
    }
    return ValueType(*struct_type);
  } else if (type.IsIntegerTy()) {
    if (type.IsSigned()) {
      switch (type.GetIntBitWidth()) {
        case 8:
          return unwrap<Integer, ValueType>(btf, "int8_t", 1, BTF_INT_SIGNED);
        case 16:
          return unwrap<Integer, ValueType>(btf, "int16_t", 2, BTF_INT_SIGNED);
        case 32:
          return unwrap<Integer, ValueType>(btf, "int32_t", 4, BTF_INT_SIGNED);
        case 64:
          return unwrap<Integer, ValueType>(btf, "int64_t", 8, BTF_INT_SIGNED);
      }
    } else {
      switch (type.GetIntBitWidth()) {
        case 8:
          return unwrap<Integer, ValueType>(btf, "uint8_t", 1, 0);
        case 16:
          return unwrap<Integer, ValueType>(btf, "uint16_t", 2, 0);
        case 32:
          return unwrap<Integer, ValueType>(btf, "uint32_t", 4, 0);
        case 64:
          return unwrap<Integer, ValueType>(btf, "uint64_t", 8, 0);
      }
    }
  }
  return make_error<CompatTypeError>(type);
}

} // namespace bpftrace::btf
