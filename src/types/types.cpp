#include <algorithm>
#include <bpf/btf.h>
#include <cerrno>

#include "types/types.h"

namespace bpftrace::types {

using namespace bpftrace;

namespace detail {

Handle::Handle() : btf_(btf__new_empty())
{
}

Handle::Handle(std::shared_ptr<Handle> base)
    : btf_(btf__new_empty_split(base->btf_)), base_(std::move(base))
{
}

Result<HandleRef> Handle::parse(const void *data, size_t sz)
{
  auto *btf = btf__new(data, sz);
  if (btf == nullptr) {
    return make_error<ParseError>(errno);
  }
  return std::make_shared<Handle>(btf);
}

Result<HandleRef> Handle::parse(HandleRef base, const void *data, size_t sz)
{
  auto *btf = btf__new_split(data, sz, base->btf_);
  if (btf == nullptr) {
    return make_error<ParseError>(errno);
  }
  return std::make_shared<Handle>(btf, std::move(base));
}

Handle::~Handle()
{
  btf__free(btf_);
}

} // namespace detail

char ParseError::ID;

void ParseError::log(llvm::raw_ostream &OS) const
{
  OS << "Parse error: " << std::strerror(err_);
}

char TypeError::ID;

void TypeError::log(llvm::raw_ostream &OS) const
{
  OS << "Type error: " << std::strerror(err_);
}

char UnknownType::ID;

void UnknownType::log(llvm::raw_ostream &OS) const
{
  std::visit([&](const auto &v) { OS << "Unknown type: " << v; }, name_);
}

char KindMismatch::ID;

void KindMismatch::log(llvm::raw_ostream &OS) const
{
  OS << "Kind mismatch: got " << got_ << ", expected " << expected_;
}

Result<size_t> BaseType::size() const
{
  auto v = btf__resolve_size(btf_library(), type_id_);
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  return static_cast<size_t>(v);
}

// Returns the required alignment for the type.
Result<size_t> BaseType::alignment() const
{
  auto v = btf__align_of(btf_library(), type_id_);
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  return static_cast<size_t>(v);
}

const struct btf_type *BaseType::btf_type() const
{
  return btf__type_by_id(handle_->btf_library(), type_id_);
}

Result<Integer> Integer::add(HandleRef handle,
                             const std::string &name,
                             size_t bytes,
                             int encoding)
{
  auto v = btf__add_int(handle->btf_library(), name.c_str(), bytes, encoding);
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  return Integer(std::move(handle), v);
}

Result<Pointer> Pointer::add(HandleRef handle, const AnyType &type)
{
  auto v = btf__add_ptr(handle->btf_library(), type.type_id());
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  return Pointer(std::move(handle), v);
}

Result<AnyType> Pointer::element_type() const
{
  return AnyType::lookup(handle(), btf_type()->type);
}

Result<Array> Array::add(HandleRef handle,
                         const Integer &index_type,
                         const ValueType &element_type,
                         size_t elements)
{
  auto v = btf__add_array(handle->btf_library(),
                          index_type.type_id(),
                          element_type.type_id(),
                          elements);
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  return Array(std::move(handle), v);
}

Result<ValueType> Array::index_type() const
{
  return ValueType::lookup(handle(), btf_array(btf_type())->index_type);
}

Result<AnyType> Array::element_type() const
{
  return AnyType::lookup(handle(), btf_array(btf_type())->type);
}

size_t Array::element_count() const
{
  return btf_array(btf_type())->nelems;
}

static Result<OK> forEachField(
    HandleRef handle,
    const struct btf_type *t,
    std::function<bool(std::string &&, FieldInfo &&)> fn)
{
  auto vlen = btf_vlen(t);
  auto *members = btf_members(t);
  for (int i = 0; i < vlen; i++) {
    std::string name(
        btf__name_by_offset(handle->btf_library(), members[i].name_off));
    auto ok = ValueType::lookup(handle, members[i].type);
    if (!ok) {
      // We found the field, but can't resolve the type.
      return ok.takeError();
    }
    bool kflag = BTF_INFO_KFLAG(t->info);
    FieldInfo info = {
      .type = std::move(*ok),
      .bit_offset = kflag ? BTF_MEMBER_BIT_OFFSET(members[i].offset)
                          : members[i].offset,
      .bit_size = kflag ? BTF_MEMBER_BITFIELD_SIZE(members[i].offset) : 0,
    };
    if (!fn(std::move(name), std::move(info))) {
      break;
    }
  }

  return OK();
} // namespace bpftrace::types

Result<Struct> Struct::add(HandleRef handle,
                           const std::string &name,
                           const std::map<std::string, ValueType> &fields)
{
  size_t total_bytes = 0;
  std::vector<size_t> offsets;
  for (const auto &[_, t] : fields) {
    auto align = t.alignment();
    if (!align) {
      return align.takeError();
    }
    auto left = total_bytes % (*align);
    if (left != 0) {
      total_bytes += (*align) - left;
    }
    offsets.push_back(total_bytes);
    auto size = t.size();
    if (!size) {
      return size.takeError();
    }
    total_bytes += (*size);
  }
  auto v = btf__add_struct(handle->btf_library(), name.c_str(), total_bytes);
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  size_t index = 0;
  for (const auto &[field_name, t] : fields) {
    // We always provide bit_size=0, which indicates that this is not a
    // bitfield. We cannot construct bitfields via the `add` API.
    btf__add_field(handle->btf_library(),
                   field_name.c_str(),
                   t.type_id(),
                   offsets[index],
                   0);
    index++;
  }
  return Struct(std::move(handle), v);
}

std::string Struct::name() const
{
  return btf__name_by_offset(btf_library(), btf_type()->name_off);
}

Result<std::optional<FieldInfo>> Struct::field(const std::string &name) const
{
  std::optional<const FieldInfo> result;
  auto ok = forEachField(handle(),
                         btf_type(),
                         [&](std::string &&field_name,
                             FieldInfo &&info) -> bool {
                           if (name == field_name) {
                             result.emplace(std::move(info));
                             return false;
                           }
                           return true;
                         });
  if (!ok) {
    return ok.takeError();
  }
  return result;
}

Result<std::map<std::string, FieldInfo>> Struct::fields() const
{
  std::map<std::string, FieldInfo> result;
  auto ok = forEachField(
      handle(),
      btf_type(),
      [&](std::string &&field_name, FieldInfo &&info) -> bool {
        result.emplace(std::move(field_name), std::move(info));
        return true;
      });
  if (!ok) {
    return ok.takeError();
  }
  return result;
}

Result<Union> Union::add(HandleRef handle,
                         const std::string &name,
                         const std::map<std::string, ValueType> &fields)
{
  size_t total_bytes = 0;
  for (const auto &[_, t] : fields) {
    auto size = t.size();
    if (!size) {
      return size.takeError();
    }
    total_bytes = std::max(total_bytes, *size);
  }
  auto v = btf__add_union(handle->btf_library(), name.c_str(), total_bytes);
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  for (const auto &[field_name, t] : fields) {
    // We always provide bit_offset 0, with a bit_size of 0 because bitfields
    // are not supported. We only rely on the total size above.
    auto r = btf__add_field(
        handle->btf_library(), field_name.c_str(), t.type_id(), 0, 0);
    if (r < 0) {
      return make_error<TypeError>(r);
    }
  }
  return Union(std::move(handle), v);
}

std::string Union::name() const
{
  return btf__name_by_offset(btf_library(), btf_type()->name_off);
}

Result<std::optional<FieldInfo>> Union::field(const std::string &name) const
{
  std::optional<const FieldInfo> result;
  auto ok = forEachField(handle(),
                         btf_type(),
                         [&](std::string &&field_name,
                             FieldInfo &&info) -> bool {
                           if (name == field_name) {
                             result.emplace(std::move(info));
                             return false;
                           }
                           return true;
                         });
  if (!ok) {
    return ok.takeError();
  }
  return result;
}

Result<std::map<std::string, FieldInfo>> Union::fields() const
{
  std::map<std::string, FieldInfo> result;
  auto ok = forEachField(
      handle(),
      btf_type(),
      [&](std::string &&field_name, FieldInfo &&info) -> bool {
        result.emplace(std::move(field_name), std::move(info));
        return true;
      });
  if (!ok) {
    return ok.takeError();
  }
  return result;
}

Result<Enum> Enum::add(HandleRef handle,
                       const std::string &name,
                       const std::map<std::string, int32_t> &values)
{
  auto v = btf__add_enum(handle->btf_library(), name.c_str(), sizeof(int32_t));
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  for (const auto &[value_name, v] : values) {
    btf__add_enum_value(handle->btf_library(), value_name.c_str(), v);
  }
  return Enum(std::move(handle), v);
}

Result<Enum64> Enum64::add(HandleRef handle,
                           const std::string &name,
                           const std::map<std::string, int64_t> &values)
{
  auto v = btf__add_enum64(
      handle->btf_library(), name.c_str(), sizeof(int64_t), true);
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  for (const auto &[value_name, v] : values) {
    btf__add_enum64_value(handle->btf_library(), value_name.c_str(), v);
  }
  return Enum64(std::move(handle), v);
}

ForwardDecl::Kind ForwardDecl::kind() const
{
  // Note that enums don't really exist in the encoded scheme, they are just
  // enums without any defined values.
  bool is_union = BTF_INFO_KFLAG(btf_type()->info);
  if (is_union) {
    return ForwardDecl::Kind::Union;
  }
  return ForwardDecl::Kind::Struct;
}

std::string ForwardDecl::name() const
{
  return btf__name_by_offset(btf_library(), btf_type()->name_off);
}

Result<Typedef> Typedef::add(HandleRef handle,
                             const std::string &name,
                             const AnyType &t)
{
  auto v = btf__add_typedef(handle->btf_library(), name.c_str(), t.type_id());
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  return Typedef(std::move(handle), v);
}

std::string Typedef::name() const
{
  return btf__name_by_offset(btf_library(), btf_type()->name_off);
}

Result<AnyType> Typedef::type() const
{
  return AnyType::lookup(handle(), btf_type()->type);
}

Result<Volatile> Volatile::add(HandleRef handle, const ValueType &value_type)
{
  auto v = btf__add_volatile(handle->btf_library(), value_type.type_id());
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  return Volatile(std::move(handle), v);
}

Result<AnyType> Volatile::type() const
{
  return AnyType::lookup(handle(), btf_type()->type);
}

Result<Const> Const::add(HandleRef handle, const ValueType &value_type)
{
  auto v = btf__add_const(handle->btf_library(), value_type.type_id());
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  return Const(std::move(handle), v);
}

Result<AnyType> Const::type() const
{
  return AnyType::lookup(handle(), btf_type()->type);
}

Result<Restrict> Restrict::add(HandleRef handle, const ValueType &value_type)
{
  auto v = btf__add_restrict(handle->btf_library(), value_type.type_id());
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  return Restrict(std::move(handle), v);
}

Result<AnyType> Restrict::type() const
{
  return AnyType::lookup(handle(), btf_type()->type);
}

Result<FunctionProto> FunctionProto::add(
    HandleRef handle,
    const ValueType &return_type,
    const std::map<std::string, ValueType> &args)
{
  auto v = btf__add_func_proto(handle->btf_library(), return_type.type_id());
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  for (const auto &[param_name, t] : args) {
    btf__add_func_param(handle->btf_library(), param_name.c_str(), t.type_id());
  }
  return FunctionProto(std::move(handle), v);
}

Result<std::map<std::string, ValueType>> FunctionProto::argument_types() const
{
  std::map<std::string, ValueType> result;
  const auto *t = btf_type();
  auto *params = btf_params(t);
  auto vlen = btf_vlen(t);
  for (int i = 0; i < vlen; i++) {
    auto v = ValueType::lookup(handle(), params[i].type);
    if (!v) {
      return v.takeError();
    }
    result.emplace(std::string(
                       btf__name_by_offset(btf_library(), params[i].name_off)),
                   std::move(*v));
  }
  return result;
}

Result<ValueType> FunctionProto::return_type() const
{
  return ValueType::lookup(handle(), btf_type()->type);
}

Result<Function> Function::add(HandleRef handle,
                               const std::string &name,
                               Linkage linkage,
                               const FunctionProto &proto)
{
  auto v = btf__add_func(handle->btf_library(),
                         name.c_str(),
                         static_cast<btf_func_linkage>(linkage),
                         proto.type_id());
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  return Function(std::move(handle), v);
}

Result<FunctionProto> Function::type() const
{
  return FunctionProto::lookup(handle(), btf_type()->type);
}

Function::Linkage Function::linkage() const
{
  return static_cast<Linkage>(btf_vlen(btf_type()));
}

std::string Function::name() const
{
  return btf__name_by_offset(btf_library(), btf_type()->name_off);
}

Result<Var> Var::add(HandleRef handle,
                     const std::string &name,
                     Linkage linkage,
                     const ValueType &type)
{
  auto v = btf__add_var(
      handle->btf_library(), name.c_str(), linkage, type.type_id());
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  return Var(std::move(handle), v);
}

Result<ValueType> Var::type() const
{
  return ValueType::lookup(handle(), btf_type()->type);
}

Var::Linkage Var::linkage() const
{
  auto *var = btf_var(btf_type());
  return static_cast<Linkage>(var->linkage);
}

std::string Var::name() const
{
  return btf__name_by_offset(btf_library(), btf_type()->name_off);
}

std::string DataSection::name() const
{
  return btf__name_by_offset(btf_library(), btf_type()->name_off);
}

Result<DataSection> DataSection::add(HandleRef handle,
                                     const std::string &name,
                                     const std::vector<Var> &vars)
{
  size_t total_bytes = 0;
  std::vector<size_t> sizes;
  std::vector<size_t> offsets;
  for (const auto &var : vars) {
    auto align = var.alignment();
    if (!align) {
      return align.takeError();
    }
    auto left = total_bytes % (*align);
    if (left != 0) {
      total_bytes += (*align) - left;
    }
    offsets.push_back(total_bytes);
    auto size = var.size();
    if (!size) {
      return size.takeError();
    }
    sizes.push_back(*size);
    total_bytes += (*size);
  }
  auto v = btf__add_datasec(handle->btf_library(), name.c_str(), total_bytes);
  if (v < 0) {
    return make_error<TypeError>(v);
  }
  for (size_t i = 0; i < vars.size(); i++) {
    auto r = btf__add_datasec_var_info(
        handle->btf_library(), vars[i].type_id(), offsets[i], sizes[i]);
    if (r < 0) {
      return make_error<TypeError>(r);
    }
  }
  return DataSection(std::move(handle), v);
}

Result<BTF> BTF::parse(const void *data, size_t sz)
{
  auto handle = detail::Handle::parse(data, sz);
  if (!handle) {
    return handle.takeError();
  }
  return BTF(std::move(*handle));
}

Result<BTF> BTF::parse(const BTF &base, const void *data, size_t sz)
{
  auto handle = detail::Handle::parse(base.handle_, data, sz);
  if (!handle) {
    return handle.takeError();
  }
  return BTF(std::move(*handle));
}

size_t BTF::size() const
{
  return btf__type_cnt(handle_->btf_library());
}

std::ostream &operator<<(std::ostream &out, const BaseType &type)
{
  auto name_offset = type.btf_type()->name_off;
  if (name_offset != 0) {
    out << btf__name_by_offset(type.btf_library(), name_offset);
  } else {
    out << "(anon)";
  }
  return out;
}

std::ostream &operator<<(std::ostream &out, [[maybe_unused]] const Void &type)
{
  out << "void";
  return out;
}

std::ostream &operator<<(std::ostream &out, const Integer &type)
{
  out << static_cast<BaseType>(type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const Pointer &type)
{
  auto t = type.element_type();
  if (!t) {
    out << "(error: " << t.takeError() << ")";
  } else {
    out << *t;
  }
  out << "*";
  return out;
}

std::ostream &operator<<(std::ostream &out, const Array &type)
{
  auto t = type.element_type();
  if (!t) {
    llvm::Error err = t.takeError();
    out << "(error: " << err << ")";
  } else {
    out << *t;
  }
  out << "[" << type.element_count() << "]";
  return out;
}

std::ostream &operator<<(std::ostream &out, const Struct &type)
{
  out << "struct " << static_cast<BaseType>(type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const Union &type)
{
  out << "union " << static_cast<BaseType>(type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const Enum &type)
{
  out << "enum " << static_cast<BaseType>(type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const Enum64 &type)
{
  out << "enum64 " << static_cast<BaseType>(type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const ForwardDecl &type)
{
  out << "enum " << static_cast<BaseType>(type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const Typedef &type)
{
  out << static_cast<BaseType>(type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const Volatile &type)
{
  auto t = type.type();
  out << "volatile ";
  if (!t) {
    out << "(error: " << t.takeError() << ")";
  } else {
    out << *t;
  }
  return out;
}

std::ostream &operator<<(std::ostream &out, const Const &type)
{
  auto t = type.type();
  out << "const ";
  if (!t) {
    out << "(error: " << t.takeError() << ")";
  } else {
    out << *t;
  }
  return out;
}

std::ostream &operator<<(std::ostream &out, const Restrict &type)
{
  auto t = type.type();
  out << "restrict ";
  if (!t) {
    out << "(error: " << t.takeError() << ")";
  } else {
    out << *t;
  }
  return out;
}

static void formatFunction(std::ostream &out,
                           const std::string &name,
                           const FunctionProto &type)
{
  auto rt = type.return_type();
  if (!rt) {
    out << "(error: " << rt.takeError() << ") ";
  } else {
    out << *rt << " ";
  }
  out << name;
  auto args = type.argument_types();
  if (!args) {
    out << "(error: " << args.takeError() << ")";
  } else {
    out << "(";
    size_t done = 0;
    for (const auto &[name, t] : *args) {
      if (done > 0) {
        out << ", ";
      }
      out << t;
      if (!name.empty()) {
        out << " " << name;
      }
    }
    out << ")";
  }
}

std::ostream &operator<<(std::ostream &out, const FunctionProto &type)
{
  formatFunction(out, "(*)", type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const Function &type)
{
  std::string name = type.name();
  auto t = type.type();
  if (!t) {
    out << "void " << name << "(error: " << t.takeError() << ")";
  } else {
    formatFunction(out, name, *t);
  }
  return out;
}

std::ostream &operator<<(std::ostream &out, const Var &type)
{
  auto t = type.type();
  if (!t) {
    out << "(error: " << t.takeError() << ") ";
  } else {
    out << *t << " ";
  }
  out << static_cast<BaseType>(type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const DataSection &type)
{
  out << static_cast<BaseType>(type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const Float &type)
{
  out << static_cast<BaseType>(type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const DeclTag &type)
{
  out << static_cast<BaseType>(type);
  return out;
}

std::ostream &operator<<(std::ostream &out, const TypeTag &type)
{
  out << static_cast<BaseType>(type);
  return out;
}

} // namespace bpftrace::types
