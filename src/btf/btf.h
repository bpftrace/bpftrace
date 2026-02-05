#pragma once

#include <bpf/btf.h>
#include <cstdint>
#include <map>
#include <memory>
#include <ranges>
#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "util/result.h"

namespace bpftrace::btf {

namespace detail {

class Handle;
using HandleRef = std::shared_ptr<Handle>;

// Handle is the internal library BTF handle. This is shared among all objects
// that may be referencing the `struct btf*` pointer. It is held as a
// `shared_ptr`, using the alias `HandleRef` (defined above).
class Handle {
public:
  Handle();
  Handle(HandleRef base);
  Handle(struct btf *btf) : btf_(btf) {};
  Handle(struct btf *btf, HandleRef base)
      : btf_(btf), base_(std::move(base)) {};
  ~Handle();
  Handle(Handle &&other) = delete;
  Handle &operator=(Handle &&other) = delete;
  Handle(const Handle &other) = delete;
  Handle &operator=(Handle &other) = delete;

  static Result<HandleRef> parse(const void *data, size_t sz);
  static Result<HandleRef> parse(HandleRef base, const void *data, size_t sz);

  struct btf *btf_library() const
  {
    return btf_;
  }

  void rebase(HandleRef base)
  {
    base_ = std::move(base);
  }

private:
  struct btf *btf_;

  // N.B. base_ is not used directly, but holds a reference to the btf_library
  // handle if this is needed. This ensures it is not released while it is being
  // used. It is only used indirectly through our own handle above.
  HandleRef base_;
};

} // namespace detail

using detail::HandleRef;

// Indicates an error occured while parsing BTF.
class ParseError : public ErrorInfo<ParseError> {
public:
  static char ID;
  ParseError(int err) : err_(err >= 0 ? err : -err) {};
  void log(llvm::raw_ostream &OS) const override;
  int error_code() const { return err_; }

private:
  int err_;
};

// Indicates an error occurred within libbtf.
class TypeError : public ErrorInfo<TypeError> {
public:
  static char ID;
  TypeError(int err) : err_(err >= 0 ? err : -err) {};
  void log(llvm::raw_ostream &OS) const override;
  int error_code() const { return err_; }

private:
  int err_;
};

// Indicates that no associated type was found, either when looking up by name
// or by type_id.
class UnknownType : public ErrorInfo<UnknownType> {
public:
  static char ID;
  UnknownType(const std::string &name) : name_(name) {};
  UnknownType(uint32_t type_id) : name_(type_id) {};
  void log(llvm::raw_ostream &OS) const override;

private:
  std::variant<uint32_t, std::string> name_;
};

// Indicates that a type was found, but it did not match the expected type.
class KindMismatch : public ErrorInfo<KindMismatch> {
public:
  static char ID;
  KindMismatch(uint32_t got, uint32_t expected)
      : got_(got), expected_(expected) {};
  void log(llvm::raw_ostream &OS) const override;

private:
  uint32_t got_;
  uint32_t expected_;
};

class Void;
class Integer;
class Pointer;
class Array;
class Struct;
class Union;
class Enum;
class Enum64;
class ForwardDecl;
class Typedef;
class Volatile;
class Const;
class Restrict;
class FunctionProto;
class Function;
class Var;
class DataSection;
class Float;
class DeclTag;
class TypeTag;

// Defined below for ordering.
template <typename... Ts>
class VariantType;

// ValueType represents a value that may be passed to functions, returned, etc.
// It excludes special types that may exist only within BTF (e.g. function,
// variable, data section, tags, etc.).
using ValueType = VariantType<Void,
                              Integer,
                              Pointer,
                              Array,
                              Struct,
                              Union,
                              Enum,
                              Enum64,
                              Typedef,
                              Volatile,
                              Const,
                              Restrict,
                              Float>;

// AnyType is the set of all possible BTF types.
using AnyType = VariantType<Void,
                            Integer,
                            Pointer,
                            Array,
                            Struct,
                            Union,
                            Enum,
                            Enum64,
                            ForwardDecl,
                            Typedef,
                            Volatile,
                            Const,
                            Restrict,
                            FunctionProto,
                            Function,
                            Var,
                            DataSection,
                            Float,
                            DeclTag,
                            TypeTag>;

// BaseType is the concrete implementation of the abstract `Type`.
class BaseType {
public:
  // Construct a new object with the handle and type_id. This is the universal
  // constructor for all types; it should not be overriden.
  BaseType(HandleRef handle, uint32_t type_id)
      : handle_(std::move(handle)), type_id_(type_id) {};

  // Return the resolved size of the type.
  Result<size_t> size() const;

  // Returns the required alignment for the type.
  Result<size_t> alignment() const;

  // Return the handle for the type.
  const struct btf_type *btf_type() const;

  // Returns the library handle.
  HandleRef handle() const
  {
    return handle_;
  }

  // Returns the type_id.
  uint32_t type_id() const
  {
    return type_id_;
  }

  // Returns the btf library data, convenience wrapper.
  struct btf *btf_library() const
  {
    return handle_->btf_library();
  }

private:
  HandleRef handle_;
  uint32_t type_id_;
};

// Type is the common implementation for all types; this class uses the CRTP
// pattern to eliminate as much boilerplate as possible.
//
// Each subclass should define the following:
// - An `add` method, which will lookup if the type already exists, and if not
//   add to the handle and return the result.
// - Any custom methods related to extracting type-specfic information.
template <typename T, uint32_t Kind>
class Type : public BaseType {
public:
  using BaseType::BaseType;

  // Used by the variant above, to determine if this accepts the given kind.
  static bool is(uint32_t kind)
  {
    return kind == Kind;
  }

  // Finds the type with the required kind and name, constructing a new object.
  static Result<T> lookup(HandleRef handle, const std::string &name)
  {
    auto v = btf__find_by_name_kind(handle->btf_library(), name.c_str(), Kind);
    if (v >= 0) {
      return T(std::move(handle), v);
    }
    return make_error<UnknownType>(name);
  }

  // Checks the given type_id against the passed one.
  static Result<T> lookup(HandleRef handle, uint32_t type_id)
  {
    const auto *t = btf__type_by_id(handle->btf_library(), type_id);
    if (t == nullptr) {
      return make_error<UnknownType>(type_id);
    }
    auto k = btf_kind(t);
    if (k != Kind) {
      return make_error<KindMismatch>(k, Kind);
    }
    return T(std::move(handle), type_id);
  }

  friend class Types;
  friend std::ostream &operator<<(std::ostream &, const BaseType &);
};

class Void : public Type<Void, BTF_KIND_UNKN> {
public:
  Void(HandleRef handle, uint32_t type_id)
      : Type(std::move(handle), type_id) {};

  static Result<Void> lookup(HandleRef handle, const std::string &name)
  {
    if (name == "void") {
      return Void(std::move(handle), 0);
    }
    return make_error<UnknownType>(name);
  }
  static Result<Void> lookup(HandleRef handle, uint32_t type_id)
  {
    if (type_id == 0) {
      return Void(std::move(handle), type_id);
    }
    return make_error<UnknownType>(type_id);
  }

private:
  // There is no `add` method for void types, it is always implicitly defined.
  // It is also used for types that we cannot currently interpret correctly.
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Void & /*type*/);
};

class Integer : public Type<Integer, BTF_KIND_INT> {
public:
  Integer(HandleRef &&handle, uint32_t type_id)
      : Type<Integer, BTF_KIND_INT>(std::move(handle), type_id) {};

  size_t bytes() const;
  bool is_bool() const {
    return btf_int_encoding(btf_type()) & BTF_INT_BOOL;
  }
  bool is_signed() const {
    return btf_int_encoding(btf_type()) & BTF_INT_SIGNED;
  }

private:
  static Result<Integer> add(HandleRef handle,
                             const std::string &name,
                             size_t bytes,
                             int encoding);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Integer & /*type*/);
};

class Pointer : public Type<Pointer, BTF_KIND_PTR> {
public:
  Pointer(HandleRef &&handle, uint32_t type_id)
      : Type<Pointer, BTF_KIND_PTR>(std::move(handle), type_id) {};

  Result<AnyType> element_type() const;

private:
  static Result<Pointer> add(HandleRef handle, const AnyType &type);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Pointer & /*type*/);
};

class Array : public Type<Array, BTF_KIND_ARRAY> {
public:
  Array(HandleRef &&handle, uint32_t type_id)
      : Type<Array, BTF_KIND_ARRAY>(std::move(handle), type_id) {};

  Result<ValueType> index_type() const;
  Result<AnyType> element_type() const;
  size_t element_count() const;

private:
  static Result<Array> add(HandleRef handle,
                           const Integer &index_type,
                           const ValueType &element_type,
                           size_t elements);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Array & /*type*/);
};

// Defined below.
struct FieldInfo;

class Struct : public Type<Struct, BTF_KIND_STRUCT> {
public:
  Struct(HandleRef &&handle, uint32_t type_id)
      : Type<Struct, BTF_KIND_STRUCT>(std::move(handle), type_id) {};

  std::string name() const;
  Result<FieldInfo> field(const std::string &name) const;
  Result<FieldInfo> field(uint32_t index) const;
  Result<std::vector<std::pair<std::string, FieldInfo>>> fields() const;

private:
  static Result<Struct> add(
      HandleRef handle,
      const std::string &name,
      const std::vector<std::pair<std::string, ValueType>> &fields);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Struct & /*type*/);
};

class Union : public Type<Union, BTF_KIND_UNION> {
public:
  Union(HandleRef handle, uint32_t type_id)
      : Type<Union, BTF_KIND_UNION>(std::move(handle), type_id) {};

  std::string name() const;
  Result<FieldInfo> field(const std::string &name) const;
  Result<FieldInfo> field(uint32_t index) const;
  Result<std::vector<std::pair<std::string, FieldInfo>>> fields() const;

private:
  static Result<Union> add(
      HandleRef handle,
      const std::string &name,
      const std::vector<std::pair<std::string, ValueType>> &fields);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Union & /*type*/);
};

class Enum : public Type<Enum, BTF_KIND_ENUM> {
public:
  Enum(HandleRef handle, uint32_t type_id)
      : Type<Enum, BTF_KIND_ENUM>(std::move(handle), type_id) {};

  std::string name() const;
  std::map<std::string, int32_t> values() const;

private:
  static Result<Enum> add(HandleRef handle,
                          const std::string &name,
                          const std::map<std::string, int32_t> &values);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Enum & /*type*/);
};

class Enum64 : public Type<Enum64, BTF_KIND_ENUM64> {
public:
  Enum64(HandleRef handle, uint32_t type_id)
      : Type<Enum64, BTF_KIND_ENUM64>(std::move(handle), type_id) {};

  std::string name() const;
  std::map<std::string, int64_t> values() const;

private:
  static Result<Enum64> add(HandleRef handle,
                            const std::string &name,
                            const std::map<std::string, int64_t> &values);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Enum64 & /*type*/);
};

class ForwardDecl : public Type<ForwardDecl, BTF_KIND_FWD> {
public:
  ForwardDecl(HandleRef &&handle, uint32_t type_id)
      : Type<ForwardDecl, BTF_KIND_FWD>(std::move(handle), type_id) {};

  enum Kind {
    Struct = BTF_FWD_STRUCT,
    Union = BTF_FWD_UNION,
    Enum = BTF_FWD_ENUM,
  };

  Kind kind() const;
  std::string name() const;

private:
  // We don't support `add` for forward declarations, this is really an
  // artifact used for constructing pointers without full type information in
  // all translation units. It should not be relevant in fully fleshed out
  // types, hence the only method is the resolution method.
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const ForwardDecl & /*type*/);
};

class Typedef : public Type<Typedef, BTF_KIND_TYPEDEF> {
public:
  Typedef(HandleRef &&handle, uint32_t type_id)
      : Type<Typedef, BTF_KIND_TYPEDEF>(std::move(handle), type_id) {};

  std::string name() const;
  Result<AnyType> type() const;

private:
  static Result<Typedef> add(HandleRef handle,
                             const std::string &name,
                             const AnyType &t);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Typedef & /*type*/);
};

class Volatile : public Type<Volatile, BTF_KIND_VOLATILE> {
public:
  Volatile(HandleRef &&handle, uint32_t type_id)
      : Type<Volatile, BTF_KIND_VOLATILE>(std::move(handle), type_id) {};

  Result<AnyType> type() const;

private:
  static Result<Volatile> add(HandleRef handle, const ValueType &value_type);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Volatile & /*type*/);
};

class Const : public Type<Const, BTF_KIND_CONST> {
public:
  Const(HandleRef handle, uint32_t type_id)
      : Type<Const, BTF_KIND_CONST>(std::move(handle), type_id) {};

  Result<AnyType> type() const;

private:
  static Result<Const> add(HandleRef handle, const ValueType &value_type);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Const & /*type*/);
};

class Restrict : public Type<Restrict, BTF_KIND_RESTRICT> {
public:
  Restrict(HandleRef &&handle, uint32_t type_id)
      : Type<Restrict, BTF_KIND_RESTRICT>(std::move(handle), type_id) {};

  Result<AnyType> type() const;

private:
  static Result<Restrict> add(HandleRef handle, const ValueType &value_type);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Restrict & /*type*/);
};

class FunctionProto : public Type<FunctionProto, BTF_KIND_FUNC_PROTO> {
public:
  FunctionProto(HandleRef &&handle, uint32_t type_id)
      : Type<FunctionProto, BTF_KIND_FUNC_PROTO>(std::move(handle), type_id) {};

  Result<std::vector<std::pair<std::string, ValueType>>> argument_types() const;
  Result<ValueType> return_type() const;

private:
  static Result<FunctionProto> add(
      HandleRef handle,
      const ValueType &return_type,
      const std::vector<std::pair<std::string, ValueType>> &args);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const FunctionProto & /*type*/);
};

class Function : public Type<Function, BTF_KIND_FUNC> {
public:
  Function(HandleRef &&handle, uint32_t type_id)
      : Type<Function, BTF_KIND_FUNC>(std::move(handle), type_id) {};

  enum Linkage {
    Static = BTF_FUNC_STATIC,
    Global = BTF_FUNC_GLOBAL,
    Extern = BTF_FUNC_EXTERN,
  };

  Result<FunctionProto> type() const;
  Linkage linkage() const;
  std::string name() const;

private:
  static Result<Function> add(HandleRef handle,
                              const std::string &name,
                              Linkage linkage,
                              const FunctionProto &proto);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Function & /*type*/);
};

class Var : public Type<Var, BTF_KIND_VAR> {
public:
  Var(HandleRef &&handle, uint32_t type_id)
      : Type<Var, BTF_KIND_VAR>(std::move(handle), type_id) {};

  enum Linkage {
    Static = BTF_VAR_STATIC,
    Global = BTF_VAR_GLOBAL_ALLOCATED,
    Extern = BTF_VAR_GLOBAL_EXTERN,
  };

  Result<ValueType> type() const;
  Linkage linkage() const;
  std::string name() const;

private:
  static Result<Var> add(HandleRef handle,
                         const std::string &name,
                         Linkage linkage,
                         const ValueType &type);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/, const Var & /*type*/);
};

class DataSection : public Type<DataSection, BTF_KIND_DATASEC> {
public:
  DataSection(HandleRef &&handle, uint32_t type_id)
      : Type<DataSection, BTF_KIND_DATASEC>(std::move(handle), type_id) {};

  std::string name() const;

private:
  static Result<DataSection> add(HandleRef handle,
                                 const std::string &name,
                                 const std::vector<Var> &vars);
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const DataSection & /*type*/);
};

class Float : public Type<Float, BTF_KIND_FLOAT> {
public:
  Float(HandleRef &&handle, uint32_t type_id)
      : Type<Float, BTF_KIND_FLOAT>(std::move(handle), type_id) {};

private:
  // We don't presently support floating point operations, and hence do not
  // have the ability to add anything to this type system.
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const Float & /*type*/);
};

class DeclTag : public Type<DeclTag, BTF_KIND_DECL_TAG> {
public:
  DeclTag(HandleRef &&handle, uint32_t type_id)
      : Type<DeclTag, BTF_KIND_DECL_TAG>(std::move(handle), type_id) {};

  std::string value() const;

private:
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const DeclTag & /*type*/);
};

class TypeTag : public Type<TypeTag, BTF_KIND_TYPE_TAG> {
public:
  TypeTag(HandleRef &&handle, uint32_t type_id)
      : Type<TypeTag, BTF_KIND_TYPE_TAG>(std::move(handle), type_id) {};

  std::string value() const;
  Result<AnyType> element_type() const;

private:
  friend class Types;
  friend std::ostream &operator<<(std::ostream & /*out*/,
                                  const TypeTag & /*type*/);
};

// VariantType represents a variant over some set of possible types.
template <typename... Ts>
class VariantType {
public:
  VariantType(std::variant<Ts...> value) : value_(std::move(value)) {};

  // Allow automatic construct from any supported type.
  template <typename U>
  VariantType(const U &value)
    requires((std::is_same_v<U, Ts> || ...))
      : value_(value){};

  // Allow conversion between types as long as one is strictly a subset of the
  // other. In general, this allows `ValueType` to `AnyType` implicit
  // conversion.
  template <typename... Us>
  VariantType(VariantType<Us...> other)
      : VariantType(
            std::visit([](const auto &v) -> std::variant<Ts...> { return v; },
                       other.value())){};

  // Checks to see if this is the given kind.
  template <typename T>
  bool is() const
  {
    return std::holds_alternative<T>(value_);
  }

  // Interpret as the given kind; use `is` first.
  template <typename T>
  const T &as() const
  {
    return std::get<T>(value_);
  }

  // Return the size of the type.
  Result<size_t> size() const
  {
    return std::visit([](const auto &v) { return v.size(); }, value_);
  }

  // Returns the alignment of the type.
  Result<size_t> alignment() const
  {
    return std::visit([](const auto &v) { return v.alignment(); }, value_);
  }

  // Return the underlying type_id for the type.
  uint32_t type_id() const
  {
    return std::visit([](const auto &v) { return v.type_id(); }, value_);
  }

  static Result<VariantType<Ts...>> lookup(HandleRef handle, uint32_t type_id)
  {
    const auto *t = btf__type_by_id(handle->btf_library(), type_id);
    assert(t != nullptr);
    auto k = btf_kind(t);
    return tryLookup<Ts...>(k, std::move(handle), type_id);
  }

  static Result<VariantType<Ts...>> lookup(HandleRef handle,
                                           const std::string &name)
  {
    return tryLookup<Ts...>(std::move(handle), name);
  }

  const std::variant<Ts...> &value() const
  {
    return value_;
  }

private:
  std::variant<Ts...> value_;

  template <typename First, typename... Rest>
  static Result<VariantType<Ts...>> tryLookup(uint32_t kind,
                                              HandleRef handle,
                                              uint32_t type_id)
  {
    if (First::is(kind)) {
      // This matches the kind provided, so we delegate to this class. Note
      // that this may still return an error, and we propagate that explicitly.
      auto ok = First::lookup(std::move(handle), type_id);
      if (!ok) {
        return ok.takeError();
      }
      return VariantType<Ts...>(std::move(*ok));
    }
    if constexpr (sizeof...(Rest) != 0) {
      // Keep tring the rest of the underlying types.
      return tryLookup<Rest...>(kind, std::move(handle), type_id);
    }
    return make_error<UnknownType>(type_id);
  }

  template <typename First, typename... Rest>
  static Result<VariantType<Ts...>> tryLookup(HandleRef handle,
                                              const std::string &name)
  {
    auto ok = First::lookup(handle, name);
    if (ok) {
      return std::move(*ok);
    }
    if constexpr (sizeof...(Rest) != 0) {
      return tryLookup<Rest...>(std::move(handle), name);
    }
    return make_error<UnknownType>(name);
  }

  friend class Types;
  template <typename... Us>
  friend std::ostream &operator<<(std::ostream &, const VariantType<Us...> &);
};

template <typename... Ts>
std::ostream &operator<<(std::ostream &out, const VariantType<Ts...> &type)
{
  std::visit([&](const auto &v) { out << v; }, type.value_);
  return out;
}

// Information for fields.
struct FieldInfo {
  ValueType type;
  size_t bit_offset;
  size_t bit_size;
};

namespace detail {

// Basic iterator over times, used to provide a view into the system.
class TypeIterator {
public:
  using value_type = AnyType;
  using difference_type = std::ptrdiff_t;
  class Sentinel {
  public:
    uint32_t limit;
  }; // Used for `end`.

  TypeIterator(HandleRef handle, uint32_t type_id)
      : handle_(std::move(handle)), type_id_(type_id) {};

  AnyType operator*() const
  {
    auto ok = AnyType::lookup(handle_, type_id_);
    if (!ok) {
      // We expect this to happen only if the iterator is being used
      // incorrectly. If exceptions are disable in this case, then everything
      // will merely die. This seems like the best outcome.
      std::stringstream ss;
      ss << ok.takeError();
      throw std::out_of_range(ss.str());
    }
    return std::move(*ok);
  }

  TypeIterator &operator++()
  {
    type_id_++;
    return *this;
  }

  TypeIterator operator++(int)
  {
    TypeIterator temp(handle_, type_id_);
    ++(*this);
    return temp;
  }

  bool operator==(const TypeIterator &other) const
  {
    return handle_ == other.handle_ && type_id_ == other.type_id_;
  }
  bool operator==(const Sentinel &other) const
  {
    return type_id_ >= other.limit;
  }

private:
  HandleRef handle_;
  uint32_t type_id_;
};

} // namespace detail

// Types represents a self-contained type system. It is typically constructed
// from a serialized BTF dataset, but may be constructed dynamically.
class Types {
public:
  Types() : handle_(std::make_shared<detail::Handle>()) {};
  Types(HandleRef &&handle) : handle_(std::move(handle)) {};
  Types(const Types &base)
      : handle_(std::make_shared<detail::Handle>(base.handle_)) {};
  Types(struct btf *btf) : handle_(std::make_shared<detail::Handle>(btf)) {};
  Types(struct btf *btf, const Types &base) : handle_(std::make_shared<detail::Handle>(btf, base.handle_)) {};
  Types(Types &&other) = default;
  Types &operator=(Types &&other) = default;

  static Result<Types> parse(const void *data, size_t sz);
  static Result<Types> parse(const Types &base, const void *data, size_t sz);

  // Iterators.
  detail::TypeIterator begin()
  {
    return { handle_, 0 };
  }
  detail::TypeIterator::Sentinel end()
  {
    return { .limit = static_cast<uint32_t>(size()) };
  }

  // Returns the number of types.
  size_t size() const;

  // See `bpf__distill_base`.
  Result<Types> distill();

  // Switches the base of this system to another.
  Result<OK> relocate(const Types &other);

  // Append another type system to this one.
  Result<OK> append(const Types &other);

  // Add adds the given type.
  template <typename T, typename... Args>
  Result<T> add(Args... args)
  {
    return T::add(handle_, args...);
  }

  // Lookup will lookup the given type by the type string.
  template <typename T = AnyType>
  Result<T> lookup(const std::string &name) const
  {
    return T::lookup(handle_, name);
  }

  // ... or, we can lookup by the type_id.
  template <typename T = AnyType>
  Result<T> lookup(uint32_t type_id) const
  {
    return T::lookup(handle_, type_id);
  }

  // Dumps a stream of C declarations.
  Result<> emit_decl(std::ostream &out) const;

private:
  HandleRef handle_;
};

} // namespace bpftrace::btf
