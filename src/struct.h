#pragma once

#include <map>
#include <memory>
#include <optional>

#include <cereal/access.hpp>

#include "ast/ast.h"
#include "types.h"
#include "utils.h"

namespace bpftrace {

struct Bitfield {
  Bitfield(size_t byte_offset, size_t bit_width);
  Bitfield(size_t read_bytes, size_t access_rshift, uint64_t mask)
      : read_bytes(read_bytes), access_rshift(access_rshift), mask(mask)
  {
  }
  Bitfield() // necessary for serialization
  {
  }

  bool operator==(const Bitfield &other) const;
  bool operator!=(const Bitfield &other) const;

  // Read `read_bytes` bytes starting from this field's offset
  size_t read_bytes;
  // Then rshift the resulting value by `access_rshift` to get field value
  size_t access_rshift;
  // Then logical AND `mask` to mask out everything but this bitfield
  uint64_t mask;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(read_bytes, access_rshift, mask);
  }
};

struct Field {
  std::string name;
  SizedType type;
  ssize_t offset;

  std::optional<Bitfield> bitfield;

  // Used for tracepoint __data_loc's
  //
  // If true, this field is a 32 bit integer whose value encodes information on
  // where to find the actual data. The first 2 bytes is the size of the data.
  // The last 2 bytes is the offset from the start of the tracepoint struct
  // where the data begins.
  bool is_data_loc = false;

  bool operator==(const Field &rhs) const
  {
    return name == rhs.name && type == rhs.type && offset == rhs.offset &&
           bitfield == rhs.bitfield && is_data_loc == rhs.is_data_loc;
  }

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(name, type, offset, bitfield, is_data_loc);
  }
};

using Fields = std::vector<Field>;

struct Struct {
  int size = -1; // in bytes
  int align = 1; // in bytes, used for tuples only
  bool padded = false;
  Fields fields;

  bool allow_override = true;

  Struct() = default;
  explicit Struct(int size, bool allow_override = true)
      : size(size), allow_override(allow_override)
  {
  }

  bool HasField(const std::string &name) const;
  const Field &GetField(const std::string &name) const;
  void AddField(const std::string &field_name,
                const SizedType &type,
                ssize_t offset,
                const std::optional<Bitfield> &bitfield,
                bool is_data_loc);
  bool HasFields() const;
  void ClearFields();

  static std::unique_ptr<Struct> CreateRecord(
      const std::vector<SizedType> &fields,
      const std::vector<std::string_view> &field_names);
  static std::unique_ptr<Struct> CreateTuple(
      const std::vector<SizedType> &fields);
  void Dump(std::ostream &os);

  bool operator==(const Struct &rhs) const
  {
    return size == rhs.size && align == rhs.align && padded == rhs.padded &&
           fields == rhs.fields;
  }
  bool operator!=(const Struct &rhs) const
  {
    return !(*this == rhs);
  }

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(size, align, padded, fields);
  }
};

std::ostream &operator<<(std::ostream &os, const Fields &t);

} // namespace bpftrace

namespace std {
template <>
struct hash<bpftrace::Struct> {
  size_t operator()(const bpftrace::Struct &s) const
  {
    size_t hash = std::hash<int>()(s.size);
    for (auto &field : s.fields)
      bpftrace::hash_combine(hash, field.type);
    return hash;
  }
};

template <>
struct hash<shared_ptr<bpftrace::Struct>> {
  size_t operator()(const std::shared_ptr<bpftrace::Struct> &s_ptr) const
  {
    return std::hash<bpftrace::Struct>()(*s_ptr);
  }
};

template <>
struct equal_to<shared_ptr<bpftrace::Struct>> {
  bool operator()(const std::shared_ptr<bpftrace::Struct> &lhs,
                  const std::shared_ptr<bpftrace::Struct> &rhs) const
  {
    return *lhs == *rhs;
  }
};
} // namespace std

namespace bpftrace {

class StructManager {
public:
  // struct map manipulation
  void Add(const std::string &name, size_t size, bool allow_override = true);
  void Add(const std::string &name, Struct &&record);
  std::weak_ptr<Struct> Lookup(const std::string &name) const;
  std::weak_ptr<Struct> LookupOrAdd(const std::string &name,
                                    size_t size,
                                    bool allow_override = true);
  bool Has(const std::string &name) const;

  std::weak_ptr<Struct> AddAnonymousStruct(
      const std::vector<SizedType> &fields,
      const std::vector<std::string_view> &field_names);
  std::weak_ptr<Struct> AddTuple(const std::vector<SizedType> &fields);
  size_t GetTuplesCnt() const;

  // probe args lookup
  const Field *GetProbeArg(const ast::Probe &probe,
                           const std::string &arg_name);

private:
  std::map<std::string, std::shared_ptr<Struct>> struct_map_;
  std::unordered_set<std::shared_ptr<Struct>> anonymous_types_;
};

} // namespace bpftrace
