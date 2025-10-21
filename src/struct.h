#pragma once

#include <cereal/access.hpp>
#include <map>
#include <memory>
#include <optional>

#include "ast/ast.h"
#include "types.h"
#include "util/hash.h"

namespace bpftrace {

static constexpr auto RETVAL_FIELD_NAME = "$retval";

struct Bitfield {
  Bitfield(size_t bit_offset, size_t bit_width);
  Bitfield(size_t read_bytes, size_t access_rshift, uint64_t mask)
      : read_bytes(read_bytes), access_rshift(access_rshift), mask(mask)
  {
  }
  Bitfield() // necessary for serialization
      = default;

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
  bool is_tracepoint_args = false;

  Struct() = default; // Used for serialization.
  Struct(const Struct &other) = delete;
  Struct &operator=(const Struct &other) = delete;
  Struct(Struct &&other) = default;
  Struct &operator=(Struct &&other) = default;

  explicit Struct(int size, bool allow_override = true)
      : size(size), allow_override(allow_override)
  {
  }

  bool HasField(const std::string &name) const;
  const Field &GetField(const std::string &name) const;
  void AddField(const std::string &field_name,
                const SizedType &type,
                ssize_t offset = 0,
                const std::optional<Bitfield> &bitfield = std::nullopt);
  bool HasFields() const;
  void ClearFields();

  static std::shared_ptr<Struct> CreateRecord(
      const std::vector<SizedType> &fields,
      const std::vector<std::string_view> &field_names);
  static std::shared_ptr<Struct> CreateTuple(
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

class StructManager {
public:
  // struct map manipulation
  std::weak_ptr<Struct> Add(const std::string &name,
                            size_t size,
                            bool allow_override = true);
  void Add(const std::string &name, std::shared_ptr<Struct> &&record);
  std::weak_ptr<Struct> Lookup(const std::string &name) const;
  std::weak_ptr<Struct> LookupOrAdd(const std::string &name,
                                    size_t size,
                                    bool allow_override = true);
  bool Has(const std::string &name) const;

  // probe args lookup
  const Field *GetProbeArg(const ast::Probe &probe,
                           const std::string &arg_name);

private:
  std::map<std::string, std::shared_ptr<Struct>> struct_map_;
};

} // namespace bpftrace
