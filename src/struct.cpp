#include "struct.h"

#include <iomanip>
#include <limits>

#include "log.h"
#include "utils.h"

namespace bpftrace {

const size_t BIFTIELD_BIT_WIDTH_MAX = sizeof(uint64_t) * 8;

Bitfield::Bitfield(size_t bit_offset, size_t bit_width)
{
  // To handle bitfields, we need to give codegen 3 additional pieces
  // of information: `read_bytes`, `access_rshift`, and `mask`.
  //
  // `read_bytes` tells codegen how many bytes to read starting at
  // `Field::offset`. This information is necessary because we can't always
  // issue, for example, a 1 byte read, as the bitfield could be the last 4 bits
  // of the struct. Reading past the end of the struct could cause a page fault.
  // Therefore, we compute the minimum number of bytes necessary to fully read
  // the bitfield. This will always keep the read within the bounds of the
  // struct.
  //
  // `access_rshift` tells codegen how much to shift the masked value so that
  // the LSB of the bitfield is the LSB of the interpreted integer.
  //
  // `mask` tells codegen how to mask out the surrounding bitfields.

  if (bit_width > BIFTIELD_BIT_WIDTH_MAX) {
    LOG(WARNING) << "bitfield bitwidth " << bit_width << "is not supported."
                 << " Use bitwidth " << BIFTIELD_BIT_WIDTH_MAX;
    bit_width = BIFTIELD_BIT_WIDTH_MAX;
  }
  if (bit_width == BIFTIELD_BIT_WIDTH_MAX)
    mask = std::numeric_limits<uint64_t>::max();
  else
    mask = (1ULL << bit_width) - 1;
  // Round up to nearest byte
  read_bytes = (bit_offset + bit_width + 7) / 8;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  access_rshift = bit_offset;
#else
  access_rshift = (read_bytes * 8 - bit_offset - bit_width);
#endif
}

bool Bitfield::operator==(const Bitfield &other) const
{
  return read_bytes == other.read_bytes && mask == other.mask &&
         access_rshift == other.access_rshift;
}

bool Bitfield::operator!=(const Bitfield &other) const
{
  return !(*this == other);
}

// Creates a struct or tuple with the given field types.
// If field_names is empty then all fields with be created without names.
std::unique_ptr<Struct> Struct::CreateRecord(
    const std::vector<SizedType> &fields,
    const std::vector<std::string_view> &field_names)
{
  assert(field_names.empty() || field_names.size() == fields.size());

  // See llvm::StructLayout::StructLayout source
  auto record = std::make_unique<Struct>(0);
  ssize_t offset = 0;
  ssize_t struct_align = 1;

  for (size_t i = 0; i < fields.size(); i++) {
    const auto &field = fields[i];
    auto align = field.GetInTupleAlignment();
    struct_align = std::max(align, struct_align);
    auto size = field.GetSize();

    auto padding = (align - (offset % align)) % align;
    if (padding)
      record->padded = true;
    offset += padding;

    record->fields.push_back(Field{
        .name = field_names.empty() ? "" : std::string{ field_names[i] },
        .type = field,
        .offset = offset,
        .bitfield = std::nullopt,
    });

    offset += size;
  }

  auto padding = (struct_align - (offset % struct_align)) % struct_align;

  record->size = offset + padding;
  record->align = struct_align;

  return record;
}

std::unique_ptr<Struct> Struct::CreateTuple(
    const std::vector<SizedType> &fields)
{
  return CreateRecord(fields, {});
}

void Struct::Dump(std::ostream &os)
{
  os << " {" << std::endl;

  auto pad = [](int size) -> std::string {
    return "__pad[" + std::to_string(size) + "]";
  };

  auto prefix = [](int offset, std::ostream &os) -> std::ostream & {
    os << " " << std::setfill(' ') << std::setw(3) << offset << " | ";
    return os;
  };

  ssize_t offset = 0;
  for (const auto &field : fields) {
    auto delta = field.offset - offset;
    if (delta) {
      prefix(offset, os) << pad(delta) << std::endl;
    }
    prefix(offset + delta, os) << field.type << std::endl;
    offset = field.offset + field.type.GetSize();
  }
  os << "} sizeof: [" << size << "]" << std::endl;
}

bool Struct::HasField(const std::string &name) const
{
  for (auto &field : fields) {
    if (field.name == name)
      return true;
  }
  return false;
}

const Field &Struct::GetField(const std::string &name) const
{
  for (auto &field : fields) {
    if (field.name == name)
      return field;
  }
  throw FatalUserException("struct has no field named " + name);
}

void Struct::AddField(const std::string &field_name,
                      const SizedType &type,
                      ssize_t offset,
                      const std::optional<Bitfield> &bitfield,
                      bool is_data_loc)
{
  if (!HasField(field_name))
    fields.emplace_back(Field{ .name = field_name,
                               .type = type,
                               .offset = offset,
                               .bitfield = bitfield,
                               .is_data_loc = is_data_loc });
}

bool Struct::HasFields() const
{
  return !fields.empty();
}

void Struct::ClearFields()
{
  fields.clear();
}

void StructManager::Add(const std::string &name,
                        size_t size,
                        bool allow_override)
{
  if (struct_map_.find(name) != struct_map_.end())
    throw FatalUserException("Type redefinition: type with name \'" + name +
                             "\' already exists");
  struct_map_[name] = std::make_unique<Struct>(size, allow_override);
}

void StructManager::Add(const std::string &name, Struct &&record)
{
  struct_map_[name] = std::make_shared<Struct>(std::move(record));
}

std::weak_ptr<Struct> StructManager::Lookup(const std::string &name) const
{
  auto s = struct_map_.find(name);
  return s != struct_map_.end() ? s->second : std::weak_ptr<Struct>();
}

std::weak_ptr<Struct> StructManager::LookupOrAdd(const std::string &name,
                                                 size_t size,
                                                 bool allow_override)
{
  auto s = struct_map_.insert(
      { name, std::make_unique<Struct>(size, allow_override) });
  return s.first->second;
}

bool StructManager::Has(const std::string &name) const
{
  return struct_map_.find(name) != struct_map_.end();
}

std::weak_ptr<Struct> StructManager::AddAnonymousStruct(
    const std::vector<SizedType> &fields,
    const std::vector<std::string_view> &field_names)
{
  auto t = anonymous_types_.insert(Struct::CreateRecord(fields, field_names));
  return *t.first;
}

std::weak_ptr<Struct> StructManager::AddTuple(
    const std::vector<SizedType> &fields)
{
  auto t = anonymous_types_.insert(Struct::CreateTuple(fields));
  return *t.first;
}

size_t StructManager::GetTuplesCnt() const
{
  return anonymous_types_.size();
}

const Field *StructManager::GetProbeArg(const ast::Probe &probe,
                                        const std::string &arg_name)
{
  auto args = Lookup(probe.args_typename()).lock();
  if (!args || !args->HasField(arg_name))
    return nullptr;

  return &args->GetField(arg_name);
}

} // namespace bpftrace
