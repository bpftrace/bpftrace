#include "struct.h"
#include <iomanip>

namespace bpftrace {

bool Bitfield::operator==(const Bitfield &other) const {
  return read_bytes == other.read_bytes
    && mask == other.mask
    && access_rshift == other.access_rshift;
}

bool Bitfield::operator!=(const Bitfield &other) const {
  return !(*this == other);
}

std::unique_ptr<Tuple> Tuple::Create(std::vector<SizedType> fields)
{
  // See llvm::StructLayout::StructLayout source
  std::unique_ptr<Tuple> tuple(new Tuple);
  ssize_t offset = 0;
  ssize_t struct_align = 1;

  for (auto &field : fields)
  {
    auto align = field.GetAlignment();
    struct_align = std::max(align, struct_align);
    auto size = field.GetSize();

    auto padding = (align - (offset % align)) % align;
    if (padding)
      tuple->padded = true;
    offset += padding;

    tuple->fields.push_back(Field{
        .type = field,
        .offset = offset,
        .is_bitfield = false,
        .bitfield = Bitfield{},
    });

    offset += size;
  }

  auto padding = (struct_align - (offset % struct_align)) % struct_align;

  tuple->size = offset + padding;
  tuple->align = struct_align;

  return tuple;
}

void Tuple::Dump(std::ostream &os)
{
  os << "tuple {" << std::endl;

  auto pad = [](int size) -> std::string {
    return "__pad[" + std::to_string(size) + "]";
  };

  auto prefix = [](int offset, std::ostream &os) -> std::ostream & {
    os << " " << std::setfill(' ') << std::setw(3) << offset << " | ";
    return os;
  };

  ssize_t offset = 0;
  for (const auto &field : fields)
  {
    auto delta = field.offset - offset;
    if (delta)
    {
      prefix(offset, os) << pad(delta) << std::endl;
    }
    prefix(offset + delta, os) << field.type << std::endl;
    offset = field.offset + field.type.GetSize();
  }
  os << "} sizeof: [" << size << "]" << std::endl;
}

bool Struct::HasField(const std::string &name) const
{
  return fields.find(name) != fields.end();
}

const Field &Struct::GetField(const std::string &name) const
{
  return fields.at(name);
}

void Struct::AddField(const std::string &field_name,
                      const SizedType &type,
                      ssize_t offset,
                      bool is_bitfield,
                      const Bitfield &bitfield,
                      bool is_data_loc)
{
  fields[field_name] = Field{ .type = type,
                              .offset = offset,
                              .is_bitfield = is_bitfield,
                              .bitfield = bitfield,
                              .is_data_loc = is_data_loc };
}

void StructManager::Add(const std::string &name, size_t size)
{
  if (struct_map_.find(name) != struct_map_.end())
    throw std::runtime_error("Type redefinition: type with name \'" + name +
                             "\' already exists");
  struct_map_[name] = std::make_shared<Struct>(size);
}

std::shared_ptr<Struct> StructManager::Lookup(const std::string &name) const
{
  auto s = struct_map_.find(name);
  return s != struct_map_.end() ? s->second : nullptr;
}

std::shared_ptr<Struct> StructManager::LookupOrAdd(const std::string &name,
                                                   size_t size)
{
  auto s = struct_map_.insert({ name, std::make_shared<Struct>(size) });
  return s.first->second;
}

bool StructManager::Has(const std::string &name) const
{
  return struct_map_.find(name) != struct_map_.end();
}

} // namespace bpftrace
