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
    auto size = field.size;

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
    offset = field.offset + field.type.size;
  }
  os << "} sizeof: [" << size << "]" << std::endl;
}

} // namespace bpftrace
