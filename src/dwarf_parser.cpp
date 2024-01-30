#include "dwarf_parser.h"

#ifdef HAVE_LIBDW

#include "bpftrace.h"
#include "log.h"

#include <dwarf.h>
#include <elfutils/libdw.h>

namespace bpftrace {

struct FuncInfo {
  std::string name;
  Dwarf_Die die;
};

Dwarf::Dwarf(BPFtrace *bpftrace, const std::string &file_path)
    : bpftrace_(bpftrace), file_path_(file_path)
{
  callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
  callbacks.section_address = dwfl_offline_section_address;
  callbacks.debuginfo_path = NULL;
  dwfl = dwfl_begin(&callbacks);
  dwfl_report_offline(dwfl, file_path.c_str(), file_path.c_str(), -1);
  dwfl_report_end(dwfl, NULL, NULL);
}

std::unique_ptr<Dwarf> Dwarf::GetFromBinary(BPFtrace *bpftrace,
                                            const std::string &file_path)
{
  std::unique_ptr<Dwarf> dwarf(new Dwarf(bpftrace, file_path));
  Dwarf_Addr bias;
  if (dwfl_nextcu(dwarf->dwfl, NULL, &bias) == NULL)
    return nullptr;

  return dwarf;
}

Dwarf::~Dwarf()
{
  dwfl_end(dwfl);
}

static int get_func_die_cb(Dwarf_Die *func_die, void *arg)
{
  auto *func_info = static_cast<struct FuncInfo *>(arg);
  if (dwarf_hasattr(func_die, DW_AT_name) &&
      dwarf_diename(func_die) == func_info->name) {
    func_info->die = *func_die;
    return DWARF_CB_ABORT;
  }
  return DWARF_CB_OK;
}

std::optional<Dwarf_Die> Dwarf::get_func_die(const std::string &function) const
{
  struct FuncInfo func_info = { .name = function, .die = {} };

  Dwarf_Die *cudie = nullptr;
  Dwarf_Addr cubias;
  while ((cudie = dwfl_nextcu(dwfl, cudie, &cubias)) != nullptr) {
    if (dwarf_getfuncs(cudie, get_func_die_cb, &func_info, 0) > 0)
      return func_info.die;
  }

  return std::nullopt;
}

static Dwarf_Die type_of(Dwarf_Die &die)
{
  Dwarf_Attribute attr;
  Dwarf_Die type_die;
  dwarf_formref_die(dwarf_attr_integrate(&die, DW_AT_type, &attr), &type_die);
  return type_die;
}

std::vector<Dwarf_Die> Dwarf::function_param_dies(
    const std::string &function) const
{
  auto func_die = get_func_die(function);
  if (!func_die)
    return {};

  return get_all_children_with_tag(&func_die.value(), DW_TAG_formal_parameter);
}

std::string Dwarf::get_type_name(Dwarf_Die &type_die) const
{
  auto tag = dwarf_tag(&type_die);
  switch (tag) {
    case DW_TAG_base_type:
    case DW_TAG_typedef:
      return dwarf_diename(&type_die);
    case DW_TAG_pointer_type: {
      if (dwarf_hasattr(&type_die, DW_AT_type)) {
        Dwarf_Die inner_type = type_of(type_die);
        return get_type_name(inner_type) + "*";
      }
      return "void*";
    }
    case DW_TAG_structure_type:
    case DW_TAG_union_type:
    case DW_TAG_enumeration_type: {
      std::string prefix;
      if (tag == DW_TAG_structure_type)
        prefix = "struct ";
      else if (tag == DW_TAG_union_type)
        prefix = "union ";
      else
        prefix = "enum ";

      if (dwarf_hasattr(&type_die, DW_AT_name))
        return prefix + dwarf_diename(&type_die);
      else
        return prefix + "<anonymous>";
    }
    case DW_TAG_const_type: {
      Dwarf_Die inner_type = type_of(type_die);
      if (dwarf_tag(&inner_type) == DW_TAG_pointer_type)
        return get_type_name(inner_type) + " const";
      else
        return "const " + get_type_name(inner_type);
    }
    default:
      return "<unknown type>";
  }
}

Dwarf_Word Dwarf::get_type_encoding(Dwarf_Die &type_die) const
{
  Dwarf_Attribute encoding_attr;
  Dwarf_Word encoding;
  dwarf_formudata(
      dwarf_attr_integrate(&type_die, DW_AT_encoding, &encoding_attr),
      &encoding);
  return encoding;
}

SizedType Dwarf::get_stype(Dwarf_Die &type_die, bool resolve_structs) const
{
  Dwarf_Die type;
  dwarf_peel_type(&type_die, &type);

  auto tag = dwarf_tag(&type);
  auto bit_size = dwarf_hasattr(&type, DW_AT_bit_size)
                      ? dwarf_bitsize(&type)
                      : dwarf_bytesize(&type) * 8;
  switch (tag) {
    case DW_TAG_base_type: {
      Dwarf_Word encoding = get_type_encoding(type);
      switch (encoding) {
        case DW_ATE_boolean:
        case DW_ATE_unsigned:
        case DW_ATE_unsigned_char:
          return CreateUInt(bit_size);
        case DW_ATE_signed:
        case DW_ATE_signed_char:
          return CreateInt(bit_size);
        default:
          return CreateNone();
      }
    }
    case DW_TAG_enumeration_type:
      return CreateUInt(bit_size);
    case DW_TAG_pointer_type: {
      if (dwarf_hasattr(&type, DW_AT_type)) {
        Dwarf_Die inner_type = type_of(type);
        return CreatePointer(get_stype(inner_type, false));
      }
      // void *
      return CreatePointer(CreateNone());
    }
    case DW_TAG_structure_type:
    case DW_TAG_union_type: {
      std::string name = dwarf_diename(&type_die);
      name = (tag == DW_TAG_structure_type ? "struct " : "union ") + name;
      auto result = CreateRecord(
          name, bpftrace_->structs.LookupOrAdd(name, bit_size / 8));
      if (resolve_structs)
        resolve_fields(result);
      return result;
    }
    case DW_TAG_array_type: {
      Dwarf_Die inner_type_die = type_of(type_die);
      Dwarf_Word inner_enc = get_type_encoding(inner_type_die);
      SizedType inner_type = get_stype(inner_type_die);
      SizedType result;
      for (auto &d :
           get_all_children_with_tag(&type_die, DW_TAG_subrange_type)) {
        ssize_t size = get_array_size(d);
        if (dwarf_tag(&inner_type_die) == DW_TAG_base_type &&
            (inner_enc == DW_ATE_signed_char ||
             inner_enc == DW_ATE_unsigned_char))
          result = CreateString(size);
        else
          result = CreateArray(size, inner_type);
        inner_type = result;
      }
      return result;
    }
    default:
      return CreateNone();
  }
}

SizedType Dwarf::get_stype(const std::string &type_name) const
{
  std::string name = type_name;
  if (name.find("struct ") == 0)
    name = name.substr(strlen("struct "));

  auto type_die = find_type(name);
  if (!type_die)
    return CreateNone();

  return get_stype(type_die.value());
}

std::optional<Bitfield> Dwarf::resolve_bitfield(Dwarf_Die &field_die) const
{
  ssize_t bitfield_width = get_bitfield_size(field_die);
  if (bitfield_width == 0)
    return std::nullopt;

  ssize_t bit_offset = get_field_bit_offset(field_die);
  if (dwarf_hasattr(&field_die, DW_AT_data_bit_offset)) {
    // DWARF >= 4
    // DW_AT_data_bit_offset is the offset in bits from the beginning of the
    // containing entity to the beginning of field. In this case, the byte
    // offset of the field is determined by (bit_offset / 8) so the bit offset
    // within the byte is given by (bit_offset % 8).
    return Bitfield(bit_offset % 8, bitfield_width);
  } else {
    // DWARF < 4 (some implementations of DWARF 4 use this, too)
    // Bit offset is given by DW_AT_bit_offset which is the offset in bits of
    // the high order bit of the container type to the high order bit of the
    // storage unit actually containing the bitfield. This representation was
    // designed for big-endian systems, so we must use the same approach to
    // determine the actual bit offset:
    // (size of the container field - DW_AT_bit_offset - bitfield size)
    auto field_size = dwarf_bytesize(&field_die) * 8;
    return Bitfield(field_size - bit_offset - bitfield_width, bitfield_width);
  }
}

void Dwarf::resolve_fields(const SizedType &type) const
{
  if (!type.IsRecordTy())
    return;

  auto str = bpftrace_->structs.Lookup(type.GetName()).lock();
  if (str->HasFields())
    return;

  std::string type_name = type.GetName();
  if (type_name.find("struct ") == 0)
    type_name = type_name.substr(strlen("struct "));
  auto type_die = find_type(type_name);
  if (!type_die)
    return;

  for (auto &field_die :
       get_all_children_with_tag(&type_die.value(), DW_TAG_member)) {
    Dwarf_Die field_type = type_of(field_die);
    str->AddField(dwarf_diename(&field_die),
                  get_stype(field_type),
                  get_field_byte_offset(field_die),
                  resolve_bitfield(field_die),
                  false);
  }
}

std::vector<std::string> Dwarf::get_function_params(
    const std::string &function) const
{
  std::vector<std::string> result;
  for (auto &param_die : function_param_dies(function)) {
    Dwarf_Die type_die = type_of(param_die);
    const std::string type_name = get_type_name(type_die);
    if (dwarf_hasattr(&param_die, DW_AT_name))
      result.push_back(type_name + " " + dwarf_diename(&param_die));
    else
      result.push_back(type_name);
  }
  return result;
}

Struct Dwarf::resolve_args(const std::string &function)
{
  Struct result(0, false);
  int i = 0;
  for (auto &param_die : function_param_dies(function)) {
    Dwarf_Die type_die = type_of(param_die);
    SizedType arg_type = get_stype(type_die);
    arg_type.is_funcarg = true;
    arg_type.funcarg_idx = i++;
    const std::string name = dwarf_hasattr(&param_die, DW_AT_name)
                                 ? dwarf_diename(&param_die)
                                 : "";
    result.AddField(name, arg_type, result.size, std::nullopt, false);
    result.size += arg_type.GetSize();
  }
  return result;
}

std::optional<Dwarf_Die> Dwarf::find_type(const std::string &name) const
{
  Dwarf_Die *cudie = nullptr;
  Dwarf_Addr cubias;
  while ((cudie = dwfl_nextcu(dwfl, cudie, &cubias)) != nullptr) {
    if (auto type_die = get_child_with_tagname(cudie,
                                               DW_TAG_structure_type,
                                               name))
      return type_die;
  }
  return std::nullopt;
}

std::optional<Dwarf_Die> Dwarf::get_child_with_tagname(Dwarf_Die *die,
                                                       int tag,
                                                       const std::string &name)
{
  Dwarf_Die child_die;
  Dwarf_Die *child_iter = &child_die;
  if (dwarf_child(die, &child_die) != 0)
    return std::nullopt;

  do {
    if (dwarf_tag(&child_die) == tag && dwarf_hasattr(&child_die, DW_AT_name) &&
        dwarf_diename(&child_die) == name)
      return child_die;
  } while (dwarf_siblingof(child_iter, &child_die) == 0);

  return std::nullopt;
}

std::vector<Dwarf_Die> Dwarf::get_all_children_with_tag(Dwarf_Die *die, int tag)
{
  Dwarf_Die child_die;
  Dwarf_Die *child_iter = &child_die;
  if (dwarf_child(die, &child_die) != 0)
    return {};

  std::vector<Dwarf_Die> children;
  do {
    if (dwarf_tag(&child_die) == tag)
      children.push_back(child_die);
  } while (dwarf_siblingof(child_iter, &child_die) == 0);

  return children;
}

ssize_t Dwarf::get_array_size(Dwarf_Die &subrange_die)
{
  Dwarf_Attribute size_attr;
  Dwarf_Word size;
  if (dwarf_hasattr(&subrange_die, DW_AT_upper_bound)) {
    dwarf_formudata(
        dwarf_attr_integrate(&subrange_die, DW_AT_upper_bound, &size_attr),
        &size);
    return (ssize_t)size + 1;
  }
  if (dwarf_hasattr(&subrange_die, DW_AT_count)) {
    dwarf_formudata(
        dwarf_attr_integrate(&subrange_die, DW_AT_count, &size_attr), &size);
    return (ssize_t)size;
  }
  return 0;
}

ssize_t Dwarf::get_field_byte_offset(Dwarf_Die &field_die)
{
  if (dwarf_hasattr(&field_die, DW_AT_data_member_location)) {
    Dwarf_Attribute attr;
    Dwarf_Word value;
    if (dwarf_formudata(
            dwarf_attr_integrate(&field_die, DW_AT_data_member_location, &attr),
            &value) >= 0)
      return (ssize_t)value;
  }
  return get_field_bit_offset(field_die) / 8;
}

ssize_t Dwarf::get_field_bit_offset(Dwarf_Die &field_die)
{
  Dwarf_Attribute attr;
  Dwarf_Word value;
  if (dwarf_hasattr(&field_die, DW_AT_data_bit_offset)) { // DWARF >= 4
    if (dwarf_formudata(
            dwarf_attr_integrate(&field_die, DW_AT_data_bit_offset, &attr),
            &value) >= 0)
      return (ssize_t)value;
  }
  if (dwarf_hasattr(&field_die, DW_AT_bit_offset)) { // DWARF < 4
    if (dwarf_formudata(
            dwarf_attr_integrate(&field_die, DW_AT_bit_offset, &attr),
            &value) >= 0)
      return (ssize_t)value;
  }

  return 0;
}

ssize_t Dwarf::get_bitfield_size(Dwarf_Die &field_die)
{
  Dwarf_Attribute attr;
  Dwarf_Word value;
  if (dwarf_hasattr(&field_die, DW_AT_bit_size)) {
    if (dwarf_formudata(dwarf_attr_integrate(&field_die, DW_AT_bit_size, &attr),
                        &value) >= 0)
      return (ssize_t)value;
  }
  return 0;
}

} // namespace bpftrace

#endif // HAVE_LIBDW
