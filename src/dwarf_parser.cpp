#include "dwarf_parser.h"

namespace bpftrace {

char DwarfParseError::ID;

void DwarfParseError::log(llvm::raw_ostream &OS) const
{
  OS << "DWARF error: " << msg_;
}

} // namespace bpftrace

#ifdef HAVE_LIBDW

#include "bpftrace.h"
#include "log.h"
#include "util/paths.h"

#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwelf.h>

namespace bpftrace {

struct FuncInfo {
  std::string name;
  Dwarf_Die die;
};

Dwarf::Dwarf(BPFtrace *bpftrace,
             const std::string &file_path,
             std::string debuginfo_path)
    : bpftrace_(bpftrace),
      file_path_(file_path),
      debuginfo_path_(std::move(debuginfo_path))
{
  debuginfo_path_cstr_ = debuginfo_path_.c_str();
  callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
  callbacks.section_address = dwfl_offline_section_address;
  callbacks.debuginfo_path = const_cast<char **>(&debuginfo_path_cstr_);
  dwfl = dwfl_begin(&callbacks);
  dwfl_report_offline(dwfl, file_path.c_str(), file_path.c_str(), -1);
  dwfl_report_end(dwfl, nullptr, nullptr);
}

static bool debug_alt_link_missing(::Dwarf *dwarf)
{
  const char *alt_name = nullptr;
  const void *build_id = nullptr;
  return dwelf_dwarf_gnu_debugaltlink(dwarf, &alt_name, &build_id) > 0 &&
         dwarf_getalt(dwarf) == nullptr;
}

std::unique_ptr<Dwarf> Dwarf::GetFromBinary(BPFtrace *bpftrace,
                                            const std::string &file_path,
                                            const std::string &debuginfo_path)
{
  std::unique_ptr<Dwarf> dwarf(new Dwarf(bpftrace, file_path, debuginfo_path));
  Dwarf_Addr bias;
  Dwarf_Die *cudie = dwfl_nextcu(dwarf->dwfl, nullptr, &bias);
  if (cudie == nullptr)
    return nullptr;

  // If the compilation units reference a separate partial type unit via
  // debugaltlink, perform an early check to ensure that the corresponding
  // shared file exists. This prevents unexpected nullptrs caused by missing
  // data from crashing the runtime.
  Dwfl_Module *mod = dwfl_cumodule(cudie);
  ::Dwarf *dw = dwfl_module_getdwarf(mod, &bias);
  if (debug_alt_link_missing(dw)) {
    return nullptr;
  }

  return dwarf;
}

Dwarf::~Dwarf()
{
  dwfl_end(dwfl);
}

bool Dwarf::next_cu_info(CuInfo *cu_info) const
{
  Dwarf_Addr cubias;
  cu_info->cudie = dwfl_nextcu(dwfl, cu_info->cudie, &cubias);
  if (cu_info->cudie == nullptr)
    return false;

  cu_info->split_cudie = std::nullopt;

  // Try to find split debug info for skeleton CU's .
  uint8_t unit_type = 0;
  Dwarf_Die subdie = {};
  if (dwarf_cu_info(cu_info->cudie->cu,
                    nullptr,
                    &unit_type,
                    nullptr,
                    &subdie,
                    nullptr,
                    nullptr,
                    nullptr) == 0 &&
      unit_type == DW_UT_skeleton) {
    // libdw sets subdie to zero, if split CU is not found.
    const Dwarf_Die zero = {};
    if (std::memcmp(&subdie, &zero, sizeof(Dwarf_Die)) != 0) {
      cu_info->split_cudie = subdie;
    } else {
      const char *dwo_name = nullptr;
      Dwarf_Attribute attr;
      if (dwarf_attr(cu_info->cudie, DW_AT_dwo_name, &attr) ||
          dwarf_attr(cu_info->cudie, DW_AT_GNU_dwo_name, &attr)) {
        dwo_name = dwarf_formstring(&attr);
      }
      const std::string binary =
          std::filesystem::path(file_path_).stem().string();
      // Fall back to binary.dwo, if the attribute is missing
      const std::string dwo =
          dwo_name ? std::filesystem::path(dwo_name).filename().string()
                   : binary + ".dwo";
      // Emit a warning instead of an error, since skeleton CU's do contain
      // minimal debug info (e.g. lines, address ranges).
      LOG(WARNING) << "Unable to find split debug file '" << dwo << "' or '"
                   << binary << ".dwp' for '" << file_path_
                   << "', debugging information may be incomplete!";
    }
  }

  return true;
}

static std::string get_die_name(Dwarf_Die *die)
{
  // If the DWARF section containing the DIE name string is malformed or
  // missing, dwarf_diename() will return nullptr, so we wrap it to prevent
  // undefined behaviour.
  const char *name = dwarf_diename(die);
  return name ?: "";
}

static int get_func_die_cb(Dwarf_Die *func_die, void *arg)
{
  auto *func_info = static_cast<struct FuncInfo *>(arg);
  if (dwarf_hasattr_integrate(func_die, DW_AT_name) &&
      get_die_name(func_die) == func_info->name) {
    func_info->die = *func_die;
    return DWARF_CB_ABORT;
  }
  return DWARF_CB_OK;
}

std::optional<Dwarf_Die> Dwarf::get_func_die(const std::string &function) const
{
  struct FuncInfo func_info = { .name = function, .die = {} };

  CuInfo cu_info = {};
  while (next_cu_info(&cu_info)) {
    if (dwarf_getfuncs(cu_info.cu_die(), get_func_die_cb, &func_info, 0) > 0)
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
      return get_die_name(&type_die);
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
        prefix = STRUCT_PREFIX;
      else if (tag == DW_TAG_union_type)
        prefix = UNION_PREFIX;
      else
        prefix = ENUM_PREFIX;

      if (dwarf_hasattr(&type_die, DW_AT_name))
        return prefix + get_die_name(&type_die);
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
      std::string name = get_die_name(&type_die);
      name = std::string(tag == DW_TAG_structure_type ? STRUCT_PREFIX
                                                      : UNION_PREFIX) +
             name;
      auto result = CreateCStruct(
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
             inner_enc == DW_ATE_unsigned_char)) {
          // See src/btf.cpp for why this is converted to a string
          result = CreateString(size);
        } else {
          result = CreateArray(size, inner_type);
        }
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
  if (name.starts_with(STRUCT_PREFIX))
    name = name.substr(STRUCT_PREFIX.length());

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
  if (!type.IsCStructTy())
    return;

  auto str = bpftrace_->structs.Lookup(type.GetName()).lock();
  if (str->HasFields())
    return;

  std::string type_name = type.GetName();
  if (type_name.starts_with(STRUCT_PREFIX))
    type_name = type_name.substr(STRUCT_PREFIX.length());
  auto type_die = find_type(type_name);
  if (!type_die)
    return;

  for (auto &field_die :
       get_all_children_with_tag(&type_die.value(), DW_TAG_member)) {
    Dwarf_Die field_type = type_of(field_die);
    str->AddField(get_die_name(&field_die),
                  get_stype(field_type),
                  get_field_byte_offset(field_die),
                  resolve_bitfield(field_die));
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
      result.push_back(type_name + " " + get_die_name(&param_die));
    else
      result.push_back(type_name);
  }
  return result;
}

std::shared_ptr<Struct> Dwarf::resolve_args(const std::string &function)
{
  auto result = std::make_shared<Struct>(0, false);
  int i = 0;
  for (auto &param_die : function_param_dies(function)) {
    Dwarf_Die type_die = type_of(param_die);
    SizedType arg_type = get_stype(type_die);
    arg_type.is_funcarg = true;
    arg_type.funcarg_idx = i++;
    const std::string name = dwarf_hasattr(&param_die, DW_AT_name)
                                 ? get_die_name(&param_die)
                                 : "";
    result->AddField(name, arg_type, result->size);
    result->size += arg_type.GetSize();
  }
  return result;
}

std::optional<Dwarf_Die> Dwarf::find_type(const std::string &name) const
{
  CuInfo cu_info = {};
  while (next_cu_info(&cu_info)) {
    if (auto type_die = get_child_with_tagname(cu_info.cu_die(),
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
        get_die_name(&child_die) == name)
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
    return static_cast<ssize_t>(size) + 1;
  }
  if (dwarf_hasattr(&subrange_die, DW_AT_count)) {
    dwarf_formudata(
        dwarf_attr_integrate(&subrange_die, DW_AT_count, &size_attr), &size);
    return static_cast<ssize_t>(size);
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
      return static_cast<ssize_t>(value);
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
      return static_cast<ssize_t>(value);
  }
  if (dwarf_hasattr(&field_die, DW_AT_bit_offset)) { // DWARF < 4
    if (dwarf_formudata(
            dwarf_attr_integrate(&field_die, DW_AT_bit_offset, &attr),
            &value) >= 0)
      return static_cast<ssize_t>(value);
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
      return static_cast<ssize_t>(value);
  }
  return 0;
}

std::optional<std::filesystem::path> Dwarf::get_cu_src_path(Dwarf_Die *cudie)
{
  Dwarf_Files *files;
  size_t nfiles;
  if (dwarf_getsrcfiles(cudie, &files, &nfiles) == 0 && nfiles > 0) {
    // The returned source file path may either be absolute or relative.
    // According to the DWARF standard, source file paths should be locatable by
    // combining DW_AT_comp_dir with the CU's file name. However, DW_AT_comp_dir
    // may be missing or empty, therefore callers should not assume the path is
    // always absolute. https://wiki.dwarfstd.org/Best_Practices.md
    const char *src = dwarf_filesrc(files, 0, nullptr, nullptr);
    if (src) {
      return std::filesystem::path(src);
    }
  }

  return std::nullopt;
}

Result<Dwarf::CuInfo> Dwarf::get_cu_by_src(const std::string &source_file) const
{
  std::optional<CuInfo> matched_cu;
  std::filesystem::path matched_src_path;

  CuInfo cu_info = {};
  while (next_cu_info(&cu_info)) {
    auto src_path = get_cu_src_path(cu_info.cu_die());
    if (!src_path)
      continue;

    if (util::path_ends_with(*src_path, source_file)) {
      if (!matched_cu) {
        matched_cu = cu_info;
        matched_src_path = *src_path;
      } else {
        return make_error<DwarfParseError>(
            "Ambiguous source path, matches multiple files: " +
            matched_src_path.string() + ", " + src_path->string());
      }
    }
  }

  if (!matched_cu)
    return make_error<DwarfParseError>("No compilation unit matches " +
                                       source_file);

  return std::move(*matched_cu);
}

Result<uint64_t> Dwarf::line_to_addr(const std::string &source_file,
                                     size_t line_num,
                                     size_t col_num) const
{
  auto cu = get_cu_by_src(source_file);
  if (!cu) {
    return cu.takeError();
  }

  auto src_path = get_cu_src_path(cu->cu_die());
  if (!src_path) {
    return make_error<DwarfParseError>(
        "Failed to get compilation unit source path");
  }

  Dwarf_Lines *lines = nullptr;
  size_t num_lines = 0;

  if (dwarf_getsrclines(cu->cu_die(), &lines, &num_lines) != 0) {
    return make_error<DwarfParseError>(
        "Failed to get compilation unit source lines");
  }

  for (size_t i = 0; i < num_lines; i++) {
    Dwarf_Line *line = dwarf_onesrcline(lines, i);
    if (!line) {
      continue;
    }

    int lineno, linecol;
    if (dwarf_lineno(line, &lineno) != 0 ||
        dwarf_linecol(line, &linecol) != 0) {
      continue;
    }

    const char *linesrc = dwarf_linesrc(line, nullptr, nullptr);
    if (!linesrc) {
      continue;
    }

    // Check if the line source matches the CU's source path, to avoid
    // unintentionally accessing statements from included files.
    if (util::path_ends_with(linesrc, *src_path) &&
        line_num == static_cast<size_t>(lineno) &&
        (col_num == 0 || col_num == static_cast<size_t>(linecol))) {
      Dwarf_Addr addr;
      if (dwarf_lineaddr(line, &addr) == 0) {
        return addr;
      }
    }
  }

  return make_error<DwarfParseError>(
      "Unable to map '" + source_file + ":" + std::to_string(line_num) +
      (col_num > 0 ? ":" + std::to_string(col_num) : "") + "' to address");
}

} // namespace bpftrace

#endif // HAVE_LIBDW
