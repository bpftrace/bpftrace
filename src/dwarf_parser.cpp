#include "dwarf_parser.h"

#ifdef HAVE_LIBDW

#include "log.h"

#include <dwarf.h>
#include <elfutils/libdw.h>

namespace bpftrace {

struct FuncInfo
{
  std::string name;
  Dwarf_Die die;
};

Dwarf::Dwarf(const std::string &file_path)
{
  callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
  callbacks.section_address = dwfl_offline_section_address;
  dwfl = dwfl_begin(&callbacks);
  if (dwfl_report_offline(dwfl, file_path.c_str(), file_path.c_str(), -1) ==
      NULL)
  {
    LOG(WARNING) << "Could not read DWARF info from " + file_path;
  }
  dwfl_report_end(dwfl, NULL, NULL);
}

std::unique_ptr<Dwarf> Dwarf::GetFromBinary(const std::string &file_path)
{
  std::unique_ptr<Dwarf> dwarf(new Dwarf(file_path));
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
  if (dwarf_diename(func_die) == func_info->name)
  {
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
  while ((cudie = dwfl_nextcu(dwfl, cudie, &cubias)) != nullptr)
  {
    if (dwarf_getfuncs(cudie, get_func_die_cb, &func_info, 0) != 0)
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

std::unordered_map<std::string, Dwarf_Die> Dwarf::function_param_dies(
    const std::string &function) const
{
  auto func_die = get_func_die(function);
  if (!func_die)
    return {};

  Dwarf_Die param_die;
  Dwarf_Die *param_iter = &param_die;
  if (dwarf_child(&func_die.value(), &param_die) != 0)
    return {};

  std::unordered_map<std::string, Dwarf_Die> param_dies;
  do
  {
    if (dwarf_tag(&param_die) == DW_TAG_formal_parameter)
    {
      const std::string param_name = dwarf_diename(&param_die);
      Dwarf_Die type_die = type_of(param_die);

      param_dies.emplace(param_name, type_die);
    }
  } while (dwarf_siblingof(param_iter, &param_die) == 0);

  return param_dies;
}

std::string Dwarf::get_type_name(Dwarf_Die &type_die) const
{
  auto tag = dwarf_tag(&type_die);
  switch (tag)
  {
    case DW_TAG_base_type:
    case DW_TAG_typedef:
      return dwarf_diename(&type_die);
    case DW_TAG_pointer_type: {
      if (dwarf_hasattr(&type_die, DW_AT_type))
      {
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

std::vector<std::string> Dwarf::get_function_params(
    const std::string &function) const
{
  std::vector<std::string> result;
  for (auto &param : function_param_dies(function))
  {
    result.push_back(get_type_name(param.second) + " " + param.first);
  }
  return result;
}

} // namespace bpftrace

#endif // HAVE_LIBDW