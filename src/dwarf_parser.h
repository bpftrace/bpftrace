#pragma once

#include "types.h"

#include <memory>
#include <string>
#include <vector>

#ifdef HAVE_LIBDW
#include <elfutils/libdwfl.h>
#include <optional>
#include <unordered_map>

namespace bpftrace {

class BPFtrace;

class Dwarf
{
public:
  virtual ~Dwarf();

  static std::unique_ptr<Dwarf> GetFromBinary(BPFtrace *bpftrace,
                                              const std::string &file_path);

  std::vector<std::string> get_function_params(
      const std::string &function) const;
  ProbeArgs resolve_args(const std::string &function);

private:
  Dwarf(BPFtrace *bpftrace, const std::string &file_path);

  std::vector<Dwarf_Die> function_param_dies(const std::string &function) const;
  std::optional<Dwarf_Die> get_func_die(const std::string &function) const;
  std::string get_type_name(Dwarf_Die &type_die) const;
  Dwarf_Word get_type_encoding(Dwarf_Die &type_die) const;
  std::optional<Dwarf_Die> find_type(const std::string &name) const;
  static ssize_t get_array_size(Dwarf_Die &subrange_die);

  static std::optional<Dwarf_Die> get_child_with_tagname(
      Dwarf_Die *die,
      int tag,
      const std::string &name);
  static std::vector<Dwarf_Die> get_all_children_with_tag(Dwarf_Die *die,
                                                          int tag);

  SizedType get_stype(Dwarf_Die &type_die) const;

  Dwfl *dwfl = nullptr;
  Dwfl_Callbacks callbacks;

  BPFtrace *bpftrace_;
  std::string file_path_;
};

} // namespace bpftrace

#else // HAVE_LIBDW

#include "log.h"

namespace bpftrace {

class BPFtrace;

class Dwarf
{
public:
  static std::unique_ptr<Dwarf> GetFromBinary(BPFtrace *bpftrace
                                              __attribute__((unused)),
                                              const std::string &file_path_
                                              __attribute__((unused)))
  {
    static bool warned = false;
    if (!warned)
      LOG(WARNING) << "Cannot parse DWARF: libdw not available";
    warned = true;
    return nullptr;
  }

  std::vector<std::string> get_function_params(const std::string &function
                                               __attribute__((unused))) const
  {
    return {};
  }

  ProbeArgs resolve_args(const std::string &function __attribute__((unused)))
  {
    return {};
  }
};

} // namespace bpftrace

#endif // HAVE_LIBDW
