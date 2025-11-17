#pragma once

#include "struct.h"
#include "types.h"
#include "util/result.h"

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#ifdef HAVE_LIBDW
#include <elfutils/libdwfl.h>
#include <optional>
#include <unordered_map>

namespace bpftrace {

class BPFtrace;

class DwarfParseError : public ErrorInfo<DwarfParseError> {
public:
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

  DwarfParseError(std::string &&msg) : msg_(std::move(msg)) {};
  DwarfParseError() = default;

  const std::string &msg() const
  {
    return msg_;
  }

private:
  std::string msg_;
};

class Dwarf {
public:
  virtual ~Dwarf();

  static std::unique_ptr<Dwarf> GetFromBinary(BPFtrace *bpftrace,
                                              const std::string &file_path);

  std::vector<std::string> get_function_params(
      const std::string &function) const;
  std::shared_ptr<Struct> resolve_args(const std::string &function);

  SizedType get_stype(const std::string &type_name) const;
  void resolve_fields(const SizedType &type) const;

  Result<uint64_t> line_to_addr(const std::string &source_file,
                                size_t line_num,
                                size_t col_num = 0) const;

private:
  struct CuInfo {
    std::filesystem::path source;
    Dwarf_Die *die;
  };

  Dwarf(BPFtrace *bpftrace, const std::string &file_path);

  std::vector<Dwarf_Die> function_param_dies(const std::string &function) const;
  std::optional<Dwarf_Die> get_func_die(const std::string &function) const;
  std::string get_type_name(Dwarf_Die &type_die) const;
  Dwarf_Word get_type_encoding(Dwarf_Die &type_die) const;
  std::optional<Dwarf_Die> find_type(const std::string &name) const;
  static ssize_t get_array_size(Dwarf_Die &subrange_die);
  static ssize_t get_field_byte_offset(Dwarf_Die &field_die);
  static ssize_t get_field_bit_offset(Dwarf_Die &field_die);
  static ssize_t get_bitfield_size(Dwarf_Die &field_die);
  std::optional<Bitfield> resolve_bitfield(Dwarf_Die &field_die) const;

  SizedType get_stype(Dwarf_Die &type_die, bool resolve_structs = true) const;

  Result<CuInfo> get_cu_info(const std::string &source_file) const;

  static std::optional<Dwarf_Die> get_child_with_tagname(
      Dwarf_Die *die,
      int tag,
      const std::string &name);
  static std::vector<Dwarf_Die> get_all_children_with_tag(Dwarf_Die *die,
                                                          int tag);

  static std::optional<std::filesystem::path> resolve_cu_path(
      std::string_view cu_name,
      std::string_view cu_comp_dir);

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

class Dwarf {
public:
  static std::unique_ptr<Dwarf> GetFromBinary(BPFtrace *bpftrace
                                              __attribute__((unused)),
                                              const std::string &file_path_
                                              __attribute__((unused)))
  {
    return nullptr;
  }

  std::vector<std::string> get_function_params(const std::string &function
                                               __attribute__((unused))) const
  {
    return {};
  }

  std::shared_ptr<Struct> resolve_args(const std::string &function
                                       __attribute__((unused)))
  {
    return nullptr;
  }

  SizedType get_stype(const std::string &type_name
                      __attribute__((unused))) const
  {
    return CreateNone();
  }

  void resolve_fields(const SizedType &type __attribute__((unused))) const
  {
  }

  Result<uint64_t> line_to_addr(const std::string &source_file
                                __attribute__((unused)),
                                size_t line_num __attribute__((unused)),
                                size_t col_num __attribute__((unused))) const
  {
    return make_error<DwarfParseError>();
  }
};

} // namespace bpftrace

#endif // HAVE_LIBDW
