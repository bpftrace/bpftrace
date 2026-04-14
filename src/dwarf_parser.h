#pragma once

#include "struct.h"
#include "types.h"
#include "util/result.h"

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace bpftrace {

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

} // namespace bpftrace

#ifdef HAVE_LIBDW
#include <elfutils/libdwfl.h>
#include <optional>
#include <unordered_map>

namespace bpftrace {

class BPFtrace;

template <typename T>
concept LineCallback =
    std::is_invocable_r_v<bool, T, Dwarf_Line *, const char *, int, int>;

class Dwarf {
public:
  virtual ~Dwarf();

  Dwarf(const Dwarf &) = delete;
  Dwarf &operator=(const Dwarf &) = delete;

  Dwarf(Dwarf &&) = delete;
  Dwarf &operator=(Dwarf &&) = delete;

  static std::unique_ptr<Dwarf> GetFromBinary(
      BPFtrace *bpftrace,
      const std::string &file_path,
      const std::string &debuginfo_path);

  std::vector<std::string> get_function_params(
      const std::string &function) const;
  std::shared_ptr<Struct> resolve_args(const std::string &function);

  SizedType get_stype(const std::string &type_name) const;
  void resolve_fields(const SizedType &type) const;

  // Maps a source file, line, and optional column to the *first* corresponding
  // instruction address. Mapping to inlined code is not supported.
  Result<uint64_t> line_to_addr(const std::string &source_file,
                                size_t line_num,
                                size_t col_num = 0) const;
  // Returns source lines associated with a function as 'file:line:col' strings.
  // Inlined line entries are omitted.
  Result<std::vector<std::string>> get_function_src_lines(
      const std::string &function) const;

  // Compilation unit wrapper, abstracting over regular and split (DWO/DWP)
  // CU DIEs.
  class CuInfo {
  public:
    // Standard CU DIE, managed by the libdw session.
    Dwarf_Die *cudie = nullptr;

    // Split CU DIE loaded from a dwo/dwp file. Must be owned and managed
    // manually per the libdw API, and is valid for the lifetime of the CuInfo
    // instance.
    //
    // Present when cudie is a DW_UT_skeleton unit. In that case, this should
    // be used instead, as it holds vast majority of the debug info. libdw
    // automatically resolves references between the skeleton and split CU.
    std::optional<Dwarf_Die> split_cudie;

    // Returns split CU DIE if present (skeleton CU), otherwise cudie.
    Dwarf_Die *cu_die()
    {
      return split_cudie ? &split_cudie.value() : cudie;
    }
  };

private:
  Dwarf(BPFtrace *bpftrace,
        const std::string &file_path,
        std::string debuginfo_path);

  bool next_cu_info(CuInfo *cu_info) const;
  std::vector<Dwarf_Die> function_param_dies(const std::string &function) const;
  std::optional<Dwarf_Die> get_func_die(const std::string &function,
                                        bool prefer_abstract_die) const;
  std::string get_type_name(Dwarf_Die &type_die) const;
  Dwarf_Word get_type_encoding(Dwarf_Die &type_die) const;
  std::optional<Dwarf_Die> find_type(const std::string &name) const;
  static ssize_t get_array_size(Dwarf_Die &subrange_die);
  static ssize_t get_field_byte_offset(Dwarf_Die &field_die);
  static ssize_t get_field_bit_offset(Dwarf_Die &field_die);
  static ssize_t get_bitfield_size(Dwarf_Die &field_die);
  std::optional<Bitfield> resolve_bitfield(Dwarf_Die &field_die) const;

  SizedType get_stype(Dwarf_Die &type_die, bool resolve_structs = true) const;
  // Returns all CUs that reference the given source file in their srcfile table
  // as (CU, resolved source file) pairs.
  std::vector<std::pair<Dwarf::CuInfo, std::string>> get_cus_with_srcfile(
      const std::string &source_file) const;

  static std::optional<Dwarf_Die> get_child_with_tagname(
      Dwarf_Die *die,
      int tag,
      const std::string &name);
  static std::vector<Dwarf_Die> get_all_children_with_tag(Dwarf_Die *die,
                                                          int tag);
  // Preorder DFS traversal of a DIE subtree.
  template <typename VisitCallback>
  static void visit_die_subtree(Dwarf_Die *die, VisitCallback &&callback);
  // Iterates line table in a CUDIE and calls the given callback for
  // each entry. If the callback returns false value the iteration stops,
  // otherwise keeps iterating.
  static Result<> foreach_src_line(Dwarf_Die *cudie,
                                   LineCallback auto &&callback);
  // Returns PC ranges of all inlined subroutines within the given function DIE.
  static std::vector<std::pair<Dwarf_Addr, Dwarf_Addr>> get_inlined_func_ranges(
      Dwarf_Die *func_die);

  Dwfl *dwfl = nullptr;
  Dwfl_Callbacks callbacks;

  BPFtrace *bpftrace_;
  std::string file_path_;
  // Dwfl_Callbacks struct takes a char** pointing to a debuginfo path which has
  // to remain valid for the lifetime of the dwfl session, because debug info is
  // loaded lazily; e.g. dwfl_nextcu triggers the find_debuginfo callback on
  // first use for *each* module and dereferences the pointer.
  //
  // Each instance of this class owns a copy of the path string and keeps
  // debuginfo_path_cstr_ pointing to its internal buffer to pass a stable
  // char** to Dwfl_Callbacks.
  std::string debuginfo_path_;
  const char *debuginfo_path_cstr_;
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
                                              __attribute__((unused)),
                                              const std::string &debuginfo_path
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

  Result<std::vector<std::string>> get_function_src_lines(
      const std::string &function __attribute__((unused))) const
  {
    return make_error<DwarfParseError>();
  }
};

} // namespace bpftrace

#endif // HAVE_LIBDW
