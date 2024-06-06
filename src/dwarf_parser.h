#pragma once

#include "struct.h"
#include "types.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#ifdef HAVE_LIBLLDB
#include <lldb/API/SBDebugger.h>
#include <lldb/API/SBTarget.h>

namespace bpftrace {

class BPFtrace;

class Dwarf {
public:
  virtual ~Dwarf();

  static std::unique_ptr<Dwarf> GetFromBinary(BPFtrace *bpftrace,
                                              std::string file_path);

  std::vector<uint64_t> get_function_locations(const std::string &function,
                                               bool include_inlined);
  std::vector<std::string> get_function_params(const std::string &function);
  Struct resolve_args(const std::string &function);

  SizedType get_stype(const std::string &type_name);
  void resolve_fields(const SizedType &type);

private:
  static std::atomic<size_t> instance_count;

  Dwarf(BPFtrace *bpftrace, std::string file_path);

  lldb::SBValueList function_params(const std::string &function);

  std::string get_type_name(lldb::SBType type);
  SizedType get_stype(lldb::SBType type, bool resolve_structs = true);
  std::optional<Bitfield> resolve_bitfield(lldb::SBTypeMember field);

  BPFtrace *bpftrace_;
  std::string file_path_;

  lldb::SBDebugger debugger_;
  lldb::SBTarget target_;
};

} // namespace bpftrace

#else // HAVE_LIBLLDB

#include "log.h"

namespace bpftrace {
class BPFtrace;

class Dwarf {
public:
  static std::unique_ptr<Dwarf> GetFromBinary(BPFtrace *bpftrace
                                              __attribute__((unused)),
                                              std::string file_path_
                                              __attribute__((unused)))
  {
    return nullptr;
  }

  std::vector<uint64_t> get_function_locations(const std::string &function
                                               __attribute__((unused)),
                                               bool include_inlined
                                               __attribute__((unused)))
  {
    return {};
  }

  std::vector<std::string> get_function_params(const std::string &function
                                               __attribute__((unused)))
  {
    return {};
  }

  Struct resolve_args(const std::string &function __attribute__((unused)))
  {
    return {};
  }

  SizedType get_stype(const std::string &type_name __attribute__((unused)))
  {
    return CreateNone();
  }

  void resolve_fields(const SizedType &type __attribute__((unused)))
  {
  }

private:
  Dwarf() = delete;
};

} // namespace bpftrace

#endif // HAVE_LIBLLDB
