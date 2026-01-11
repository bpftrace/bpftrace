#pragma once

#include <cstdint>
#include <istream>
#include <ostream>
#include <string>
#include <tuple>
#include <unordered_set>
#include <vector>

#include <cereal/access.hpp>
#include <cereal/types/variant.hpp>

#include "ast/location.h"
#include "format_string.h"
#include "globalvars.h"
#include "map_info.h"
#include "struct.h"
#include "types.h"
#include "util/bpf_funcs.h"

namespace bpftrace {

class BPFtrace;

static const auto DIVIDE_BY_ZERO_MSG =
    "Divide or modulo by 0 detected. This can lead to unexpected "
    "results. 1 is being used as the result.";

static const auto ARRAY_ACCESS_OOB_MSG =
    "Array access out of bounds. This can lead to unexpected "
    "results.";

enum class RuntimeErrorId {
  DIVIDE_BY_ZERO,
  HELPER_ERROR,
  ARRAY_ACCESS_OOB,
};

enum class PrintfSeverity {
  NONE,
  ERROR,
  WARNING,
};

struct SourceLocation {
  std::string filename;
  int line;
  int column;
  std::string source_location;
  std::vector<std::string> source_context;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(filename, line, column, source_location, source_context);
  }
};

class SourceInfo {
public:
  SourceInfo(const ast::Location &loc)
  {
    auto curr_loc = loc;

    while (curr_loc) {
      locations.emplace_back(curr_loc->filename(),
                             curr_loc->line(),
                             curr_loc->column(),
                             curr_loc->source_location(),
                             curr_loc->source_context());
      auto &parent = curr_loc->parent;
      if (parent) {
        curr_loc = parent->loc;
      } else {
        break;
      }
    }
  }

  SourceInfo() = default;

  std::vector<SourceLocation> locations;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(locations);
  }
};

class RuntimeErrorInfo : public SourceInfo {
public:
  // This class effectively wraps a location, but preserves only the parts that
  // are needed to emit the error in a useful way. This is because it may be
  // serialized and used by a separate runtime.
  RuntimeErrorInfo(RuntimeErrorId error_id,
                   bpf_func_id func_id,
                   const ast::Location &loc)
      : SourceInfo(loc), error_id(error_id), func_id(func_id)
  {
  }

  RuntimeErrorInfo(RuntimeErrorId error_id, const ast::Location &loc)
      : RuntimeErrorInfo(error_id, __BPF_FUNC_MAX_ID, loc) {};

  RuntimeErrorInfo()
      : error_id(RuntimeErrorId::HELPER_ERROR), func_id(__BPF_FUNC_MAX_ID) {};

  RuntimeErrorId error_id;
  bpf_func_id func_id;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(error_id, func_id);
  }
};

std::ostream &operator<<(std::ostream &os, const RuntimeErrorInfo &info);

// This class contains script-specific metadata that bpftrace's runtime needs.
//
// This class is intended to completely encapsulate all of a script's runtime
// needs such as maps, async printf argument metadata, etc. An instance of this
// class plus the actual bpf bytecode should be all that's necessary to run a
// script on another host.
class RequiredResources {
public:
  // `save_state()` serializes `RequiredResources` and writes results into
  // `out`. `load_state()` does the reverse: takes serialized data and loads it
  // into the current instance.
  //
  // NB: The serialized data is not versioned and is not forward/backwards
  // compatible.
  //
  // NB: both the output and input stream must be opened in binary
  // (std::ios::binary) mode to avoid binary data from being interpreted wrong
  void save_state(std::ostream &out) const;
  void load_state(std::istream &in);
  void load_state(const uint8_t *ptr, size_t len);

  // Async argument metadata
  // There is both a vector and a map of AST pointers to vector index.
  // We only need the latter for a later passes that want to accurately
  // access the id for a specific node so it can be passed into userspace
  // when the script is executing.
  std::vector<
      std::tuple<FormatString, std::vector<Field>, PrintfSeverity, SourceInfo>>
      printf_args;
  std::unordered_map<ast::Call* , size_t> printf_args_id_map;
  std::vector<std::tuple<FormatString, std::vector<Field>>> system_args;
  std::unordered_map<ast::Call* , size_t> system_args_id_map;
  // fmt strings for BPF helpers (bpf_seq_printf, bpf_trace_printk)
  std::vector<FormatString> bpf_print_fmts;
  std::unordered_map<ast::Call* , size_t> bpf_print_fmts_id_map;
  std::vector<std::tuple<FormatString, std::vector<Field>>> cat_args;
  std::unordered_map<ast::Call* , size_t> cat_args_id_map;
  std::vector<std::string> join_args;
  std::unordered_map<ast::Call* , size_t> join_args_id_map;
  std::vector<std::string> time_args;
  std::unordered_map<ast::Call* , size_t> time_args_id_map;
  std::vector<std::string> strftime_args;
  std::unordered_map<ast::Call* , size_t> strftime_args_id_map;
  std::vector<std::string> cgroup_path_args;
  std::unordered_map<ast::Call* , size_t> cgroup_path_args_id_map;
  std::vector<SizedType> non_map_print_args;
  std::unordered_map<ast::Call* , size_t> non_map_print_args_id_map;
  std::vector<std::tuple<std::string, long>> skboutput_args_;
  std::unordered_map<ast::Call* , size_t> skboutput_args_id_map;
  // While max fmtstring args size is not used at runtime, the size
  // calculation requires taking into account struct alignment semantics,
  // and that is tricky enough that we want to minimize repetition of
  // such logic in the codebase. So keep it in resource analysis
  // rather than duplicating it in CodegenResources.
  uint64_t max_fmtstring_args_size = 0;

  // Required for sizing of tuple/record scratch buffer
  size_t anon_struct_buffers = 0;
  size_t max_anon_struct_size = 0;

  // Required for sizing of kstack and ustack scratch buffer
  size_t call_stack_buffers = 0;
  size_t max_call_stack_size = 0;

  // Required for sizing of string scratch buffer
  size_t str_buffers = 0;

  // Required for sizing of map value scratch buffers
  size_t read_map_value_buffers = 0;
  size_t max_read_map_value_size = 0;
  size_t max_write_map_value_size = 0;

  // Required for sizing of variable scratch buffers
  size_t variable_buffers = 0;
  size_t max_variable_size = 0;

  // Required for sizing of map key scratch buffers
  size_t map_key_buffers = 0;
  size_t max_map_key_size = 0;

  size_t join_value_size = 0;

  // Async argument metadata that codegen creates. Ideally ResourceAnalyser
  // pass should be collecting this, but it's complex to move the logic.
  //
  // Don't add more async arguments here!.
  std::unordered_map<int64_t, RuntimeErrorInfo> runtime_error_info;
  std::vector<std::string> probe_ids;

  // Map metadata
  std::map<std::string, MapInfo> maps_info;
  globalvars::GlobalVars global_vars;
  bool using_skboutput = false;
  bool needs_elapsed_map = false;

  // Probe metadata
  //
  // Probe metadata that codegen creates. Ideally ResourceAnalyser pass should
  // be collecting this, but it's complex to move the logic.
  std::vector<Probe> probes;
  std::vector<Probe> begin_probes;
  std::vector<Probe> end_probes;
  std::vector<Probe> test_probes;
  std::vector<Probe> benchmark_probes;
  std::vector<Probe> signal_probes;
  std::vector<Probe> watchpoint_probes;

  size_t num_probes() const
  {
    return probes.size() + begin_probes.size() + end_probes.size() +
           test_probes.size() + benchmark_probes.size() + signal_probes.size() +
           watchpoint_probes.size();
  }

  // List of probes using userspace symbol resolution
  std::unordered_set<const ast::Probe *> probes_using_usym;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(system_args,
            bpf_print_fmts,
            join_args,
            time_args,
            strftime_args,
            cat_args,
            non_map_print_args,
            runtime_error_info,
            printf_args,
            probe_ids,
            maps_info,
            global_vars,
            using_skboutput,
            probes,
            signal_probes,
            begin_probes,
            end_probes,
            test_probes,
            benchmark_probes);
  }
};

} // namespace bpftrace
