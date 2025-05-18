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

namespace bpftrace {

class BPFtrace;

class HelperErrorInfo {
public:
  // This class effectively wraps a location, but preserves only the parts that
  // are needed to emit the error in a useful way. This is because it may be
  // serialized and used by a separate runtime.
  HelperErrorInfo(int func_id, const ast::Location &loc)
      : func_id(func_id),
        filename(loc->filename()),
        line(loc->line()),
        column(loc->column()),
        source_location(loc->source_location()),
        source_context(loc->source_context())
  {
  }

  // This is only used in the case that for some reason there is no helper
  // registered for the specific instance.
  HelperErrorInfo() : func_id(-1), line(0), column(0) {};

  const int func_id;
  const std::string filename;
  const int line;
  const int column;
  const std::string source_location;
  const std::vector<std::string> source_context;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(func_id, filename, line, column, source_location, source_context);
  }
};

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
  std::vector<std::tuple<FormatString, std::vector<Field>>> printf_args;
  std::vector<std::tuple<FormatString, std::vector<Field>>> system_args;
  // fmt strings for BPF helpers (bpf_seq_printf, bpf_trace_printk)
  std::vector<FormatString> bpf_print_fmts;
  std::vector<std::tuple<FormatString, std::vector<Field>>> cat_args;
  std::vector<std::string> join_args;
  std::vector<std::string> time_args;
  std::vector<std::string> strftime_args;
  std::vector<std::string> cgroup_path_args;
  std::vector<SizedType> non_map_print_args;
  std::vector<std::tuple<std::string, long>> skboutput_args_;
  // While max fmtstring args size is not used at runtime, the size
  // calculation requires taking into account struct alignment semantics,
  // and that is tricky enough that we want to minimize repetition of
  // such logic in the codebase. So keep it in resource analysis
  // rather than duplicating it in CodegenResources.
  uint64_t max_fmtstring_args_size = 0;

  // Required for sizing of tuple scratch buffer
  size_t tuple_buffers = 0;
  size_t max_tuple_size = 0;

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

  // Async argument metadata that codegen creates. Ideally ResourceAnalyser
  // pass should be collecting this, but it's complex to move the logic.
  //
  // Don't add more async arguments here!.
  std::unordered_map<int64_t, HelperErrorInfo> helper_error_info;
  std::vector<std::string> probe_ids;

  // Map metadata
  std::map<std::string, MapInfo> maps_info;
  std::unordered_set<bpftrace::globalvars::GlobalVar> needed_global_vars;
  bool needs_perf_event_map = false;

  // Probe metadata
  //
  // Probe metadata that codegen creates. Ideally ResourceAnalyser pass should
  // be collecting this, but it's complex to move the logic.
  std::vector<Probe> probes;
  std::unordered_map<std::string, Probe> special_probes;
  std::vector<Probe> signal_probes;
  std::vector<Probe> watchpoint_probes;

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
            // Hard to annotate flex types, so skip
            // helper_error_info,
            printf_args,
            probe_ids,
            maps_info,
            needed_global_vars,
            needs_perf_event_map,
            probes,
            signal_probes,
            special_probes);
  }
};

} // namespace bpftrace
