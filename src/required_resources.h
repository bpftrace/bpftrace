#pragma once

#include <cstdint>
#include <istream>
#include <ostream>
#include <string>
#include <tuple>
#include <unordered_set>
#include <vector>

#include <cereal/access.hpp>

#include "format_string.h"
#include "location.hh"
#include "struct.h"
#include "types.h"

namespace bpftrace {

class BPFtrace;

struct HelperErrorInfo {
  int func_id = -1;
  location loc;
};

struct LinearHistogramArgs {
  long min = -1;
  long max = -1;
  long step = -1;

  bool operator==(const LinearHistogramArgs &other)
  {
    return min == other.min && max == other.max && step == other.step;
  }
  bool operator!=(const LinearHistogramArgs &other)
  {
    return !(*this == other);
  }

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(min, max, step);
  }
};

struct MapInfo {
  SizedType key_type;
  SizedType value_type;
  std::optional<LinearHistogramArgs> lhist_args;
  std::optional<int> hist_bits_arg;
  int id = -1;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(key_type, value_type, lhist_args, hist_bits_arg, id);
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
  std::unordered_map<int64_t, struct HelperErrorInfo> helper_error_info;
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
            special_probes);
  }
};

} // namespace bpftrace
