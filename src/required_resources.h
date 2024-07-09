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
#include "mapkey.h"
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
  MapKey key;
  SizedType value_type;
  std::optional<LinearHistogramArgs> lhist_args;
  std::optional<int> hist_bits_arg;
  int id = -1;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(key, value_type, lhist_args, hist_bits_arg, id);
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
  std::vector<std::tuple<FormatString, std::vector<Field>>> system_args;
  // fmt strings for BPF helpers (bpf_seq_printf, bpf_trace_printk)
  std::vector<FormatString> bpf_print_fmts;
  std::vector<std::string> join_args;
  std::vector<std::string> time_args;
  std::vector<std::string> strftime_args;
  std::vector<std::string> cgroup_path_args;
  std::vector<std::tuple<FormatString, std::vector<Field>>> cat_args;
  std::vector<SizedType> non_map_print_args;
  std::vector<std::tuple<std::string, long>> skboutput_args_;

  // Async argument metadata that codegen creates. Ideally ResourceAnalyser
  // pass should be collecting this, but it's complex to move the logic.
  //
  // Don't add more async arguments here!.
  std::unordered_map<int64_t, struct HelperErrorInfo> helper_error_info;
  // `printf_args` is created here but the field offsets are fixed up
  // by codegen -- only codegen knows data layout to compute offsets
  std::vector<std::tuple<FormatString, std::vector<Field>>> printf_args;
  std::vector<std::string> probe_ids;

  // Map metadata
  std::map<std::string, MapInfo> maps_info;
  std::unordered_set<StackType> stackid_maps;
  std::unordered_set<std::string_view> needed_global_vars;
  bool needs_join_map = false;
  bool needs_elapsed_map = false;
  bool needs_perf_event_map = false;
  uint32_t str_buffers = 0;

  // Probe metadata
  //
  // Probe metadata that codegen creates. Ideally ResourceAnalyser pass should
  // be collecting this, but it's complex to move the logic.
  std::vector<Probe> probes;
  std::vector<Probe> special_probes;
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
            stackid_maps,
            needs_join_map,
            needs_elapsed_map,
            needs_perf_event_map,
            probes,
            special_probes);
  }
};

} // namespace bpftrace
