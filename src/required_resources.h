#pragma once

#include <cstdint>
#include <istream>
#include <ostream>
#include <string>
#include <tuple>
#include <unordered_set>
#include <vector>

#include <cereal/access.hpp>

#include "location.hh"
#include "mapkey.h"
#include "mapmanager.h"
#include "struct.h"
#include "types.h"

namespace bpftrace {

class BPFtrace;

struct HelperErrorInfo
{
  int func_id = -1;
  location loc;
};

struct LinearHistogramArgs
{
  long min = -1;
  long max = -1;
  long step = -1;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(min, max, step);
  }
};

// This class contains script-specific metadata that bpftrace's runtime needs.
//
// This class is intended to completely encapsulate all of a script's runtime
// needs such as maps, async printf argument metadata, etc. An instance of this
// class plus the actual bpf bytecode should be all that's necessary to run a
// script on another host.
class RequiredResources
{
public:
  // Create maps in `maps` based on stored metadata
  //
  // If `fake` is set, then `FakeMap`s will be created. This is useful for:
  // * allocating map IDs for codegen, because there's no need to prematurely
  //   create resources that may not get used (debug mode, AOT codepath, etc.)
  // * unit tests, as unit tests should not make system state changes
  //
  // Returns 0 on success, number of maps that failed to be created otherwise
  int create_maps(BPFtrace &bpftrace, bool fake);

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

  // Async argument metadata
  std::vector<std::tuple<std::string, std::vector<Field>>> system_args;
  std::vector<std::tuple<std::string, std::vector<Field>>> seq_printf_args;
  std::vector<std::tuple<int, int>> seq_printf_ids;
  std::vector<std::string> join_args;
  std::vector<std::string> time_args;
  std::vector<std::string> strftime_args;
  std::vector<std::tuple<std::string, std::vector<Field>>> cat_args;
  std::vector<SizedType> non_map_print_args;

  // Async argument metadata that codegen creates. Ideally ResourceAnalyser
  // pass should be collecting this, but it's complex to move the logic.
  //
  // Don't add more async arguments here!.
  std::unordered_map<int64_t, struct HelperErrorInfo> helper_error_info;
  // `printf_args` is created here but the field offsets are fixed up
  // by codegen -- only codegen knows data layout to compute offsets
  std::vector<std::tuple<std::string, std::vector<Field>>> printf_args;
  std::vector<std::string> probe_ids;

  // Map metadata
  std::map<std::string, SizedType> map_vals;
  std::map<std::string, LinearHistogramArgs> lhist_args;
  std::map<std::string, MapKey> map_keys;
  std::unordered_set<StackType> stackid_maps;
  bool needs_join_map = false;
  bool needs_elapsed_map = false;
  bool needs_data_map = false;

private:
  template <typename T>
  int create_maps_impl(BPFtrace &bpftrace, bool fake);

  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(system_args,
            seq_printf_args,
            seq_printf_ids,
            join_args,
            time_args,
            strftime_args,
            cat_args,
            non_map_print_args,
            // Hard to annotate flex types, so skip
            // helper_error_info,
            printf_args,
            probe_ids,
            map_vals,
            lhist_args,
            map_keys,
            stackid_maps,
            needs_join_map,
            needs_elapsed_map,
            needs_data_map);
  }
};

} // namespace bpftrace
