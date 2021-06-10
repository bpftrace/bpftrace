#pragma once

#include <string>
#include <tuple>
#include <unordered_set>
#include <vector>

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
};

} // namespace bpftrace
