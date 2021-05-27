#pragma once

#include "ast/ast.h"

#include <set>
#include <sstream>

#include <linux/perf_event.h>

namespace bpftrace {

const std::string kprobe_path =
    "/sys/kernel/debug/tracing/available_filter_functions";
const std::string tp_avail_path = "/sys/kernel/debug/tracing/available_events";
const std::string tp_path = "/sys/kernel/debug/tracing/events";

struct ProbeListItem
{
  std::string path;
  std::string alias;
  uint32_t type;
  uint64_t defaultp;
};

// clang-format off
const std::vector<ProbeListItem> SW_PROBE_LIST = {
  { "alignment-faults", "",       PERF_COUNT_SW_ALIGNMENT_FAULTS,    1 },
  { "bpf-output",       "",       PERF_COUNT_SW_BPF_OUTPUT,          1 },
  { "context-switches", "cs",     PERF_COUNT_SW_CONTEXT_SWITCHES, 1000 },
  { "cpu-clock",        "cpu",    PERF_COUNT_SW_CPU_CLOCK,     1000000 },
  { "cpu-migrations",   "",       PERF_COUNT_SW_CPU_MIGRATIONS,      1 },
  { "dummy",            "",       PERF_COUNT_SW_DUMMY,               1 },
  { "emulation-faults", "",       PERF_COUNT_SW_EMULATION_FAULTS,    1 },
  { "major-faults",     "",       PERF_COUNT_SW_PAGE_FAULTS_MAJ,     1 },
  { "minor-faults",     "",       PERF_COUNT_SW_PAGE_FAULTS_MIN,   100 },
  { "page-faults",      "faults", PERF_COUNT_SW_PAGE_FAULTS,       100 },
  { "task-clock",       "",       PERF_COUNT_SW_TASK_CLOCK,          1 },
};

const std::vector<ProbeListItem> HW_PROBE_LIST = {
  { "backend-stalls",      "",         PERF_COUNT_HW_STALLED_CYCLES_BACKEND,  1000000 },
  { "branch-instructions", "branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS,      100000 },
  { "branch-misses",       "",         PERF_COUNT_HW_BRANCH_MISSES,            100000 },
  { "bus-cycles",          "",         PERF_COUNT_HW_BUS_CYCLES,               100000 },
  { "cache-misses",        "",         PERF_COUNT_HW_CACHE_MISSES,            1000000 },
  { "cache-references",    "",         PERF_COUNT_HW_CACHE_REFERENCES,        1000000 },
  { "cpu-cycles",          "cycles",   PERF_COUNT_HW_CPU_CYCLES,              1000000 },
  { "frontend-stalls",     "",         PERF_COUNT_HW_STALLED_CYCLES_FRONTEND, 1000000 },
  { "instructions",        "",         PERF_COUNT_HW_INSTRUCTIONS,            1000000 },
  { "ref-cycles",          "",         PERF_COUNT_HW_REF_CPU_CYCLES,          1000000 }
};
// clang-format on

class BPFtrace;

typedef std::map<std::string, std::vector<std::string>> FuncParamLists;

class ProbeMatcher
{
public:
  explicit ProbeMatcher(BPFtrace *bpftrace) : bpftrace_(bpftrace)
  {
  }
  virtual ~ProbeMatcher() = default;

  /*
   * Get all matches for attach point containing a wildcard.
   * The output strings format depends on the probe type.
   */
  std::set<std::string> get_matches_for_ap(
      const ast::AttachPoint &attach_point);
  /*
   * Expanding probe type containing a wildcard.
   */
  std::set<std::string> expand_probetype_kernel(const std::string &probe_type);
  std::set<std::string> expand_probetype_userspace(
      const std::string &probe_type);
  /*
   * Match all probes in prog and print them to stdout.
   */
  void list_probes(ast::Program *prog);
  /*
   * Print definitions of structures matching search.
   */
  void list_structs(const std::string &search);

  const BPFtrace *bpftrace_;

private:
  std::set<std::string> get_matches_in_stream(const std::string &search_input,
                                              bool ignore_trailing_module,
                                              std::istream &symbol_stream,
                                              const char delim = '\n');
  std::set<std::string> get_matches_for_probetype(
      const ProbeType &probe_type,
      const std::string &target,
      const std::string &search_input);
  std::set<std::string> get_matches_in_set(const std::string &search_input,
                                           const std::set<std::string> &set);

  virtual std::unique_ptr<std::istream> get_symbols_from_file(
      const std::string &path) const;
  virtual std::unique_ptr<std::istream> get_func_symbols_from_file(
      const std::string &path) const;
  virtual std::unique_ptr<std::istream> get_symbols_from_usdt(
      int pid,
      const std::string &target) const;
  virtual std::unique_ptr<std::istream> get_symbols_from_list(
      const std::vector<ProbeListItem> &probes_list) const;

  std::unique_ptr<std::istream> get_iter_symbols(void) const;

  std::unique_ptr<std::istream> kernel_probe_list();
  std::unique_ptr<std::istream> userspace_probe_list();

  FuncParamLists get_tracepoints_params(
      const std::set<std::string> &tracepoints);

  FuncParamLists get_iters_params(const std::set<std::string> &iters);
};
} // namespace bpftrace
