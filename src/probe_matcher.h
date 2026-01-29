#pragma once

#include <linux/perf_event.h>
#include <set>

#include "ast/ast.h"
#include "btf.h"

namespace bpftrace {

struct ProbeListItem {
  std::string path;
  std::string alias;
  uint32_t type;
  uint64_t defaultp;
};

// clang-format off
const std::vector<ProbeListItem> SW_PROBE_LIST = {
  { .path="alignment-faults", .alias="",       .type=PERF_COUNT_SW_ALIGNMENT_FAULTS,    .defaultp=1 },
  { .path="bpf-output",       .alias="",       .type=PERF_COUNT_SW_BPF_OUTPUT,          .defaultp=1 },
  { .path="context-switches", .alias="cs",     .type=PERF_COUNT_SW_CONTEXT_SWITCHES, .defaultp=1000 },
  { .path="cpu-clock",        .alias="cpu",    .type=PERF_COUNT_SW_CPU_CLOCK,     .defaultp=1000000 },
  { .path="cpu-migrations",   .alias="",       .type=PERF_COUNT_SW_CPU_MIGRATIONS,      .defaultp=1 },
  { .path="dummy",            .alias="",       .type=PERF_COUNT_SW_DUMMY,               .defaultp=1 },
  { .path="emulation-faults", .alias="",       .type=PERF_COUNT_SW_EMULATION_FAULTS,    .defaultp=1 },
  { .path="major-faults",     .alias="",       .type=PERF_COUNT_SW_PAGE_FAULTS_MAJ,     .defaultp=1 },
  { .path="minor-faults",     .alias="",       .type=PERF_COUNT_SW_PAGE_FAULTS_MIN,   .defaultp=100 },
  { .path="page-faults",      .alias="faults", .type=PERF_COUNT_SW_PAGE_FAULTS,       .defaultp=100 },
  { .path="task-clock",       .alias="",       .type=PERF_COUNT_SW_TASK_CLOCK,          .defaultp=1 },
};

const std::vector<ProbeListItem> HW_PROBE_LIST = {
  { .path="backend-stalls",      .alias="",         .type=PERF_COUNT_HW_STALLED_CYCLES_BACKEND,  .defaultp=1000000 },
  { .path="branch-instructions", .alias="branches", .type=PERF_COUNT_HW_BRANCH_INSTRUCTIONS,      .defaultp=100000 },
  { .path="branch-misses",       .alias="",         .type=PERF_COUNT_HW_BRANCH_MISSES,            .defaultp=100000 },
  { .path="bus-cycles",          .alias="",         .type=PERF_COUNT_HW_BUS_CYCLES,               .defaultp=100000 },
  { .path="cache-misses",        .alias="",         .type=PERF_COUNT_HW_CACHE_MISSES,            .defaultp=1000000 },
  { .path="cache-references",    .alias="",         .type=PERF_COUNT_HW_CACHE_REFERENCES,        .defaultp=1000000 },
  { .path="cpu-cycles",          .alias="cycles",   .type=PERF_COUNT_HW_CPU_CYCLES,              .defaultp=1000000 },
  { .path="frontend-stalls",     .alias="",         .type=PERF_COUNT_HW_STALLED_CYCLES_FRONTEND, .defaultp=1000000 },
  { .path="instructions",        .alias="",         .type=PERF_COUNT_HW_INSTRUCTIONS,            .defaultp=1000000 },
  { .path="ref-cycles",          .alias="",         .type=PERF_COUNT_HW_REF_CPU_CYCLES,          .defaultp=1000000 }
};
// clang-format on

const std::unordered_set<std::string> TIME_UNITS = { "s", "ms", "us", "hz" };

const std::unordered_set<std::string> SIGNALS = { "SIGUSR1" };

class BPFtrace;

class ProbeMatcher {
public:
  explicit ProbeMatcher(BPFtrace *bpftrace) : bpftrace_(bpftrace)
  {
  }
  virtual ~ProbeMatcher() = default;

  // Get all matches for attach point containing a wildcard.
  // The output strings format depends on the probe type.
  std::set<std::string> get_matches_for_ap(
      const ast::AttachPoint &attach_point);
  // Expanding probe type containing a wildcard.
  std::set<std::string> expand_probetype_kernel(const std::string &probe_type);
  std::set<std::string> expand_probetype_userspace(
      const std::string &probe_type);
  // Match all probes in prog and print them to stdout.
  void list_probes(ast::Program *prog);
  // Print definitions of structures matching search.
  void list_structs(const std::string &search);

  const BPFtrace *bpftrace_;

private:
  std::set<std::string> get_matches_in_stream(const std::string &search_input,
                                              std::istream &symbol_stream,
                                              bool demangle_symbols = true,
                                              char delim = '\n');
  std::set<std::string> get_matches_for_probetype(
      const ProbeType &probe_type,
      const std::string &target,
      const std::string &search_input,
      bool demangle_symbols);
  std::set<std::string> get_matches_in_set(const std::string &search_input,
                                           const std::set<std::string> &set);

  virtual std::unique_ptr<std::istream> get_symbols_from_traceable_funcs(
      bool with_modules = false) const;
  virtual std::unique_ptr<std::istream> get_module_symbols_from_traceable_funcs(
    const std::string &module_name) const;
  virtual std::unique_ptr<std::istream> get_symbols_from_file(
      const std::string &path) const;
  virtual std::unique_ptr<std::istream> get_func_symbols_from_file(
      std::optional<int> pid,
      const std::string &path) const;
  virtual std::unique_ptr<std::istream> get_symbols_from_usdt(
      std::optional<int> pid,
      const std::string &target) const;
  virtual std::unique_ptr<std::istream> get_symbols_from_list(
      const std::vector<ProbeListItem> &probes_list) const;
  virtual std::unique_ptr<std::istream> get_fentry_symbols(
      const std::string &mod) const;
  virtual std::unique_ptr<std::istream> get_running_bpf_programs() const;
  virtual std::unique_ptr<std::istream> get_raw_tracepoint_symbols() const;
  virtual std::unique_ptr<std::istream> get_raw_tracepoints_from_traceable_funcs()
      const;

  std::unique_ptr<std::istream> get_iter_symbols() const;

  std::unique_ptr<std::istream> kernel_probe_list();
  std::unique_ptr<std::istream> userspace_probe_list();

  FuncParamLists get_tracepoints_params(
      const std::set<std::string> &tracepoints);

  FuncParamLists get_iters_params(const std::set<std::string> &iters);
  FuncParamLists get_uprobe_params(const std::set<std::string> &uprobes);
};
} // namespace bpftrace
