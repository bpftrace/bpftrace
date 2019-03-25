#include <sstream>

#include <linux/perf_event.h>

namespace bpftrace {

struct ProbeListItem
{
  std::string path;
  std::string alias;
  uint32_t type;
  uint64_t defaultp;
};

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

void list_probes(const std::string &search = "", int pid = 0);

} // namespace bpftrace
