#include <cassert>
#include <cstdint>
#include <fstream>
#include <vector>

#include "util/cpus.h"
#include "util/math.h"

namespace bpftrace::util {

static std::vector<int> read_cpu_range(std::string path)
{
  std::ifstream cpus_range_stream{ path };
  std::vector<int> cpus;
  std::string cpu_range;

  while (std::getline(cpus_range_stream, cpu_range, ',')) {
    std::size_t rangeop = cpu_range.find('-');
    if (rangeop == std::string::npos) {
      cpus.push_back(std::stoi(cpu_range));
    } else {
      int start = std::stoi(cpu_range.substr(0, rangeop));
      int end = std::stoi(cpu_range.substr(rangeop + 1));
      for (int i = start; i <= end; i++)
        cpus.push_back(i);
    }
  }
  return cpus;
}

std::vector<int> get_online_cpus()
{
  return read_cpu_range("/sys/devices/system/cpu/online");
}

std::vector<int> get_possible_cpus()
{
  return read_cpu_range("/sys/devices/system/cpu/possible");
}

int get_max_cpu_id()
{
  // When booting, the kernel ensures CPUs are ordered from 0 -> N so there
  // are no gaps in possible CPUs. CPU ID is also u32 so this cast is safe
  const auto num_possible_cpus = static_cast<uint32_t>(
      get_possible_cpus().size());
  assert(num_possible_cpus > 0);
  // Using global scratch variables for big string usage looks like:
  //   bounded_cpu_id = bpf_get_smp_processor_id() & MAX_CPU_ID
  //   buf = global_var[bounded_cpu_id][slot_id]
  // We bound CPU ID to satisfy the BPF verifier on older kernels. We use an AND
  // instruction vs. LLVM umin function to reduce the number of jumps in BPF to
  // ensure we don't hit the complexity limit of 8192 jumps
  //
  // To bound using AND, we need to ensure NUM_POSSIBLE_CPUS is rounded up to
  // next nearest power of 2.
  return round_up_to_next_power_of_two(num_possible_cpus) - 1;
}

} // namespace bpftrace::util
