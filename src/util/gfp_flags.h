#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace bpftrace {
namespace util {

// GFP flag definitions based on linux/gfp_types.h
// These are the most common GFP flags used in the kernel
class GFPFlags {
public:
  // Format a GFP flag value to human readable string
  static std::string format(uint64_t gfp_flags);

private:
  // Additional flags for completeness
  static constexpr uint64_t __GFP_NOWARN = 0x800000;

  // GFP flag bit definitions (from linux/gfp_types.h)
  static constexpr uint64_t __GFP_DMA = 0x01;
  static constexpr uint64_t __GFP_HIGHMEM = 0x02;
  static constexpr uint64_t __GFP_DMA32 = 0x04;
  static constexpr uint64_t __GFP_MOVABLE = 0x08;
  static constexpr uint64_t __GFP_RECLAIMABLE = 0x10;
  static constexpr uint64_t __GFP_HIGH = 0x20;
  static constexpr uint64_t __GFP_IO = 0x40;
  static constexpr uint64_t __GFP_FS = 0x80;
  static constexpr uint64_t __GFP_ZERO = 0x100;
  static constexpr uint64_t __GFP_NOFAIL = 0x200;
  static constexpr uint64_t __GFP_NORETRY = 0x400;
  static constexpr uint64_t __GFP_MEMALLOC = 0x800;
  static constexpr uint64_t __GFP_COMP = 0x1000;
  static constexpr uint64_t __GFP_NOMEMALLOC = 0x2000;
  static constexpr uint64_t __GFP_HARDWALL = 0x4000;
  static constexpr uint64_t __GFP_THISNODE = 0x8000;
  static constexpr uint64_t __GFP_ATOMIC = 0x10000;
  static constexpr uint64_t __GFP_ACCOUNT = 0x20000;
  static constexpr uint64_t __GFP_DIRECT_RECLAIM = 0x40000;
  static constexpr uint64_t __GFP_WRITE = 0x80000;
  static constexpr uint64_t __GFP_KSWAPD_RECLAIM = 0x100000;
  static constexpr uint64_t __GFP_ZEROTAGS = 0x200000;
  static constexpr uint64_t __GFP_SKIP_KASAN = 0x400000;

  // Compound GFP flags (common combinations) - calculated at compile time
  static constexpr uint64_t GFP_ATOMIC = (__GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM);
  static constexpr uint64_t GFP_KERNEL = (__GFP_DIRECT_RECLAIM | __GFP_IO | __GFP_FS | __GFP_KSWAPD_RECLAIM);
  static constexpr uint64_t GFP_KERNEL_ACCOUNT = (GFP_KERNEL | __GFP_ACCOUNT);
  static constexpr uint64_t GFP_NOWAIT = (__GFP_KSWAPD_RECLAIM);
  static constexpr uint64_t GFP_NOIO = (__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM);
  static constexpr uint64_t GFP_NOFS = (__GFP_DIRECT_RECLAIM | __GFP_IO | __GFP_KSWAPD_RECLAIM);
  static constexpr uint64_t GFP_USER = (__GFP_DIRECT_RECLAIM | __GFP_IO | __GFP_FS | __GFP_KSWAPD_RECLAIM | __GFP_HARDWALL);
  static constexpr uint64_t GFP_DMA = (__GFP_DMA);
  static constexpr uint64_t GFP_DMA32 = (__GFP_DMA32);
  static constexpr uint64_t GFP_HIGHUSER = (GFP_USER | __GFP_HIGHMEM);
  static constexpr uint64_t GFP_HIGHUSER_MOVABLE = (GFP_HIGHUSER | __GFP_MOVABLE);
  static constexpr uint64_t GFP_TRANSHUGE_LIGHT = (GFP_HIGHUSER_MOVABLE | __GFP_COMP | __GFP_NOMEMALLOC | __GFP_NOWARN);
  static constexpr uint64_t GFP_TRANSHUGE = (GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM);

  // Map of flag values to names for individual flags
  static const std::unordered_map<uint64_t, std::string> flag_names;
  
  // Map of compound flag values to names (order matters - check most specific first)
  static const std::vector<std::pair<uint64_t, std::string>> compound_flags;
};

} // namespace util
} // namespace bpftrace