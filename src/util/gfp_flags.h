#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

#define BIT(nr) (1UL << (nr))

// GFP flag bit definitions (from linux/gfp_types.h)
enum {
	___GFP_DMA_BIT,
	___GFP_HIGHMEM_BIT,
	___GFP_DMA32_BIT,
	___GFP_MOVABLE_BIT,
	___GFP_RECLAIMABLE_BIT,
	___GFP_HIGH_BIT,
	___GFP_IO_BIT,
	___GFP_FS_BIT,
	___GFP_ZERO_BIT,
	___GFP_UNUSED_BIT,	/* 0x200u unused */
	___GFP_DIRECT_RECLAIM_BIT,
	___GFP_KSWAPD_RECLAIM_BIT,
	___GFP_WRITE_BIT,
	___GFP_NOWARN_BIT,
	___GFP_RETRY_MAYFAIL_BIT,
	___GFP_NOFAIL_BIT,
	___GFP_NORETRY_BIT,
	___GFP_MEMALLOC_BIT,
	___GFP_COMP_BIT,
	___GFP_NOMEMALLOC_BIT,
	___GFP_HARDWALL_BIT,
	___GFP_THISNODE_BIT,
	___GFP_ACCOUNT_BIT,
	___GFP_ZEROTAGS_BIT,
	___GFP_SKIP_ZERO_BIT,
	___GFP_SKIP_KASAN_BIT,
	___GFP_NO_OBJ_EXT_BIT,
	___GFP_LAST_BIT
};

namespace bpftrace {
namespace util {

// GFP flag definitions based on linux/gfp_types.h
// These are the most common GFP flags used in the kernel
class GFPFlags {
public:
  // Format a GFP flag value to human readable string
  static std::string format(uint64_t gfp_flags);

private:
  static constexpr uint64_t __GFP_DMA = BIT(___GFP_DMA_BIT);
  static constexpr uint64_t __GFP_HIGHMEM = BIT(___GFP_HIGHMEM_BIT);
  static constexpr uint64_t __GFP_DMA32 = BIT(___GFP_DMA32_BIT);
  static constexpr uint64_t __GFP_MOVABLE = BIT(___GFP_MOVABLE_BIT);
  static constexpr uint64_t __GFP_RECLAIMABLE = BIT(___GFP_RECLAIMABLE_BIT);
  static constexpr uint64_t __GFP_HIGH = BIT(___GFP_HIGH_BIT);
  static constexpr uint64_t __GFP_IO = BIT(___GFP_IO_BIT);
  static constexpr uint64_t __GFP_FS = BIT(___GFP_FS_BIT);
  static constexpr uint64_t __GFP_ZERO = BIT(___GFP_ZERO_BIT);
  static constexpr uint64_t __GFP_DIRECT_RECLAIM = BIT(___GFP_DIRECT_RECLAIM_BIT);
  static constexpr uint64_t __GFP_KSWAPD_RECLAIM = BIT(___GFP_KSWAPD_RECLAIM_BIT);
  static constexpr uint64_t __GFP_WRITE = BIT(___GFP_WRITE_BIT);
  static constexpr uint64_t __GFP_NOWARN = BIT(___GFP_NOWARN_BIT);
  static constexpr uint64_t __GFP_RETRY_MAYFAIL = BIT(___GFP_RETRY_MAYFAIL_BIT);
  static constexpr uint64_t __GFP_NOFAIL = BIT(___GFP_NOFAIL_BIT);
  static constexpr uint64_t __GFP_NORETRY = BIT(___GFP_NORETRY_BIT);
  static constexpr uint64_t __GFP_MEMALLOC = BIT(___GFP_MEMALLOC_BIT);
  static constexpr uint64_t __GFP_COMP = BIT(___GFP_COMP_BIT);
  static constexpr uint64_t __GFP_NOMEMALLOC = BIT(___GFP_NOMEMALLOC_BIT);
  static constexpr uint64_t __GFP_HARDWALL = BIT(___GFP_HARDWALL_BIT);
  static constexpr uint64_t __GFP_THISNODE = BIT(___GFP_THISNODE_BIT);
  static constexpr uint64_t __GFP_ACCOUNT = BIT(___GFP_ACCOUNT_BIT);
  static constexpr uint64_t __GFP_ZEROTAGS = BIT(___GFP_ZEROTAGS_BIT);
  static constexpr uint64_t __GFP_SKIP_ZERO = BIT(___GFP_SKIP_ZERO_BIT);
  static constexpr uint64_t __GFP_SKIP_KASAN = BIT(___GFP_SKIP_KASAN_BIT);
  static constexpr uint64_t __GFP_NO_OBJ_EXT = BIT(___GFP_NO_OBJ_EXT_BIT);

  static constexpr uint64_t __GFP_RECLAIM = (__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM);

  // Compound GFP flags (common combinations) - calculated at compile time
  static constexpr uint64_t GFP_ATOMIC = (__GFP_HIGH | __GFP_KSWAPD_RECLAIM);
  static constexpr uint64_t GFP_KERNEL = (__GFP_RECLAIM | __GFP_IO | __GFP_FS);
  static constexpr uint64_t GFP_KERNEL_ACCOUNT = (GFP_KERNEL | __GFP_ACCOUNT);
  static constexpr uint64_t GFP_NOWAIT = (__GFP_KSWAPD_RECLAIM | __GFP_NOWARN);
  static constexpr uint64_t GFP_NOIO = (__GFP_RECLAIM);
  static constexpr uint64_t GFP_NOFS = (__GFP_RECLAIM | __GFP_IO);
  static constexpr uint64_t GFP_USER = (__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL);
  static constexpr uint64_t GFP_DMA = (__GFP_DMA);
  static constexpr uint64_t GFP_DMA32 = (__GFP_DMA32);
  static constexpr uint64_t GFP_HIGHUSER = (GFP_USER | __GFP_HIGHMEM);
  static constexpr uint64_t GFP_HIGHUSER_MOVABLE = (GFP_HIGHUSER | __GFP_MOVABLE | __GFP_SKIP_KASAN);
  static constexpr uint64_t GFP_TRANSHUGE_LIGHT = (GFP_HIGHUSER_MOVABLE | __GFP_COMP | __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM;
  static constexpr uint64_t GFP_TRANSHUGE = (GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM);

  // Map of flag values to names for individual flags
  static const std::unordered_map<uint64_t, std::string> flag_names;
  
  // Map of compound flag values to names (order matters - check most specific first)
  static const std::vector<std::pair<uint64_t, std::string>> compound_flags;
};

} // namespace util
} // namespace bpftrace