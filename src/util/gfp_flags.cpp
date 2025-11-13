#include "gfp_flags.h"

#include <sstream>

namespace bpftrace {
namespace util {

// Individual flag names mapping
const std::unordered_map<uint64_t, std::string> GFPFlags::flag_names = {
  { __GFP_DMA, "__GFP_DMA" },
  { __GFP_HIGHMEM, "__GFP_HIGHMEM" },
  { __GFP_DMA32, "__GFP_DMA32" },
  { __GFP_MOVABLE, "__GFP_MOVABLE" },
  { __GFP_RECLAIMABLE, "__GFP_RECLAIMABLE" },
  { __GFP_HIGH, "__GFP_HIGH" },
  { __GFP_IO, "__GFP_IO" },
  { __GFP_FS, "__GFP_FS" },
  { __GFP_ZERO, "__GFP_ZERO" },
  { __GFP_NOFAIL, "__GFP_NOFAIL" },
  { __GFP_NORETRY, "__GFP_NORETRY" },
  { __GFP_MEMALLOC, "__GFP_MEMALLOC" },
  { __GFP_COMP, "__GFP_COMP" },
  { __GFP_NOMEMALLOC, "__GFP_NOMEMALLOC" },
  { __GFP_HARDWALL, "__GFP_HARDWALL" },
  { __GFP_THISNODE, "__GFP_THISNODE" },
  { __GFP_ATOMIC, "__GFP_ATOMIC" },
  { __GFP_ACCOUNT, "__GFP_ACCOUNT" },
  { __GFP_DIRECT_RECLAIM, "__GFP_DIRECT_RECLAIM" },
  { __GFP_WRITE, "__GFP_WRITE" },
  { __GFP_KSWAPD_RECLAIM, "__GFP_KSWAPD_RECLAIM" },
  { __GFP_ZEROTAGS, "__GFP_ZEROTAGS" },
  { __GFP_SKIP_KASAN, "__GFP_SKIP_KASAN" },
  { __GFP_NOWARN, "__GFP_NOWARN" }
};

// Compound flag names mapping (ordered from most specific to least specific)
const std::vector<std::pair<uint64_t, std::string>> GFPFlags::compound_flags = {
  { GFP_TRANSHUGE, "GFP_TRANSHUGE" },
  { GFP_TRANSHUGE_LIGHT, "GFP_TRANSHUGE_LIGHT" },
  { GFP_HIGHUSER_MOVABLE, "GFP_HIGHUSER_MOVABLE" },
  { GFP_HIGHUSER, "GFP_HIGHUSER" },
  { GFP_KERNEL_ACCOUNT, "GFP_KERNEL_ACCOUNT" },
  { GFP_KERNEL, "GFP_KERNEL" },
  { GFP_USER, "GFP_USER" },
  { GFP_ATOMIC, "GFP_ATOMIC" },
  { GFP_NOWAIT, "GFP_NOWAIT" },
  { GFP_NOIO, "GFP_NOIO" },
  { GFP_NOFS, "GFP_NOFS" },
  { GFP_DMA32, "GFP_DMA32" },
  { GFP_DMA, "GFP_DMA" }
};

std::string GFPFlags::format(uint64_t gfp_flags)
{
  if (gfp_flags == 0) {
    return "0";
  }

  std::stringstream result;
  uint64_t remaining = gfp_flags;
  bool first = true;

  // First check for compound flags (exact matches)
  for (const auto& pair : compound_flags) {
    if ((remaining & pair.first) == pair.first) {
      if (!first) {
        result << "|";
      }
      result << pair.second;
      remaining &= ~pair.first;
      first = false;
    }
  }

  // Then check remaining individual flags
  for (const auto& pair : flag_names) {
    if (remaining & pair.first) {
      if (!first) {
        result << "|";
      }
      result << pair.second;
      remaining &= ~pair.first;
      first = false;
    }
  }

  // If there are unrecognized bits, add them as hex
  if (remaining != 0) {
    if (!first) {
      result << "|";
    }
    result << "0x" << std::hex << remaining;
  }

  return result.str();
}

} // namespace util
} // namespace bpftrace
